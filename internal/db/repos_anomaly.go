package db

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"slices"
	"strconv"
	"strings"
	"time"
	"uuid"

	"github.com/jackc/pgx/v5/pgtype"

	"github.com/venkataPhanindraVutla/cipherframe/internal/db/dbgen"
	"github.com/venkataPhanindraVutla/cipherframe/internal/errs"
	"github.com/venkataPhanindraVutla/cipherframe/internal/id"
)

// The kinds of anomaly events (the playback_events CHECK constraint lists the same).
const (
	EventKeyReplay            = "key_replay"
	EventKeyRate              = "key_rate"
	EventSessionLimit         = "session_limit"
	EventRapidSessionCreation = "rapid_session_creation"
	EventSegmentsWithoutKey   = "segments_without_key"
)

// EventKinds lists every kind, in the order the documentation uses.
var EventKinds = []string{
	EventKeyReplay, EventKeyRate, EventSessionLimit, EventRapidSessionCreation, EventSegmentsWithoutKey,
}

// AutoRevokeKinds are the kinds a tenant may list in its auto_revoke setting. session_limit is not
// one: a refused creation has no session to revoke.
var AutoRevokeKinds = []string{EventKeyReplay, EventKeyRate, EventRapidSessionCreation, EventSegmentsWithoutKey}

// ValidEventKind reports whether k is an anomaly event kind.
func ValidEventKind(k string) bool { return slices.Contains(EventKinds, k) }

// ValidAutoRevokeKind reports whether k may be listed in a tenant's auto_revoke setting.
func ValidAutoRevokeKind(k string) bool { return slices.Contains(AutoRevokeKinds, k) }

// SessionFingerprint is the 8-hex-character label of a session that the access log, the events API
// and the logs show: the first 4 bytes of SHA-256(session hash || tenant ID bytes). It groups the
// rows of one session and cannot be turned into the session ID.
func SessionFingerprint(sessionHash []byte, tenantID id.TenantID) string {
	tb := toPG(tenantID).Bytes
	b := append(slices.Clone(sessionHash), tb[:]...)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:4])
}

// NewAnomalyEvent is the input of InsertAnomalyEvent. Detail holds small numbers only. A
// session-level event sets SessionHash (the viewer is copied from the session row); a viewer-level
// one leaves it nil and sets ViewerID. Since is the start of the duplicate-suppression window: an
// event of the same kind for the same subject at or after it suppresses this one.
type NewAnomalyEvent struct {
	TenantID    id.TenantID
	SessionHash []byte
	ViewerID    string
	AssetID     id.AssetID
	Kind        string
	At          time.Time
	Since       time.Time
	Detail      map[string]int64
}

// LockAnomalySubject takes a transaction-scoped advisory lock for raising one kind for one
// subject, so concurrent detections record one event. Use it inside Tx, before InsertAnomalyEvent.
func (r *Repos) LockAnomalySubject(ctx context.Context, tenantID id.TenantID, kind, subject string) error {
	if tenantID.IsZero() || subject == "" {
		return errs.New(errs.InvalidRequest, "a required identifier is missing")
	}
	return mapError(r.q.LockAnomalySubject(ctx, "cipherframe.anomaly:"+tenantID.String()+":"+kind+":"+subject))
}

// InsertAnomalyEvent stores an event unless the same kind was already raised for the same subject
// since in.Since, and reports whether it stored one.
func (r *Repos) InsertAnomalyEvent(ctx context.Context, in NewAnomalyEvent) (bool, error) {
	tid, err := requirePG(in.TenantID)
	if err != nil {
		return false, err
	}
	aid, err := requirePG(in.AssetID)
	if err != nil {
		return false, err
	}
	if !ValidEventKind(in.Kind) {
		return false, errs.New(errs.InvalidRequest, "invalid event kind")
	}
	detail, err := json.Marshal(in.Detail)
	if err != nil || in.Detail == nil {
		detail = []byte("{}")
	}
	at := in.At.UTC().Truncate(time.Microsecond)
	since := in.Since.UTC().Truncate(time.Microsecond)
	var n int64
	switch {
	case len(in.SessionHash) > 0:
		n, err = r.q.InsertSessionAnomaly(ctx, dbgen.InsertSessionAnomalyParams{
			TenantID: tid, SessionHash: in.SessionHash, AssetID: aid, Kind: in.Kind, At: at, Detail: detail, Since: since,
		})
	case in.ViewerID != "":
		n, err = r.q.InsertViewerAnomaly(ctx, dbgen.InsertViewerAnomalyParams{
			TenantID: tid, ViewerID: in.ViewerID, AssetID: aid, Kind: in.Kind, At: at, Detail: detail, Since: since,
		})
	default:
		return false, errs.New(errs.InvalidRequest, "an event needs a session or a viewer")
	}
	if err != nil {
		return false, mapError(err)
	}
	return n > 0, nil
}

// CountViewerSessionsCreatedSince counts the sessions created for the viewer after since.
func (r *Repos) CountViewerSessionsCreatedSince(ctx context.Context, tenantID id.TenantID, viewerID string, since time.Time) (int, error) {
	tid, err := requirePG(tenantID)
	if err != nil {
		return 0, err
	}
	n, err := r.q.CountViewerSessionsCreatedSince(ctx, dbgen.CountViewerSessionsCreatedSinceParams{
		TenantID: tid, ViewerID: viewerID, Since: since.UTC(),
	})
	if err != nil {
		return 0, mapError(err)
	}
	return int(n), nil
}

// SegmentDelta is how many segments a session was served since the last flush.
type SegmentDelta struct {
	SessionHash []byte
	Count       int
}

// SegmentsWithoutKey is a session that is over its tenant's segments_without_key threshold and has
// never been served the key, and that has no event of that kind yet.
type SegmentsWithoutKey struct {
	SessionHash []byte
	TenantID    id.TenantID
	AssetID     id.AssetID
	Served      int64
	Threshold   int
}

// AddPlaybackSegments adds the deltas to the sessions' served-segment counters in one statement
// and returns the sessions that are now over their tenant's threshold without ever having been
// served the key (and have no segments_without_key event yet). A threshold of 0 disables the
// signal for the tenant. Unknown sessions are ignored.
func (r *Repos) AddPlaybackSegments(ctx context.Context, deltas []SegmentDelta) ([]SegmentsWithoutKey, error) {
	if len(deltas) == 0 {
		return nil, nil
	}
	hashes := make([][]byte, len(deltas))
	counts := make([]int64, len(deltas))
	for i, d := range deltas {
		hashes[i], counts[i] = d.SessionHash, int64(d.Count)
	}
	rows, err := r.conn.Query(ctx, `
WITH d AS (
    SELECT h, n FROM unnest($1::bytea[], $2::bigint[]) AS t(h, n)
), upd AS (
    UPDATE playback_sessions s SET segments_served = LEAST(s.segments_served + d.n, 9000000000000000000)
    FROM d WHERE s.id_hash = d.h
    RETURNING s.id_hash, s.tenant_id, s.asset_id, s.segments_served, s.key_served_at
)
SELECT upd.id_hash, upd.tenant_id, upd.asset_id, upd.segments_served,
       COALESCE(ps.anomaly_segments_without_key, 30)::integer AS threshold
FROM upd
LEFT JOIN playback_settings ps ON ps.tenant_id = upd.tenant_id
WHERE upd.key_served_at IS NULL
  AND COALESCE(ps.anomaly_segments_without_key, 30) > 0
  AND upd.segments_served > COALESCE(ps.anomaly_segments_without_key, 30)
  AND NOT EXISTS (SELECT 1 FROM playback_events e WHERE e.session_hash = upd.id_hash AND e.kind = 'segments_without_key')`,
		hashes, counts)
	if err != nil {
		return nil, mapError(err)
	}
	defer rows.Close()
	var out []SegmentsWithoutKey
	for rows.Next() {
		var (
			hash          []byte
			tenant, asset pgtype.UUID
			served        int64
			threshold     int32
		)
		if err := rows.Scan(&hash, &tenant, &asset, &served, &threshold); err != nil {
			return nil, mapError(err)
		}
		out = append(out, SegmentsWithoutKey{
			SessionHash: hash, TenantID: fromPG[id.TenantKind](tenant), AssetID: fromPG[id.AssetKind](asset),
			Served: served, Threshold: int(threshold),
		})
	}
	return out, mapError(rows.Err())
}

// MaxEventPage is the largest page of the events read API.
const MaxEventPage = 500

// PlaybackEvent is one anomaly event as the read API reports it. It never holds the session ID or
// its hash: SessionFingerprint is the same 8 hex characters the access log uses, and is empty for a
// viewer-level event.
type PlaybackEvent struct {
	ID                 uuid.UUID
	Kind               string
	At                 time.Time
	AssetID            id.AssetID
	ViewerID           string
	SessionFingerprint string
	Detail             map[string]int64
}

// EventCursor is the position after which the next page of events starts.
type EventCursor struct {
	At time.Time
	ID uuid.UUID
}

// Encode returns the opaque text form of the cursor.
func (c EventCursor) Encode() string {
	raw := "1." + strconv.FormatInt(c.At.UnixMicro(), 10) + "." + c.ID.String()
	return base64.RawURLEncoding.EncodeToString([]byte(raw))
}

// ParseEventCursor decodes a cursor made by Encode. Malformed text is an invalid_request error.
func ParseEventCursor(s string) (EventCursor, error) {
	bad := errs.New(errs.InvalidRequest, "The cursor is invalid.")
	raw, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return EventCursor{}, bad
	}
	parts := strings.Split(string(raw), ".")
	if len(parts) != 3 || parts[0] != "1" {
		return EventCursor{}, bad
	}
	micros, err1 := strconv.ParseInt(parts[1], 10, 64)
	eid, err2 := uuid.Parse(parts[2])
	if err1 != nil || err2 != nil {
		return EventCursor{}, bad
	}
	return EventCursor{At: time.UnixMicro(micros).UTC(), ID: eid}, nil
}

// EventQuery filters and pages a read of events. Zero From and To mean unbounded (From inclusive,
// To exclusive); Kind, ViewerID and a zero AssetID mean no filter. Limit is 1 to MaxEventPage.
type EventQuery struct {
	Kind     string
	AssetID  id.AssetID
	ViewerID string
	From, To time.Time
	Cursor   *EventCursor
	Limit    int
}

// ListPlaybackEvents returns the tenant's events, newest first, and the cursor of the next page
// (nil on the last page).
func (r *Repos) ListPlaybackEvents(ctx context.Context, tenantID id.TenantID, q EventQuery) ([]PlaybackEvent, *EventCursor, error) {
	tid, err := requirePG(tenantID)
	if err != nil {
		return nil, nil, err
	}
	if q.Limit < 1 || q.Limit > MaxEventPage {
		return nil, nil, errs.New(errs.InvalidRequest, "invalid page size")
	}
	if q.Kind != "" && !ValidEventKind(q.Kind) {
		return nil, nil, errs.New(errs.InvalidRequest, "invalid event kind")
	}
	from, to := time.Date(1, 1, 1, 0, 0, 0, 0, time.UTC), time.Date(9000, 1, 1, 0, 0, 0, 0, time.UTC)
	if !q.From.IsZero() {
		from = q.From
	}
	if !q.To.IsZero() {
		to = q.To
	}
	cursorAt, cursorID := to, uuid.Max()
	if q.Cursor != nil {
		cursorAt, cursorID = q.Cursor.At, q.Cursor.ID
	}
	rows, err := r.q.ListPlaybackEvents(ctx, dbgen.ListPlaybackEventsParams{
		TenantID: tid, Kind: strPtr(q.Kind), AssetID: toPG(q.AssetID), ViewerID: strPtr(q.ViewerID),
		FromAt: from, ToAt: to, CursorAt: cursorAt, CursorID: rawToPG(cursorID),
		MaxRows: int32(q.Limit + 1), //nolint:gosec // bounded by MaxEventPage
	})
	if err != nil {
		return nil, nil, mapError(err)
	}
	out := make([]PlaybackEvent, len(rows))
	for i, row := range rows {
		detail := map[string]int64{}
		_ = json.Unmarshal(row.Detail, &detail) // numbers only by construction; a bad row reads as empty
		out[i] = PlaybackEvent{
			ID: uuid.UUID(row.ID.Bytes), Kind: row.Kind, At: row.At.UTC(), AssetID: fromPG[id.AssetKind](row.AssetID),
			ViewerID: strVal(row.ViewerID), SessionFingerprint: row.SessionFingerprint, Detail: detail,
		}
	}
	if len(out) <= q.Limit {
		return out, nil, nil
	}
	out = out[:q.Limit]
	last := out[len(out)-1]
	return out, &EventCursor{At: last.At, ID: last.ID}, nil
}

// DeletePlaybackEventsBefore deletes up to batch anomaly events older than cutoff and returns how
// many it deleted. Call it until it returns less than batch (retention, M6-4).
func (r *Repos) DeletePlaybackEventsBefore(ctx context.Context, cutoff time.Time, batch int) (int64, error) {
	if batch < 1 {
		return 0, errs.New(errs.InvalidRequest, "invalid batch size")
	}
	n, err := r.q.DeletePlaybackEventsBefore(ctx, dbgen.DeletePlaybackEventsBeforeParams{Cutoff: cutoff.UTC(), Batch: int32(batch)}) //nolint:gosec // bounded by the caller
	return n, mapError(err)
}
