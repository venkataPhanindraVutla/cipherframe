package db

import (
	"context"
	"encoding/base64"
	"errors"
	"math"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/venkataPhanindraVutla/cipherframe/internal/db/dbgen"
	"github.com/venkataPhanindraVutla/cipherframe/internal/errs"
	"github.com/venkataPhanindraVutla/cipherframe/internal/id"
)

// The events of the access trail (the playback_access_log.event column). Segment requests are never
// logged one by one: AccessSegments rows carry how many a session fetched in a flush interval.
const (
	AccessSessionCreated = "session_created"
	AccessSessionDenied  = "session_denied"
	AccessPlaylist       = "playlist"
	AccessKey            = "key"
	AccessKeyDenied      = "key_denied"
	AccessHeartbeat      = "heartbeat"
	AccessEnd            = "end"
	AccessRevoked        = "revoked"
	AccessExpired        = "expired"
	AccessSegments       = "segments"
)

// AccessEvents lists every event, in the order the documentation uses.
var AccessEvents = []string{
	AccessSessionCreated, AccessSessionDenied, AccessPlaylist, AccessKey, AccessKeyDenied,
	AccessHeartbeat, AccessEnd, AccessRevoked, AccessExpired, AccessSegments,
}

// ValidAccessEvent reports whether e is an event of the access trail.
func ValidAccessEvent(e string) bool {
	for _, v := range AccessEvents {
		if v == e {
			return true
		}
	}
	return false
}

// Limits of the stored text columns (the table's CHECK constraints).
const (
	MaxAccessUserAgentChars = 256
	MaxAccessRequestIDChars = 64
)

// MaxAccessLogPage is the largest page of the access-log read API.
const MaxAccessLogPage = 500

// AccessLogRow is one row to append. Zero values mean NULL: an empty ViewerID, AuthMethod, IP,
// UserAgent or RequestID, a nil SessionHash, a zero AssetID and zero SegmentsServed.
type AccessLogRow struct {
	TenantID       id.TenantID
	AssetID        id.AssetID
	SessionHash    []byte
	ViewerID       string
	AuthMethod     string
	Event          string
	At             time.Time
	SegmentsServed int
	IP             string
	UserAgent      string
	RequestID      string
}

// InsertAccessLog appends rows in one statement. Rows of a tenant that does not exist are silently
// left out: the table has no foreign key, and the browser-session route lets anyone name any tenant
// in a refused request. Every row's time must fall in an existing
// partition (see EnsureAccessLogPartitions); otherwise the whole statement fails and nothing is
// written.
func (r *Repos) InsertAccessLog(ctx context.Context, rows []AccessLogRow) error {
	if len(rows) == 0 {
		return nil
	}
	n := len(rows)
	var (
		tenants  = make([]pgtype.UUID, n)
		assets   = make([]pgtype.UUID, n)
		hashes   = make([][]byte, n)
		viewers  = make([]*string, n)
		methods  = make([]*string, n)
		events   = make([]string, n)
		ats      = make([]time.Time, n)
		segments = make([]*int32, n)
		ips      = make([]*string, n)
		agents   = make([]*string, n)
		rids     = make([]*string, n)
	)
	for i, row := range rows {
		tid, err := requirePG(row.TenantID)
		if err != nil {
			return err
		}
		if !ValidAccessEvent(row.Event) {
			return errs.New(errs.InvalidRequest, "invalid access event")
		}
		tenants[i], assets[i] = tid, toPG(row.AssetID)
		if len(row.SessionHash) > 0 {
			hashes[i] = row.SessionHash
		}
		viewers[i], methods[i] = strPtr(row.ViewerID), strPtr(row.AuthMethod)
		events[i], ats[i] = row.Event, row.At
		if row.SegmentsServed > 0 {
			s := int32(min(row.SegmentsServed, math.MaxInt32)) //nolint:gosec // clamped
			segments[i] = &s
		}
		ips[i], agents[i], rids[i] = strPtr(row.IP), strPtr(row.UserAgent), strPtr(row.RequestID)
	}
	_, err := r.conn.Exec(ctx, `
INSERT INTO playback_access_log (
    tenant_id, asset_id, session_hash, viewer_id, auth_method, event, at, segments_served, ip, user_agent, request_id)
SELECT t.tenant_id, t.asset_id, t.session_hash, t.viewer_id, t.auth_method, t.event, t.at, t.segments_served,
       t.ip::inet, t.user_agent, t.request_id
FROM unnest($1::uuid[], $2::uuid[], $3::bytea[], $4::text[], $5::text[], $6::text[], $7::timestamptz[],
            $8::integer[], $9::text[], $10::text[], $11::text[])
     AS t(tenant_id, asset_id, session_hash, viewer_id, auth_method, event, at, segments_served, ip, user_agent, request_id)
JOIN tenants ON tenants.id = t.tenant_id`,
		tenants, assets, hashes, viewers, methods, events, ats, segments, ips, agents, rids)
	return mapError(err)
}

// AccessLogEntry is one row of the access trail as the read API reports it. It never holds the
// session ID or its hash: SessionFingerprint (8 hex characters, derived from both the hash and the
// tenant) only lets a reader group the rows of one session. It is empty when the row has no
// session (a refused creation).
type AccessLogEntry struct {
	ID                 int64
	AssetID            id.AssetID
	SessionFingerprint string
	ViewerID           string
	AuthMethod         string
	Event              string
	At                 time.Time
	SegmentsServed     int
	IP                 string
	UserAgent          string
	RequestID          string
}

// AccessLogCursor is the position after which the next page starts.
type AccessLogCursor struct {
	At time.Time
	ID int64
}

// Encode returns the opaque text form of the cursor.
func (c AccessLogCursor) Encode() string {
	raw := "1." + strconv.FormatInt(c.At.UnixMicro(), 10) + "." + strconv.FormatInt(c.ID, 10)
	return base64.RawURLEncoding.EncodeToString([]byte(raw))
}

// ParseAccessLogCursor decodes a cursor made by Encode. Any malformed text is an
// invalid_request error.
func ParseAccessLogCursor(s string) (AccessLogCursor, error) {
	bad := errs.New(errs.InvalidRequest, "The cursor is invalid.")
	raw, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return AccessLogCursor{}, bad
	}
	parts := strings.Split(string(raw), ".")
	if len(parts) != 3 || parts[0] != "1" {
		return AccessLogCursor{}, bad
	}
	micros, err1 := strconv.ParseInt(parts[1], 10, 64)
	rid, err2 := strconv.ParseInt(parts[2], 10, 64)
	if err1 != nil || err2 != nil || rid < 0 {
		return AccessLogCursor{}, bad
	}
	return AccessLogCursor{At: time.UnixMicro(micros).UTC(), ID: rid}, nil
}

// AccessLogQuery filters and pages a read. Zero From and To mean unbounded; From is inclusive and
// To exclusive. Cursor is nil for the first page. Limit is 1 to MaxAccessLogPage.
type AccessLogQuery struct {
	From, To time.Time
	Event    string
	Cursor   *AccessLogCursor
	Limit    int
}

// bounds turns the optional range into concrete timestamps, and the cursor into the row-comparison
// bound of the keyset query.
func (q AccessLogQuery) bounds() (from, to, cursorAt time.Time, cursorID int64, err error) {
	if q.Limit < 1 || q.Limit > MaxAccessLogPage {
		return from, to, cursorAt, 0, errs.New(errs.InvalidRequest, "invalid page size")
	}
	if q.Event != "" && !ValidAccessEvent(q.Event) {
		return from, to, cursorAt, 0, errs.New(errs.InvalidRequest, "invalid event")
	}
	// Year 1 and year 9000 are inside Postgres's timestamptz range and outside any real row.
	from, to = time.Date(1, 1, 1, 0, 0, 0, 0, time.UTC), time.Date(9000, 1, 1, 0, 0, 0, 0, time.UTC)
	if !q.From.IsZero() {
		from = q.From
	}
	if !q.To.IsZero() {
		to = q.To
	}
	cursorAt, cursorID = to, math.MaxInt64
	if q.Cursor != nil {
		cursorAt, cursorID = q.Cursor.At, q.Cursor.ID
	}
	return from, to, cursorAt, cursorID, nil
}

// page trims the extra row fetched to learn whether another page exists.
func accessPage(entries []AccessLogEntry, limit int) ([]AccessLogEntry, *AccessLogCursor) {
	if len(entries) <= limit {
		return entries, nil
	}
	entries = entries[:limit]
	last := entries[len(entries)-1]
	return entries, &AccessLogCursor{At: last.At, ID: last.ID}
}

// ListAssetAccessLog returns the tenant's access-trail rows of one asset, newest first, and the
// cursor of the next page (nil on the last page). It does not check that the asset exists.
func (r *Repos) ListAssetAccessLog(ctx context.Context, tenantID id.TenantID, assetID id.AssetID, q AccessLogQuery) ([]AccessLogEntry, *AccessLogCursor, error) {
	tid, err := requirePG(tenantID)
	if err != nil {
		return nil, nil, err
	}
	aid, err := requirePG(assetID)
	if err != nil {
		return nil, nil, err
	}
	from, to, cat, cid, err := q.bounds()
	if err != nil {
		return nil, nil, err
	}
	rows, err := r.q.ListAssetAccessLog(ctx, dbgen.ListAssetAccessLogParams{
		TenantID: tid, AssetID: aid, FromAt: from, ToAt: to, Event: strPtr(q.Event),
		CursorAt: cat, CursorID: cid, MaxRows: int32(q.Limit + 1), //nolint:gosec // bounded by MaxAccessLogPage
	})
	if err != nil {
		return nil, nil, mapError(err)
	}
	out := make([]AccessLogEntry, len(rows))
	for i, row := range rows {
		out[i] = accessEntry(row.ID, row.AssetID, row.SessionFingerprint, row.ViewerID, row.AuthMethod, row.Event,
			row.At, row.SegmentsServed, row.Ip, row.UserAgent, row.RequestID)
	}
	entries, next := accessPage(out, q.Limit)
	return entries, next, nil
}

// ListSessionAccessLog is ListAssetAccessLog for one session, found by the hash of its ID.
func (r *Repos) ListSessionAccessLog(ctx context.Context, tenantID id.TenantID, hash []byte, q AccessLogQuery) ([]AccessLogEntry, *AccessLogCursor, error) {
	tid, err := requirePG(tenantID)
	if err != nil {
		return nil, nil, err
	}
	from, to, cat, cid, err := q.bounds()
	if err != nil {
		return nil, nil, err
	}
	rows, err := r.q.ListSessionAccessLog(ctx, dbgen.ListSessionAccessLogParams{
		TenantID: tid, SessionHash: hash, FromAt: from, ToAt: to, Event: strPtr(q.Event),
		CursorAt: cat, CursorID: cid, MaxRows: int32(q.Limit + 1), //nolint:gosec // bounded by MaxAccessLogPage
	})
	if err != nil {
		return nil, nil, mapError(err)
	}
	out := make([]AccessLogEntry, len(rows))
	for i, row := range rows {
		out[i] = accessEntry(row.ID, row.AssetID, row.SessionFingerprint, row.ViewerID, row.AuthMethod, row.Event,
			row.At, row.SegmentsServed, row.Ip, row.UserAgent, row.RequestID)
	}
	entries, next := accessPage(out, q.Limit)
	return entries, next, nil
}

func accessEntry(rowID int64, asset pgtype.UUID, fingerprint string, viewer, method *string, event string,
	at time.Time, segments *int32, ip string, agent, rid *string,
) AccessLogEntry {
	e := AccessLogEntry{
		ID: rowID, AssetID: fromPG[id.AssetKind](asset), SessionFingerprint: fingerprint,
		ViewerID: strVal(viewer), AuthMethod: strVal(method), Event: event, At: at.UTC(),
		IP: ip, UserAgent: strVal(agent), RequestID: strVal(rid),
	}
	if segments != nil {
		e.SegmentsServed = int(*segments)
	}
	return e
}

// SessionViewer is what the access-log writer needs to know about a session.
type SessionViewer struct {
	ViewerID   string
	AuthMethod string
}

// SessionViewers returns the viewer and authorization method of the sessions with the given hashes,
// keyed by string(hash). Unknown hashes are absent.
func (r *Repos) SessionViewers(ctx context.Context, hashes [][]byte) (map[string]SessionViewer, error) {
	if len(hashes) == 0 {
		return map[string]SessionViewer{}, nil
	}
	rows, err := r.q.SessionViewers(ctx, hashes)
	if err != nil {
		return nil, mapError(err)
	}
	out := make(map[string]SessionViewer, len(rows))
	for _, row := range rows {
		out[string(row.IDHash)] = SessionViewer{ViewerID: row.ViewerID, AuthMethod: row.AuthMethod}
	}
	return out, nil
}

// EnsureAccessLogPartitions creates the monthly partitions of playback_access_log for the UTC month
// of now and the next ahead months, when missing, and returns how many it created. Idempotent and
// safe from any number of replicas at once.
func (r *Repos) EnsureAccessLogPartitions(ctx context.Context, now time.Time, ahead int) (int, error) {
	if ahead < 0 || ahead > 24 {
		return 0, errs.New(errs.InvalidRequest, "invalid number of months")
	}
	first := firstOfMonth(now)
	created := 0
	for i := 0; i <= ahead; i++ {
		month := first.AddDate(0, i, 0)
		ok, err := r.q.EnsureAccessLogPartition(ctx, pgtype.Date{Time: month, Valid: true})
		if err != nil {
			return created, mapError(err)
		}
		if ok {
			created++
		}
	}
	return created, nil
}

// DropAccessLogPartitionsBefore drops every monthly partition whose whole range ends at or before
// the UTC date of before, and returns the names it dropped. It refuses a date in the future.
//
// The retention job (package retention) calls it with the retention cutoff. The SQL function is
// SECURITY DEFINER, so it works from any role the service connects as.
func (r *Repos) DropAccessLogPartitionsBefore(ctx context.Context, before time.Time) ([]string, error) {
	names, err := r.q.DropAccessLogPartitionsBefore(ctx, pgtype.Date{Time: firstOfDay(before), Valid: true})
	if err != nil {
		return nil, mapError(err)
	}
	return names, nil
}

func firstOfMonth(t time.Time) time.Time {
	t = t.UTC()
	return time.Date(t.Year(), t.Month(), 1, 0, 0, 0, 0, time.UTC)
}

func firstOfDay(t time.Time) time.Time {
	t = t.UTC()
	return time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, time.UTC)
}

// PrivacySettings are a tenant's privacy choices (ADR 0040). A tenant without a stored row uses
// DefaultPrivacySettings: everything off and no default time-to-live. UpdatedAt is the zero time
// for the defaults.
type PrivacySettings struct {
	// StoreIP keeps the viewer's IP address (the connecting peer address) in the access trail.
	StoreIP bool
	// StoreUserAgent keeps the viewer's User-Agent header, cut to 256 characters.
	StoreUserAgent bool
	// AssetTTLSeconds is the tenant's default time-to-live for assets created from now on
	// (M6-4); nil means assets are kept until deleted.
	AssetTTLSeconds *int
	UpdatedAt       time.Time
}

// DefaultPrivacySettings returns the most private choices.
func DefaultPrivacySettings() PrivacySettings { return PrivacySettings{} }

// GetPrivacySettings returns the tenant's privacy settings, or the defaults when none are stored.
func (r *Repos) GetPrivacySettings(ctx context.Context, tenantID id.TenantID) (PrivacySettings, error) {
	tid, err := requirePG(tenantID)
	if err != nil {
		return PrivacySettings{}, err
	}
	row, err := r.q.GetPrivacySettings(ctx, tid)
	if errors.Is(err, pgx.ErrNoRows) {
		return DefaultPrivacySettings(), nil
	}
	if err != nil {
		return PrivacySettings{}, mapError(err)
	}
	return privacyFromRow(row), nil
}

func privacyFromRow(row dbgen.PrivacySetting) PrivacySettings {
	out := PrivacySettings{StoreIP: row.StoreIp, StoreUserAgent: row.StoreUserAgent, UpdatedAt: row.UpdatedAt.UTC()}
	if row.AssetTtlSeconds != nil {
		n := int(*row.AssetTtlSeconds)
		out.AssetTTLSeconds = &n
	}
	return out
}

// PutPrivacySettings replaces the tenant's privacy settings.
func (r *Repos) PutPrivacySettings(ctx context.Context, tenantID id.TenantID, s PrivacySettings, at time.Time) (PrivacySettings, error) {
	tid, err := requirePG(tenantID)
	if err != nil {
		return PrivacySettings{}, err
	}
	var ttl *int32
	if s.AssetTTLSeconds != nil {
		if *s.AssetTTLSeconds < MinAssetTTLSeconds || *s.AssetTTLSeconds > MaxAssetTTLSeconds {
			return PrivacySettings{}, errs.New(errs.InvalidRequest, "invalid asset time-to-live")
		}
		n := int32(*s.AssetTTLSeconds) //nolint:gosec // range checked above
		ttl = &n
	}
	row, err := r.q.UpsertPrivacySettings(ctx, dbgen.UpsertPrivacySettingsParams{
		TenantID: tid, StoreIp: s.StoreIP, StoreUserAgent: s.StoreUserAgent, AssetTtlSeconds: ttl, At: at,
	})
	if err != nil {
		return PrivacySettings{}, mapError(err)
	}
	return privacyFromRow(row), nil
}

// DeleteAccessLogBefore deletes up to batch rows of the access trail older than cutoff and returns
// how many it deleted. Call it until it returns less than batch.
func (r *Repos) DeleteAccessLogBefore(ctx context.Context, cutoff time.Time, batch int) (int64, error) {
	if batch < 1 {
		return 0, errs.New(errs.InvalidRequest, "invalid batch size")
	}
	n, err := r.q.DeleteAccessLogBefore(ctx, dbgen.DeleteAccessLogBeforeParams{Cutoff: cutoff.UTC(), Batch: int32(batch)}) //nolint:gosec // bounded by the caller
	return n, mapError(err)
}
