// Package anomaly raises the playback anomaly signals (M4-9): key replay, key rate, a refused
// session creation (session limit), rapid session creation and segments served without a key.
//
// A signal becomes a row in playback_events (which is also the outbox the webhook system of M7
// delivers from) and, when the tenant's auto_revoke setting lists its kind, a revocation.
//
// What the signals use: counters and timestamps Cipherframe already keeps for enforcement and for
// the access trail (invariant I10). Nothing is learned about what a viewer watched or did inside
// the player; there is no behavioural profile, only per-session and per-viewer counts compared
// with the tenant's thresholds.
//
// Two rules hold everywhere:
//
//   - A database failure is not abuse (I11). When the event cannot be stored, or the tenant's
//     settings cannot be read, nothing is revoked. The event and the revocation share one
//     transaction, so there is no state in which a session was revoked without its event.
//   - Raising is idempotent and quiet: one event per (session or viewer, kind) per window, so a
//     scraper that keeps going does not flood the table.
package anomaly

import (
	"context"
	"encoding/hex"
	"errors"
	"log/slog"
	"slices"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/venkataPhanindraVutla/cipherframe/internal/accesslog"
	"github.com/venkataPhanindraVutla/cipherframe/internal/db"
	"github.com/venkataPhanindraVutla/cipherframe/internal/db/dbgen"
	"github.com/venkataPhanindraVutla/cipherframe/internal/errs"
	"github.com/venkataPhanindraVutla/cipherframe/internal/id"
	"github.com/venkataPhanindraVutla/cipherframe/internal/reqid"
)

// Window is the duplicate-suppression window, and the sliding window of rapid_session_creation.
// One event per subject and kind is recorded per window. segments_without_key is the exception:
// it is recorded once per session, because the condition never clears for a session that has not
// fetched the key, and repeating it every window would be noise.
const Window = 10 * time.Minute

// AutoRevokePrefix starts the revoke reason of every automatic revocation: "auto:<kind>".
const AutoRevokePrefix = "auto:"

// Audit actions written when a signal revokes sessions. The audit row has no client or API key:
// nobody asked for it.
const (
	AuditAutoRevoke     = "playback_session.auto_revoke"
	AuditAutoRevokeBulk = "playback_sessions.auto_revoke"
)

// Pool is the database handle of a Detector: *pgxpool.Pool implements it.
type Pool interface {
	dbgen.DBTX
	db.Beginner
}

// Deps are the collaborators of a Detector.
type Deps struct {
	Pool Pool
	// Access receives the access-trail rows of revocations. Nil records nothing.
	Access *accesslog.Recorder
	Log    *slog.Logger
	// Now defaults to time.Now.
	Now func() time.Time
}

// Detector raises signals. Safe for concurrent use. A nil *Detector does nothing.
type Detector struct {
	pool   Pool
	repos  *db.Repos
	access *accesslog.Recorder
	log    *slog.Logger
	now    func() time.Time
}

// New builds a Detector.
func New(d Deps) *Detector {
	if d.Log == nil {
		d.Log = slog.Default()
	}
	if d.Now == nil {
		d.Now = time.Now
	}
	return &Detector{pool: d.Pool, repos: db.New(d.Pool), access: d.Access, log: d.Log, now: d.Now}
}

var _ accesslog.SegmentSink = (*Detector)(nil)

// NewFromPool is New for the common case of a *pgxpool.Pool.
func NewFromPool(p *pgxpool.Pool, access *accesslog.Recorder, log *slog.Logger, now func() time.Time) *Detector {
	return New(Deps{Pool: p, Access: access, Log: log, Now: now})
}

// Signal is one detected anomaly. Set Session (the hash of the session ID) for a session-level
// signal, or leave it nil and set Viewer for a viewer-level one.
type Signal struct {
	Tenant  id.TenantID
	Asset   id.AssetID
	Session []byte
	Viewer  string
	Kind    string
	// Detail is small numbers only: the bound and the observed count.
	Detail map[string]int64
	At     time.Time
}

// viewerLevel reports whether the kind belongs to a viewer, not to one session. For those, an
// enabled auto-revoke revokes every active session of the viewer.
func viewerLevel(kind string) bool {
	return kind == db.EventSessionLimit || kind == db.EventRapidSessionCreation
}

// since is the start of the suppression window of a kind at time at.
func since(kind string, at time.Time) time.Time {
	if kind == db.EventSegmentsWithoutKey {
		return time.Unix(0, 0).UTC()
	}
	return at.Add(-Window)
}

// Outcome is what Raise did.
type Outcome struct {
	// Recorded is true when this call stored a new event (false: one already exists in the window,
	// or storing failed).
	Recorded bool
	// Revoked is how many sessions this call revoked.
	Revoked int
}

// Raise records the signal and applies the tenant's auto-revoke policy. It never returns an error:
// a failure is logged (with the kind and a session fingerprint, never an ID or token), because no
// caller can do anything useful with it and none may fail a playback request over it.
//
// When the kind is in the tenant's auto_revoke list the revocation is applied whenever the
// condition is detected, even if the event itself is suppressed as a duplicate. That is what stops
// a scraper that simply creates a new session after the first one was revoked. Revoking is
// idempotent (only active sessions change).
func (d *Detector) Raise(ctx context.Context, sig Signal) Outcome {
	if d == nil || d.pool == nil || sig.Tenant.IsZero() || sig.Asset.IsZero() || !db.ValidEventKind(sig.Kind) {
		return Outcome{}
	}
	if len(sig.Session) == 0 && sig.Viewer == "" {
		return Outcome{}
	}
	if sig.At.IsZero() {
		sig.At = d.now()
	}
	sig.At = sig.At.UTC().Truncate(time.Microsecond)
	// Detached from the request: the answer to the viewer has been decided, and the event must be
	// stored even if the client went away.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()

	revoke := false
	set, err := d.repos.GetPlaybackSettings(ctx, sig.Tenant)
	if err != nil {
		// Not abuse (I11): record the event if the database allows, revoke nothing.
		d.logFailure(sig, "settings unavailable, nothing will be revoked", err)
	} else {
		revoke = slices.Contains(set.AutoRevoke, sig.Kind)
	}

	var out Outcome
	var revoked []db.SessionRef
	err = db.Tx(ctx, d.pool, func(tx *db.Repos) error {
		out, revoked = Outcome{}, nil
		subject := sig.Viewer
		if len(sig.Session) > 0 {
			subject = hex.EncodeToString(sig.Session)
		}
		if err := tx.LockAnomalySubject(ctx, sig.Tenant, sig.Kind, subject); err != nil {
			return err
		}
		recorded, err := tx.InsertAnomalyEvent(ctx, db.NewAnomalyEvent{
			TenantID: sig.Tenant, SessionHash: sig.Session, ViewerID: sig.Viewer, AssetID: sig.Asset,
			Kind: sig.Kind, At: sig.At, Since: since(sig.Kind, sig.At), Detail: sig.Detail,
		})
		if err != nil {
			return err
		}
		out.Recorded = recorded
		if !revoke {
			return nil
		}
		revoked, err = d.revoke(ctx, tx, sig)
		out.Revoked = len(revoked)
		return err
	})
	if err != nil {
		d.logFailure(sig, "signal not recorded, nothing revoked", err)
		return Outcome{}
	}
	for _, ref := range revoked {
		d.recordRevoked(ctx, ref, sig.At)
	}
	if out.Recorded || out.Revoked > 0 {
		d.log.LogAttrs(ctx, slog.LevelWarn, "playback anomaly",
			slog.String("kind", sig.Kind), slog.String("session", fingerprintOf(sig)), slog.Bool("recorded", out.Recorded),
			slog.Int("revoked", out.Revoked))
	}
	return out
}

// revoke applies the auto-revoke policy inside the transaction and audits it.
func (d *Detector) revoke(ctx context.Context, tx *db.Repos, sig Signal) ([]db.SessionRef, error) {
	reason := AutoRevokePrefix + sig.Kind
	var refs []db.SessionRef
	var action, target string
	switch {
	case viewerLevel(sig.Kind):
		var err error
		refs, err = tx.RevokePlaybackSessionsByFilter(ctx, sig.Tenant, sig.Viewer, id.AssetID{}, reason, sig.At)
		if err != nil || len(refs) == 0 {
			return nil, err
		}
		action, target = AuditAutoRevokeBulk, "viewer="+sig.Viewer+" revoked="+strconv.Itoa(len(refs))+" reason="+reason
	default:
		row, changed, err := tx.RevokePlaybackSession(ctx, sig.Tenant, sig.Session, reason, sig.At)
		if err != nil || !changed {
			return nil, err
		}
		refs = []db.SessionRef{{IDHash: sig.Session, TenantID: sig.Tenant, AssetID: row.AssetID, ViewerID: row.ViewerID, AuthMethod: row.AuthMethod}}
		action, target = AuditAutoRevoke, "session:"+hex.EncodeToString(sig.Session[:4])+" reason="+reason
	}
	_, err := tx.InsertAuditEvent(ctx, db.NewAuditEvent{TenantID: sig.Tenant, Action: action, Target: target})
	return refs, err
}

// recordRevoked writes the access-trail row of a revoked session, like a revocation through the
// API does. It carries no address or user agent: nobody made a request.
func (d *Detector) recordRevoked(ctx context.Context, ref db.SessionRef, at time.Time) {
	ev := accesslog.Event{
		TenantID: ref.TenantID, AssetID: ref.AssetID, SessionHash: ref.IDHash, ViewerID: ref.ViewerID,
		AuthMethod: ref.AuthMethod, Kind: db.AccessRevoked, At: at,
	}
	ev.RequestID, _ = reqid.FromContext(ctx)
	d.access.Record(ev)
}

// SegmentsServed implements accesslog.SegmentSink: it adds the counts to the sessions and raises
// segments_without_key for every session that is over its tenant's threshold and has never been
// served the key.
//
// This runs at the segment-count flush instead of reading the access log because the log is best
// effort (rows can be dropped under load) and a missing "key" row would turn into a false
// accusation. The session row's counters are exact and shared by all replicas, the work is one
// batched UPDATE per flush per replica, and the query that finds offenders rides on the same
// statement.
func (d *Detector) SegmentsServed(ctx context.Context, counts []accesslog.SegmentCount) {
	if d == nil || d.pool == nil || len(counts) == 0 {
		return
	}
	deltas := make([]db.SegmentDelta, 0, len(counts))
	for _, c := range counts {
		deltas = append(deltas, db.SegmentDelta{SessionHash: c.SessionHash, Count: c.Count})
	}
	over, err := d.repos.AddPlaybackSegments(ctx, deltas)
	if err != nil {
		d.log.LogAttrs(ctx, slog.LevelWarn, "segment counts not added to sessions", slog.String("code", codeOf(err)))
		return
	}
	for _, o := range over {
		d.Raise(ctx, Signal{
			Tenant: o.TenantID, Asset: o.AssetID, Session: o.SessionHash, Kind: db.EventSegmentsWithoutKey,
			Detail: map[string]int64{"segments": o.Served, "limit": int64(o.Threshold)}, At: d.now(),
		})
	}
}

func (d *Detector) logFailure(sig Signal, msg string, err error) {
	d.log.LogAttrs(context.Background(), slog.LevelWarn, "playback anomaly: "+msg,
		slog.String("kind", sig.Kind), slog.String("session", fingerprintOf(sig)), slog.String("code", codeOf(err)))
}

// fingerprintOf is the label of the signal's session in logs: the same 8 hex characters the access
// log and the events API show. Empty for a viewer-level signal.
func fingerprintOf(sig Signal) string {
	if len(sig.Session) == 0 {
		return ""
	}
	return db.SessionFingerprint(sig.Session, sig.Tenant)
}

// codeOf returns the registered code of err, for logs: never its text, which may name internals.
func codeOf(err error) string {
	var e *errs.Error
	if errors.As(err, &e) {
		return string(e.Code)
	}
	return "unknown"
}
