package api

import (
	"context"

	"github.com/venkataPhanindraVutla/cipherframe/internal/api/gen"
	"github.com/venkataPhanindraVutla/cipherframe/internal/db"
	"github.com/venkataPhanindraVutla/cipherframe/internal/errs"
	"github.com/venkataPhanindraVutla/cipherframe/internal/id"
	"github.com/venkataPhanindraVutla/cipherframe/internal/playback"
)

const defaultAccessLogPage = 100

// accessQuery converts the query parameters shared by both access-log reads.
func accessQuery(from, to *gen.AccessLogFrom, event *gen.AccessLogEvent, limit *gen.AccessLogLimit, cursor *gen.AccessLogCursor) (db.AccessLogQuery, error) {
	q := db.AccessLogQuery{Limit: defaultAccessLogPage}
	var fields []errs.FieldError
	if limit != nil {
		if *limit < 1 || *limit > db.MaxAccessLogPage {
			fields = append(fields, errs.FieldError{Field: "limit", Message: "must be between 1 and 500"})
		} else {
			q.Limit = *limit
		}
	}
	if event != nil {
		if !db.ValidAccessEvent(string(*event)) {
			fields = append(fields, errs.FieldError{Field: "event", Message: "is not a known event"})
		} else {
			q.Event = string(*event)
		}
	}
	if from != nil {
		q.From = from.UTC()
	}
	if to != nil {
		q.To = to.UTC()
	}
	if cursor != nil {
		c, err := db.ParseAccessLogCursor(*cursor)
		if err != nil {
			fields = append(fields, errs.FieldError{Field: "cursor", Message: "is invalid"})
		} else {
			q.Cursor = &c
		}
	}
	if len(fields) > 0 {
		return db.AccessLogQuery{}, errs.Invalid("The request is invalid.", fields)
	}
	return q, nil
}

func accessListOut(page playback.AccessLogPage) gen.AccessLogList {
	out := gen.AccessLogList{Items: make([]gen.AccessLogEntry, len(page.Entries))}
	for i, e := range page.Entries {
		item := gen.AccessLogEntry{Event: gen.AccessLogEvent(e.Event), At: e.At}
		if !e.AssetID.IsZero() {
			a := e.AssetID.String()
			item.AssetId = &a
		}
		if e.SessionFingerprint != "" {
			item.Session = &e.SessionFingerprint
		}
		if e.ViewerID != "" {
			item.ViewerId = &e.ViewerID
		}
		if e.AuthMethod != "" {
			m := gen.AccessLogEntryAuthMethod(e.AuthMethod)
			item.AuthMethod = &m
		}
		if e.SegmentsServed > 0 {
			n := e.SegmentsServed
			item.SegmentsServed = &n
		}
		if e.IP != "" {
			item.Ip = &e.IP
		}
		if e.UserAgent != "" {
			item.UserAgent = &e.UserAgent
		}
		if e.RequestID != "" {
			item.RequestId = &e.RequestID
		}
		out.Items[i] = item
	}
	if page.Next != nil {
		c := page.Next.Encode()
		out.NextCursor = &c
	}
	return out
}

// GetAssetAccessLog reads the access trail of one asset of the caller's tenant.
func (s *server) GetAssetAccessLog(ctx context.Context, req gen.GetAssetAccessLogRequestObject) (gen.GetAssetAccessLogResponseObject, error) {
	p, _, err := caller(ctx)
	if err != nil {
		return nil, err
	}
	svc, err := s.playbackService()
	if err != nil {
		return nil, err
	}
	aid, err := parseAssetID(req.AssetId)
	if err != nil {
		return nil, err
	}
	q, err := accessQuery(req.Params.From, req.Params.To, req.Params.Event, req.Params.Limit, req.Params.Cursor)
	if err != nil {
		return nil, err
	}
	page, err := svc.AssetAccessLog(ctx, p.TenantID, aid, q)
	if err != nil {
		return nil, err
	}
	return gen.GetAssetAccessLog200JSONResponse{
		Body: accessListOut(page), Headers: gen.GetAssetAccessLog200ResponseHeaders{CacheControl: noStore, XRequestId: requestID(ctx)},
	}, nil
}

// GetPlaybackSessionAccessLog reads the access trail of one session of the caller's tenant.
func (s *server) GetPlaybackSessionAccessLog(ctx context.Context, req gen.GetPlaybackSessionAccessLogRequestObject) (gen.GetPlaybackSessionAccessLogResponseObject, error) {
	p, _, err := caller(ctx)
	if err != nil {
		return nil, err
	}
	svc, err := s.playbackService()
	if err != nil {
		return nil, err
	}
	sid, err := id.ParseSession(req.SessionId)
	if err != nil {
		return nil, errNoSuchSession()
	}
	q, err := accessQuery(req.Params.From, req.Params.To, req.Params.Event, req.Params.Limit, req.Params.Cursor)
	if err != nil {
		return nil, err
	}
	page, err := svc.SessionAccessLog(ctx, p.TenantID, sid, q)
	if err != nil {
		return nil, notFoundAs(err, errNoSuchSession)
	}
	return gen.GetPlaybackSessionAccessLog200JSONResponse{
		Body: accessListOut(page), Headers: gen.GetPlaybackSessionAccessLog200ResponseHeaders{CacheControl: noStore, XRequestId: requestID(ctx)},
	}, nil
}

func privacyOut(s db.PrivacySettings) gen.PrivacySettings {
	out := gen.PrivacySettings{StoreIp: s.StoreIP, StoreUserAgent: s.StoreUserAgent}
	if !s.UpdatedAt.IsZero() {
		t := s.UpdatedAt
		out.UpdatedAt = &t
	}
	return out
}

// GetPrivacySettings returns the caller's tenant's effective privacy settings.
func (s *server) GetPrivacySettings(ctx context.Context, _ gen.GetPrivacySettingsRequestObject) (gen.GetPrivacySettingsResponseObject, error) {
	p, _, err := caller(ctx)
	if err != nil {
		return nil, err
	}
	svc, err := s.playbackService()
	if err != nil {
		return nil, err
	}
	set, err := svc.GetPrivacy(ctx, p.TenantID)
	if err != nil {
		return nil, err
	}
	return gen.GetPrivacySettings200JSONResponse{Body: privacyOut(set), Headers: gen.GetPrivacySettings200ResponseHeaders{XRequestId: requestID(ctx)}}, nil
}

// UpdatePrivacySettings replaces every privacy setting of the caller's tenant.
func (s *server) UpdatePrivacySettings(ctx context.Context, req gen.UpdatePrivacySettingsRequestObject) (gen.UpdatePrivacySettingsResponseObject, error) {
	p, actor, err := caller(ctx)
	if err != nil {
		return nil, err
	}
	svc, err := s.playbackService()
	if err != nil {
		return nil, err
	}
	if req.Body == nil {
		return nil, errs.New(errs.InvalidRequest, "A request body is required.")
	}
	var missing []errs.FieldError
	if req.Body.StoreIp == nil {
		missing = append(missing, errs.FieldError{Field: "store_ip", Message: "is required"})
	}
	if req.Body.StoreUserAgent == nil {
		missing = append(missing, errs.FieldError{Field: "store_user_agent", Message: "is required"})
	}
	if len(missing) > 0 {
		return nil, errs.Invalid("The privacy settings are incomplete.", missing)
	}
	set, err := svc.PutPrivacy(ctx, p.TenantID, actor, db.PrivacySettings{StoreIP: *req.Body.StoreIp, StoreUserAgent: *req.Body.StoreUserAgent})
	if err != nil {
		return nil, err
	}
	return gen.UpdatePrivacySettings200JSONResponse{Body: privacyOut(set), Headers: gen.UpdatePrivacySettings200ResponseHeaders{XRequestId: requestID(ctx)}}, nil
}
