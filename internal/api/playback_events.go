package api

import (
	"context"

	openapi_types "github.com/oapi-codegen/runtime/types"

	"github.com/venkataPhanindraVutla/cipherframe/internal/api/gen"
	"github.com/venkataPhanindraVutla/cipherframe/internal/db"
	"github.com/venkataPhanindraVutla/cipherframe/internal/errs"
	"github.com/venkataPhanindraVutla/cipherframe/internal/id"
)

// eventQuery converts the query parameters of the events read. Every malformed value is a field
// error: an asset filter that is not an asset ID is a bad request, not a "not found", because the
// filter only narrows what the caller's own tenant owns.
func eventQuery(p gen.ListPlaybackEventsParams) (db.EventQuery, error) {
	q := db.EventQuery{Limit: defaultAccessLogPage}
	var fields []errs.FieldError
	bad := func(field, msg string) { fields = append(fields, errs.FieldError{Field: field, Message: msg}) }
	if p.Limit != nil {
		if *p.Limit < 1 || *p.Limit > db.MaxEventPage {
			bad("limit", "must be between 1 and 500")
		} else {
			q.Limit = *p.Limit
		}
	}
	if p.Kind != nil {
		if !db.ValidEventKind(string(*p.Kind)) {
			bad("kind", "is not a known kind")
		} else {
			q.Kind = string(*p.Kind)
		}
	}
	if p.AssetId != nil {
		a, err := id.Parse[id.AssetKind](*p.AssetId)
		if err != nil {
			bad("asset_id", "is not an asset ID")
		} else {
			q.AssetID = a
		}
	}
	if p.ViewerId != nil {
		q.ViewerID = *p.ViewerId
	}
	if p.From != nil {
		q.From = p.From.UTC()
	}
	if p.To != nil {
		q.To = p.To.UTC()
	}
	if p.Cursor != nil {
		c, err := db.ParseEventCursor(*p.Cursor)
		if err != nil {
			bad("cursor", "is invalid")
		} else {
			q.Cursor = &c
		}
	}
	if len(fields) > 0 {
		return db.EventQuery{}, errs.Invalid("The request is invalid.", fields)
	}
	return q, nil
}

// ListPlaybackEvents reads the anomaly events of the caller's tenant, newest first.
func (s *server) ListPlaybackEvents(ctx context.Context, req gen.ListPlaybackEventsRequestObject) (gen.ListPlaybackEventsResponseObject, error) {
	p, _, err := caller(ctx)
	if err != nil {
		return nil, err
	}
	svc, err := s.playbackService()
	if err != nil {
		return nil, err
	}
	q, err := eventQuery(req.Params)
	if err != nil {
		return nil, err
	}
	page, err := svc.Events(ctx, p.TenantID, q)
	if err != nil {
		return nil, err
	}
	out := gen.PlaybackEventList{Items: make([]gen.PlaybackEvent, len(page.Events))}
	for i, e := range page.Events {
		item := gen.PlaybackEvent{
			Id: openapi_types.UUID(e.ID), Kind: gen.PlaybackEventKind(e.Kind), At: e.At, AssetId: e.AssetID.String(), Detail: e.Detail,
		}
		if e.ViewerID != "" {
			v := e.ViewerID
			item.ViewerId = &v
		}
		if e.SessionFingerprint != "" {
			f := e.SessionFingerprint
			item.Session = &f
		}
		out.Items[i] = item
	}
	if page.Next != nil {
		c := page.Next.Encode()
		out.NextCursor = &c
	}
	return gen.ListPlaybackEvents200JSONResponse{
		Body: out, Headers: gen.ListPlaybackEvents200ResponseHeaders{CacheControl: noStore, XRequestId: requestID(ctx)},
	}, nil
}
