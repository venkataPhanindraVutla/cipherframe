package api

import (
	"context"

	"github.com/venkataPhanindraVutla/cipherframe/internal/api/gen"
	"github.com/venkataPhanindraVutla/cipherframe/internal/db"
	"github.com/venkataPhanindraVutla/cipherframe/internal/errs"
	"github.com/venkataPhanindraVutla/cipherframe/internal/id"
	"github.com/venkataPhanindraVutla/cipherframe/internal/uploads"
)

// service returns the asset service, or dependency_unavailable when the process runs without one.
func (s *server) service() (*uploads.Service, error) {
	if s.assets == nil {
		return nil, errs.New(errs.DependencyUnavailable, "Assets are not available.")
	}
	return s.assets, nil
}

// assetOut converts an asset field by field. It never copies the source key or the object
// store's upload ID: those fields have no counterpart in gen.Asset.
func assetOut(a db.Asset) gen.Asset {
	out := gen.Asset{
		Id:                  a.ID.String(),
		State:               gen.AssetState(a.State),
		SizeBytes:           a.SizeBytes,
		UploadMethod:        gen.UploadMethod(a.UploadMethod),
		CreatedAt:           a.CreatedAt,
		UpdatedAt:           a.UpdatedAt,
		UploadExpiresAt:     a.UploadExpiresAt,
		CommittedAt:         a.CommittedAt,
		ProcessingStartedAt: a.ProcessingStartedAt,
		ReadyAt:             a.ReadyAt,
		FailedAt:            a.FailedAt,
		MaskFaces:           a.MaskFaces,
	}
	if a.MaskFaces {
		m := gen.Masking{State: gen.MaskingStatePending, FacesDetected: a.FacesDetected}
		if a.MaskingState != "" { // empty until the original is ready: the masked variant is pending too
			m.State = gen.MaskingState(a.MaskingState)
		}
		out.Masking = &m
	}
	if a.ContentType != "" {
		ct := a.ContentType
		out.ContentType = &ct
	}
	if a.FailureCode != "" {
		fc := a.FailureCode
		out.FailureCode = &fc
	}
	return out
}

// parseAssetID reads an asset ID path parameter. A malformed ID is not_found, like an unknown
// one, so the answer does not tell the two apart.
func parseAssetID(s string) (id.AssetID, error) {
	a, err := id.Parse[id.AssetKind](s)
	if err != nil {
		return id.AssetID{}, errs.New(errs.NotFound, "No such asset.")
	}
	return a, nil
}

// CreateAsset creates an asset and the instructions for uploading its source.
func (s *server) CreateAsset(ctx context.Context, req gen.CreateAssetRequestObject) (gen.CreateAssetResponseObject, error) {
	p, actor, err := caller(ctx)
	if err != nil {
		return nil, err
	}
	svc, err := s.service()
	if err != nil {
		return nil, err
	}
	if req.Body == nil {
		return nil, errs.New(errs.InvalidRequest, "A request body is required.")
	}
	in := uploads.CreateInput{
		TenantID: p.TenantID, Actor: actor, SizeBytes: req.Body.SizeBytes,
		Method: db.UploadMethod(req.Body.UploadMethod),
	}
	if req.Body.ContentType != nil {
		in.ContentType = *req.Body.ContentType
	}
	if req.Body.MaskFaces != nil {
		in.MaskFaces = *req.Body.MaskFaces
	}
	created, err := svc.Create(ctx, in)
	if err != nil {
		return nil, err
	}
	ins := gen.UploadInstructions{
		Method:    gen.UploadMethod(created.Upload.Method),
		Url:       created.Upload.URL,
		Token:     created.Upload.Token.Reveal(),
		ExpiresAt: created.Upload.ExpiresAt,
	}
	if created.Upload.PartBytes > 0 {
		pb := created.Upload.PartBytes
		ins.PartSizeBytes = &pb
	}
	return gen.CreateAsset201JSONResponse{
		Body:    gen.CreatedAsset{Asset: assetOut(created.Asset), Upload: ins},
		Headers: gen.CreateAsset201ResponseHeaders{CacheControl: noStore, XRequestId: requestID(ctx)},
	}, nil
}

// ListAssets lists the caller's tenant's assets.
func (s *server) ListAssets(ctx context.Context, req gen.ListAssetsRequestObject) (gen.ListAssetsResponseObject, error) {
	p, _, err := caller(ctx)
	if err != nil {
		return nil, err
	}
	svc, err := s.service()
	if err != nil {
		return nil, err
	}
	limit, err := pageLimit(req.Params.Limit)
	if err != nil {
		return nil, err
	}
	var after id.AssetID
	if req.Params.Cursor != nil {
		if after, err = id.Parse[id.AssetKind](*req.Params.Cursor); err != nil {
			return nil, errs.New(errs.InvalidRequest, "The cursor is invalid.")
		}
	}
	rows, next, err := svc.List(ctx, p.TenantID, after, limit)
	if err != nil {
		return nil, err
	}
	body := gen.AssetList{Items: make([]gen.Asset, len(rows))}
	for i, a := range rows {
		body.Items[i] = assetOut(a)
	}
	if !next.IsZero() {
		c := next.String()
		body.NextCursor = &c
	}
	return gen.ListAssets200JSONResponse{Body: body, Headers: gen.ListAssets200ResponseHeaders{XRequestId: requestID(ctx)}}, nil
}

// GetAsset returns one asset of the caller's tenant.
func (s *server) GetAsset(ctx context.Context, req gen.GetAssetRequestObject) (gen.GetAssetResponseObject, error) {
	p, _, err := caller(ctx)
	if err != nil {
		return nil, err
	}
	svc, err := s.service()
	if err != nil {
		return nil, err
	}
	aid, err := parseAssetID(req.AssetId)
	if err != nil {
		return nil, err
	}
	a, err := svc.Get(ctx, p.TenantID, aid)
	if err != nil {
		return nil, err
	}
	return gen.GetAsset200JSONResponse{Body: assetOut(a), Headers: gen.GetAsset200ResponseHeaders{XRequestId: requestID(ctx)}}, nil
}

// CommitAsset ends the upload and queues processing.
func (s *server) CommitAsset(ctx context.Context, req gen.CommitAssetRequestObject) (gen.CommitAssetResponseObject, error) {
	p, actor, err := caller(ctx)
	if err != nil {
		return nil, err
	}
	svc, err := s.service()
	if err != nil {
		return nil, err
	}
	aid, err := parseAssetID(req.AssetId)
	if err != nil {
		return nil, err
	}
	a, err := svc.Commit(ctx, p.TenantID, actor, aid)
	if err != nil {
		return nil, err
	}
	return gen.CommitAsset200JSONResponse{Body: assetOut(a), Headers: gen.CommitAsset200ResponseHeaders{XRequestId: requestID(ctx)}}, nil
}

// AbortAsset stops an upload and deletes its partial objects.
func (s *server) AbortAsset(ctx context.Context, req gen.AbortAssetRequestObject) (gen.AbortAssetResponseObject, error) {
	p, actor, err := caller(ctx)
	if err != nil {
		return nil, err
	}
	svc, err := s.service()
	if err != nil {
		return nil, err
	}
	aid, err := parseAssetID(req.AssetId)
	if err != nil {
		return nil, err
	}
	a, err := svc.Abort(ctx, p.TenantID, actor, aid)
	if err != nil {
		return nil, err
	}
	return gen.AbortAsset200JSONResponse{Body: assetOut(a), Headers: gen.AbortAsset200ResponseHeaders{XRequestId: requestID(ctx)}}, nil
}
