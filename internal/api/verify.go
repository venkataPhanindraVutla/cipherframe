package api

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"regexp"
	"strings"

	"github.com/venkataPhanindraVutla/cipherframe/internal/api/gen"
	"github.com/venkataPhanindraVutla/cipherframe/internal/db"
	"github.com/venkataPhanindraVutla/cipherframe/internal/errs"
	"github.com/venkataPhanindraVutla/cipherframe/internal/httpx"
	"github.com/venkataPhanindraVutla/cipherframe/internal/id"
	"github.com/venkataPhanindraVutla/cipherframe/internal/integrity/dsse"
	"github.com/venkataPhanindraVutla/cipherframe/internal/integrity/manifest"
	"github.com/venkataPhanindraVutla/cipherframe/internal/integrity/proof"
	"github.com/venkataPhanindraVutla/cipherframe/internal/storage/keys"
)

// manifestContentType is the media type of the manifest endpoint (ADR 0039).
const manifestContentType = "application/vnd.cipherframe.manifest+json; profile=dsse"

var sha256Hex = regexp.MustCompile(`^[0-9a-f]{64}$`)

func (s *server) integrityDeps() (*db.Repos, error) {
	if s.repos == nil || s.keyset == nil {
		return nil, errs.New(errs.DependencyUnavailable, "Integrity manifests are not available.")
	}
	return s.repos, nil
}

func errNoManifest() error {
	return errs.New(errs.NotFound, "The asset has no manifest.")
}

func isNotFound(err error) bool {
	var e *errs.Error
	return errors.As(err, &e) && e.Code == errs.NotFound
}

// manifestRow returns the stored manifest of a ready asset of the tenant. An unknown asset, one of
// another tenant, one that is not ready and one without a manifest are all not_found.
func manifestRow(ctx context.Context, repos *db.Repos, tenantID id.TenantID, assetID id.AssetID) (db.Asset, db.AssetManifest, error) {
	a, err := repos.GetAsset(ctx, tenantID, assetID)
	if err != nil {
		return db.Asset{}, db.AssetManifest{}, err
	}
	if a.State != db.AssetReady {
		return db.Asset{}, db.AssetManifest{}, errNoManifest()
	}
	m, err := repos.GetManifest(ctx, assetID)
	if err != nil {
		if isNotFound(err) {
			return db.Asset{}, db.AssetManifest{}, errNoManifest()
		}
		return db.Asset{}, db.AssetManifest{}, err
	}
	if m.TenantID != tenantID { // defence in depth: the asset lookup is already tenant-scoped
		return db.Asset{}, db.AssetManifest{}, errNoManifest()
	}
	return a, m, nil
}

// manifestResponse writes the stored envelope as it is.
type manifestResponse struct {
	body      []byte
	requestID string
}

func (r manifestResponse) VisitGetAssetManifestResponse(w http.ResponseWriter) error {
	w.Header().Set("Content-Type", manifestContentType)
	w.Header().Set("X-Request-Id", r.requestID)
	w.WriteHeader(http.StatusOK)
	_, err := w.Write(r.body)
	return err
}

// GetAssetManifest returns the signed manifest envelope of a ready asset, as stored.
func (s *server) GetAssetManifest(ctx context.Context, req gen.GetAssetManifestRequestObject) (gen.GetAssetManifestResponseObject, error) {
	p, _, err := caller(ctx)
	if err != nil {
		return nil, err
	}
	repos, err := s.integrityDeps()
	if err != nil {
		return nil, err
	}
	aid, err := parseAssetID(req.AssetId)
	if err != nil {
		return nil, err
	}
	_, m, err := manifestRow(ctx, repos, p.TenantID, aid)
	if err != nil {
		return nil, err
	}
	return manifestResponse{body: m.Envelope, requestID: requestID(ctx)}, nil
}

// decodeManifest reads the manifest out of a stored envelope without checking its signature.
func decodeManifest(envelope []byte) (manifest.Manifest, *dsse.Envelope, error) {
	env, err := dsse.Decode(envelope)
	if err != nil {
		return manifest.Manifest{}, nil, err
	}
	var m manifest.Manifest
	if err := json.Unmarshal(env.Payload, &m); err != nil {
		return manifest.Manifest{}, nil, err
	}
	return m, env, nil
}

// GetAssetProof returns the inclusion proof of one artifact, computed from the stored manifest.
func (s *server) GetAssetProof(ctx context.Context, req gen.GetAssetProofRequestObject) (gen.GetAssetProofResponseObject, error) {
	p, _, err := caller(ctx)
	if err != nil {
		return nil, err
	}
	repos, err := s.integrityDeps()
	if err != nil {
		return nil, err
	}
	variant := proof.Original
	var fields []errs.FieldError
	if req.Params.Variant != nil {
		variant = string(*req.Params.Variant)
	}
	if variant != proof.Original && variant != proof.Masked {
		fields = append(fields, errs.FieldError{Field: "variant", Message: "must be original or masked"})
	}
	if req.Params.Path == "" || len(req.Params.Path) > 512 {
		fields = append(fields, errs.FieldError{Field: "path", Message: "is required and at most 512 characters"})
	}
	if len(fields) > 0 {
		return nil, errs.Invalid("The request is invalid.", fields)
	}
	aid, err := parseAssetID(req.AssetId)
	if err != nil {
		return nil, err
	}
	asset, row, err := manifestRow(ctx, repos, p.TenantID, aid)
	if err != nil {
		return nil, err
	}
	m, _, err := decodeManifest(row.Envelope)
	if err != nil {
		httpx.Logger(ctx).Error("stored manifest does not decode", slog.String("asset_id", aid.String()), slog.Any("error", err))
		return nil, errs.New(errs.InternalError, "An internal error occurred.")
	}
	pf, err := proof.Build(m, variant, req.Params.Path)
	switch {
	case errors.Is(err, proof.ErrNotFound):
		return nil, errs.New(errs.ArtifactNotFound, "The manifest has no artifact at this path.")
	case errors.Is(err, proof.ErrNoVariant) && !asset.MaskFaces:
		return nil, errs.New(errs.VariantUnavailable, "The asset has no masked variant.")
	case errors.Is(err, proof.ErrNoVariant):
		return nil, errs.New(errs.VariantNotReady, "The masked variant is not ready.")
	case err != nil:
		httpx.Logger(ctx).Error("stored manifest does not yield a proof", slog.String("asset_id", aid.String()), slog.Any("error", err))
		return nil, errs.New(errs.InternalError, "An internal error occurred.")
	}
	return gen.GetAssetProof200JSONResponse{Body: proofOut(*pf), Headers: gen.GetAssetProof200ResponseHeaders{XRequestId: requestID(ctx)}}, nil
}

func proofOut(p proof.Proof) gen.InclusionProof {
	out := gen.InclusionProof{
		AssetId: p.AssetID, Variant: gen.ArtifactVariant(p.Variant), Path: p.Path, Sha256: p.SHA256, Size: p.Size,
		TopLevel: gen.ProofLevel{
			LeafIndex: int(p.TopLevel.LeafIndex), TreeSize: int(p.TopLevel.TreeSize), AuditPath: p.TopLevel.AuditPath, Root: p.TopLevel.Root,
		},
	}
	if p.TopLevel.AuditPath == nil {
		out.TopLevel.AuditPath = []string{}
	}
	if p.RenditionRoot != "" {
		li, ts := int(*p.LeafIndex), int(*p.TreeSize)
		out.LeafIndex, out.TreeSize, out.Rendition, out.RenditionRoot, out.AuditPath = &li, &ts, &p.Rendition, &p.RenditionRoot, &p.AuditPath
	}
	return out
}

// VerifyArtifact answers whether a SHA-256 is what Cipherframe signed.
func (s *server) VerifyArtifact(ctx context.Context, req gen.VerifyArtifactRequestObject) (gen.VerifyArtifactResponseObject, error) {
	p, _, err := caller(ctx)
	if err != nil {
		return nil, err
	}
	repos, err := s.integrityDeps()
	if err != nil {
		return nil, err
	}
	if req.Body == nil {
		return nil, errs.New(errs.InvalidRequest, "A request body is required.")
	}
	b := req.Body
	var fields []errs.FieldError
	if !sha256Hex.MatchString(b.Sha256) {
		fields = append(fields, errs.FieldError{Field: "sha256", Message: "must be 64 lowercase hex digits"})
	}
	if (b.AssetId == nil) != (b.Path == nil) || (b.AssetId == nil && b.Variant != nil) {
		fields = append(fields, errs.FieldError{Field: "path", Message: "asset_id and path go together, and variant needs both"})
	}
	variant := proof.Original
	if b.Variant != nil {
		variant = string(*b.Variant)
	}
	if variant != proof.Original && variant != proof.Masked {
		fields = append(fields, errs.FieldError{Field: "variant", Message: "must be original or masked"})
	}
	if b.Path != nil && (*b.Path == "" || len(*b.Path) > 512) {
		fields = append(fields, errs.FieldError{Field: "path", Message: "must be 1 to 512 characters"})
	}
	if len(fields) > 0 {
		return nil, errs.Invalid("The request is invalid.", fields)
	}
	var res gen.VerifyResult
	if b.AssetId != nil {
		res, err = s.verifyAt(ctx, repos, p.TenantID, *b.AssetId, variant, *b.Path, b.Sha256)
	} else {
		res, err = s.verifyByHash(ctx, repos, p.TenantID, b.Sha256)
	}
	if err != nil {
		return nil, err
	}
	return gen.VerifyArtifact200JSONResponse{Body: res, Headers: gen.VerifyArtifact200ResponseHeaders{XRequestId: requestID(ctx)}}, nil
}

func cannotSay(reason gen.VerifyResultReason) gen.VerifyResult {
	return gen.VerifyResult{Outcome: gen.CannotSay, Reason: &reason}
}

// verifyAt compares sum with the artifact at path of the asset's signed manifest.
func (s *server) verifyAt(ctx context.Context, repos *db.Repos, tenantID id.TenantID, assetID, variant, path, sum string) (gen.VerifyResult, error) {
	aid, err := parseAssetID(assetID)
	if err != nil {
		return cannotSay(gen.NoMatch), nil //nolint:nilerr // an unparsable ID is an unknown asset
	}
	_, row, err := manifestRow(ctx, repos, tenantID, aid)
	if isNotFound(err) {
		return cannotSay(gen.NoMatch), nil
	}
	if err != nil {
		return gen.VerifyResult{}, err
	}
	m, err := s.signedManifest(ctx, row.Envelope)
	if err != nil {
		var e *errs.Error
		if errors.As(err, &e) { // the key set is unavailable: a dependency, not a verdict
			return gen.VerifyResult{}, err
		}
		httpx.Logger(ctx).Error("stored manifest failed verification", slog.String("asset_id", aid.String()), slog.Any("error", err))
		return cannotSay(gen.ManifestUnverifiable), nil
	}
	pf, err := proof.Build(m, variant, path)
	switch {
	case errors.Is(err, proof.ErrNotFound), errors.Is(err, proof.ErrNoVariant):
		return cannotSay(gen.NoMatch), nil
	case err != nil:
		httpx.Logger(ctx).Error("stored manifest does not yield a proof", slog.String("asset_id", aid.String()), slog.Any("error", err))
		return cannotSay(gen.ManifestUnverifiable), nil
	}
	aidStr, v := aid.String(), gen.ArtifactVariant(variant)
	res := gen.VerifyResult{Outcome: gen.Modified, AssetId: &aidStr, Variant: &v, Path: &path}
	if pf.SHA256 == sum {
		out := proofOut(*pf)
		res.Outcome, res.Proof = gen.Ours, &out
	}
	return res, nil
}

// signedManifest decodes the envelope and returns its manifest only if a published key signed it.
// A failure to read the key set is an *errs.Error; any other error means the manifest cannot be
// trusted.
func (s *server) signedManifest(ctx context.Context, envelope []byte) (manifest.Manifest, error) {
	m, env, err := decodeManifest(envelope)
	if err != nil {
		return manifest.Manifest{}, err
	}
	published, err := s.keyset.Get(ctx)
	if err != nil {
		return manifest.Manifest{}, err
	}
	trusted := make(map[string]ed25519.PublicKey, len(published))
	for _, k := range published {
		trusted[k.KeyID] = k.PublicKey
	}
	res, err := dsse.Verify(env, manifest.PayloadType, trusted)
	if err != nil {
		return manifest.Manifest{}, err
	}
	return m, res.RequireAny()
}

// verifyByHash looks sum up among the tenant's registered artifacts and confirms each candidate
// against its signed manifest, so the answer is the manifest path and never a storage key.
func (s *server) verifyByHash(ctx context.Context, repos *db.Repos, tenantID id.TenantID, sum string) (gen.VerifyResult, error) {
	raw, err := hex.DecodeString(sum)
	if err != nil {
		return cannotSay(gen.NoMatch), nil //nolint:nilerr // validated by the caller
	}
	matches, err := repos.FindArtifactsBySHA256(ctx, tenantID, raw)
	if err != nil {
		return gen.VerifyResult{}, err
	}
	out := cannotSay(gen.NoMatch)
	for _, m := range matches {
		v := keys.Variant(m.Variant)
		prefix := keys.VariantHLSPrefix(tenantID, m.AssetID, v)
		path, ok := strings.CutPrefix(m.ObjectKey, prefix)
		if !ok || path == "" {
			continue
		}
		res, err := s.verifyAt(ctx, repos, tenantID, m.AssetID.String(), m.Variant, path, sum)
		if err != nil {
			return gen.VerifyResult{}, err
		}
		switch {
		case res.Outcome == gen.Ours:
			return res, nil
		case res.Reason != nil && *res.Reason == gen.ManifestUnverifiable:
			out = res
		}
	}
	return out, nil
}
