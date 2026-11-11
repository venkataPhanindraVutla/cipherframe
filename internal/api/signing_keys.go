package api

import (
	"context"

	"github.com/venkataPhanindraVutla/cipherframe/internal/api/gen"
	"github.com/venkataPhanindraVutla/cipherframe/internal/errs"
	"github.com/venkataPhanindraVutla/cipherframe/internal/signing"
)

// Header values of the public key set.
const (
	publicCacheControl = "public, max-age=300"
	corsAnyOrigin      = "*"
)

func errSigningUnavailable() error {
	return errs.New(errs.DependencyUnavailable, "Signing keys are not available.")
}

func signingKeyOut(k signing.PublicKey) gen.SigningKey {
	return gen.SigningKey{
		KeyId: k.KeyID, Algorithm: gen.SigningKeyAlgorithm(k.Algorithm), State: gen.SigningKeyState(k.Status),
		Current: k.Current, PublicKey: k.PublicKeyBase64(),
		CreatedAt: k.CreatedAt, ActivatedAt: k.ActivatedAt, RetiredAt: k.RetiredAt,
	}
}

// ListSigningKeys lists every integrity signing key, public data only. The keys are
// deployment-wide, so the caller's tenant does not filter them.
func (s *server) ListSigningKeys(ctx context.Context, _ gen.ListSigningKeysRequestObject) (gen.ListSigningKeysResponseObject, error) {
	if s.signing == nil {
		return nil, errSigningUnavailable()
	}
	keys, err := s.signing.PublicKeys(ctx)
	if err != nil {
		return nil, err
	}
	body := gen.SigningKeyList{Items: make([]gen.SigningKey, len(keys))}
	for i, k := range keys {
		body.Items[i] = signingKeyOut(k)
	}
	return gen.ListSigningKeys200JSONResponse{Body: body, Headers: gen.ListSigningKeys200ResponseHeaders{XRequestId: requestID(ctx)}}, nil
}

// RotateSigningKey creates a new current key; the previous one stays active and published.
func (s *server) RotateSigningKey(ctx context.Context, _ gen.RotateSigningKeyRequestObject) (gen.RotateSigningKeyResponseObject, error) {
	p, actor, err := caller(ctx)
	if err != nil {
		return nil, err
	}
	if s.signing == nil {
		return nil, errSigningUnavailable()
	}
	k, err := s.signing.Rotate(ctx, signing.Audit{TenantID: p.TenantID, Actor: actor})
	if err != nil {
		return nil, err
	}
	return gen.RotateSigningKey201JSONResponse{Body: signingKeyOut(k), Headers: gen.RotateSigningKey201ResponseHeaders{XRequestId: requestID(ctx)}}, nil
}

// RetireSigningKey retires a non-current key. It stays published.
func (s *server) RetireSigningKey(ctx context.Context, req gen.RetireSigningKeyRequestObject) (gen.RetireSigningKeyResponseObject, error) {
	p, actor, err := caller(ctx)
	if err != nil {
		return nil, err
	}
	if s.signing == nil {
		return nil, errSigningUnavailable()
	}
	k, err := s.signing.Retire(ctx, req.KeyId, signing.Audit{TenantID: p.TenantID, Actor: actor})
	if err != nil {
		return nil, err
	}
	return gen.RetireSigningKey200JSONResponse{Body: signingKeyOut(k), Headers: gen.RetireSigningKey200ResponseHeaders{XRequestId: requestID(ctx)}}, nil
}

// GetSigningKeySet serves the public key set. It needs no authentication and no key service.
func (s *server) GetSigningKeySet(ctx context.Context, _ gen.GetSigningKeySetRequestObject) (gen.GetSigningKeySetResponseObject, error) {
	if s.keyset == nil {
		return nil, errSigningUnavailable()
	}
	keys, err := s.keyset.Get(ctx)
	if err != nil {
		return nil, err
	}
	body := gen.SigningKeySet{Keys: make([]gen.PublishedSigningKey, len(keys))}
	for i, k := range keys {
		body.Keys[i] = gen.PublishedSigningKey{
			Keyid: k.KeyID, Alg: gen.PublishedSigningKeyAlg(k.Algorithm), PublicKey: k.PublicKeyBase64(),
			Status: gen.PublishedSigningKeyStatus(k.Status), CreatedAt: k.CreatedAt, RetiredAt: k.RetiredAt,
		}
	}
	return gen.GetSigningKeySet200JSONResponse{Body: body, Headers: gen.GetSigningKeySet200ResponseHeaders{
		CacheControl: publicCacheControl, AccessControlAllowOrigin: corsAnyOrigin, XRequestId: requestID(ctx),
	}}, nil
}
