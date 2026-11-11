package edge

import (
	"context"

	"github.com/venkataPhanindraVutla/cipherframe/internal/edge/gen"
	"github.com/venkataPhanindraVutla/cipherframe/internal/errs"
)

// Header values of the public key set. It is public data: any origin may read it, and no
// credentials are involved.
const (
	publicCacheControl = "public, max-age=300"
	corsAnyOrigin      = "*"
)

// GetSigningKeySet serves /.well-known/cipherframe-keys.json (M5-2, ADR 0033): the public keys
// that verify integrity manifests and deletion records. It reads only public data through a
// 60-second in-process cache, needs no authentication, and never touches the key service.
func (s *server) GetSigningKeySet(ctx context.Context, _ gen.GetSigningKeySetRequestObject) (gen.GetSigningKeySetResponseObject, error) {
	if s.keyset == nil {
		return nil, errs.New(errs.DependencyUnavailable, "Signing keys are not available.")
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
