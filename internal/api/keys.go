package api

import (
	"context"
	"time"

	"github.com/venkataPhanindraVutla/cipherframe/internal/api/gen"
	"github.com/venkataPhanindraVutla/cipherframe/internal/auth"
	"github.com/venkataPhanindraVutla/cipherframe/internal/db"
	"github.com/venkataPhanindraVutla/cipherframe/internal/errs"
	"github.com/venkataPhanindraVutla/cipherframe/internal/id"
	"github.com/venkataPhanindraVutla/cipherframe/internal/reqid"
)

// Page sizes.
const (
	defaultPageSize = 50
	maxPageSize     = 100
)

// noStore is the Cache-Control value of every response that carries a full key.
const noStore = "no-store"

// caller returns the authenticated principal and the audit actor for the request. The guard
// always sets the principal; its absence is a programming error and fails closed.
func caller(ctx context.Context) (auth.Principal, auth.Actor, error) {
	p, ok := auth.PrincipalFrom(ctx)
	if !ok {
		return auth.Principal{}, auth.Actor{}, errs.New(errs.Unauthenticated, "The API key is missing or invalid.")
	}
	rid, _ := reqid.FromContext(ctx)
	return p, auth.Actor{ClientID: p.ClientID, KeyID: p.KeyID, RequestID: rid}, nil
}

func requestID(ctx context.Context) string {
	rid, _ := reqid.FromContext(ctx)
	return rid
}

func pageLimit(p *int) (int, error) {
	if p == nil {
		return defaultPageSize, nil
	}
	if *p < 1 || *p > maxPageSize {
		return 0, errs.New(errs.InvalidRequest, "limit must be between 1 and 100")
	}
	return *p, nil
}

func scopesOut(in []db.Scope) []gen.Scope {
	out := make([]gen.Scope, len(in))
	for i, s := range in {
		out[i] = gen.Scope(s)
	}
	return out
}

func clientOut(c db.Client) gen.Client {
	return gen.Client{Id: c.ID.String(), Name: c.Name, CreatedAt: c.CreatedAt, DisabledAt: c.DisabledAt}
}

// keyOut returns key metadata. It never includes a hash.
func keyOut(k db.APIKey) gen.ApiKey {
	out := gen.ApiKey{
		Id: k.ID.String(), ClientId: k.ClientID.String(), Name: k.Name, Prefix: k.Prefix,
		Scopes: scopesOut(k.Scopes), CreatedAt: k.CreatedAt,
		RotatedAt: k.RotatedAt, RevokedAt: k.RevokedAt, LastUsedAt: k.LastUsedAt,
	}
	if k.Previous != nil {
		t := k.Previous.ValidUntil
		out.PreviousValidUntil = &t
	}
	return out
}

// issuedOut returns key metadata plus the full key, for the single response that shows it.
func issuedOut(i auth.Issued) gen.CreatedApiKey {
	m := keyOut(i.Key)
	return gen.CreatedApiKey{
		Id: m.Id, ClientId: m.ClientId, Name: m.Name, Prefix: m.Prefix, Scopes: m.Scopes,
		CreatedAt: m.CreatedAt, RotatedAt: m.RotatedAt, PreviousValidUntil: m.PreviousValidUntil,
		RevokedAt: m.RevokedAt, LastUsedAt: m.LastUsedAt,
		Key: i.Secret.Reveal(),
	}
}

// GetWhoami returns the identity behind the presented key.
func (s *server) GetWhoami(ctx context.Context, _ gen.GetWhoamiRequestObject) (gen.GetWhoamiResponseObject, error) {
	p, _, err := caller(ctx)
	if err != nil {
		return nil, err
	}
	return gen.GetWhoami200JSONResponse{
		Body: gen.Whoami{
			TenantId: p.TenantID.String(), ClientId: p.ClientID.String(), KeyId: p.KeyID.String(),
			Scopes: scopesOut(p.Scopes),
		},
		Headers: gen.GetWhoami200ResponseHeaders{XRequestId: requestID(ctx)},
	}, nil
}

// CreateClient creates a client in the caller's tenant.
func (s *server) CreateClient(ctx context.Context, req gen.CreateClientRequestObject) (gen.CreateClientResponseObject, error) {
	p, actor, err := caller(ctx)
	if err != nil {
		return nil, err
	}
	if req.Body == nil {
		return nil, errs.New(errs.InvalidRequest, "A request body is required.")
	}
	c, err := s.mgr.CreateClient(ctx, p.TenantID, actor, req.Body.Name)
	if err != nil {
		return nil, err
	}
	return gen.CreateClient201JSONResponse{Body: clientOut(c), Headers: gen.CreateClient201ResponseHeaders{XRequestId: requestID(ctx)}}, nil
}

// ListClients lists the caller's tenant's clients.
func (s *server) ListClients(ctx context.Context, req gen.ListClientsRequestObject) (gen.ListClientsResponseObject, error) {
	p, _, err := caller(ctx)
	if err != nil {
		return nil, err
	}
	limit, err := pageLimit(req.Params.Limit)
	if err != nil {
		return nil, err
	}
	var after id.ClientID
	if req.Params.Cursor != nil {
		if after, err = id.Parse[id.ClientKind](*req.Params.Cursor); err != nil {
			return nil, errs.New(errs.InvalidRequest, "The cursor is invalid.")
		}
	}
	rows, next, err := s.mgr.ListClients(ctx, p.TenantID, after, limit)
	if err != nil {
		return nil, err
	}
	body := gen.ClientList{Items: make([]gen.Client, len(rows))}
	for i, c := range rows {
		body.Items[i] = clientOut(c)
	}
	if !next.IsZero() {
		c := next.String()
		body.NextCursor = &c
	}
	return gen.ListClients200JSONResponse{Body: body, Headers: gen.ListClients200ResponseHeaders{XRequestId: requestID(ctx)}}, nil
}

// CreateKey creates a key for a client of the caller's tenant.
func (s *server) CreateKey(ctx context.Context, req gen.CreateKeyRequestObject) (gen.CreateKeyResponseObject, error) {
	p, actor, err := caller(ctx)
	if err != nil {
		return nil, err
	}
	if req.Body == nil {
		return nil, errs.New(errs.InvalidRequest, "A request body is required.")
	}
	clientID, err := id.Parse[id.ClientKind](req.Body.ClientId)
	if err != nil {
		return nil, errs.New(errs.InvalidRequest, "client_id is not a valid client ID.")
	}
	in := auth.CreateKeyInput{ClientID: clientID, Name: req.Body.Name}
	if req.Body.Scopes != nil {
		in.Scopes = make([]db.Scope, len(*req.Body.Scopes))
		for i, sc := range *req.Body.Scopes {
			in.Scopes[i] = db.Scope(sc)
		}
	}
	issued, err := s.mgr.CreateKey(ctx, p.TenantID, actor, in)
	if err != nil {
		return nil, err
	}
	return gen.CreateKey201JSONResponse{
		Body:    issuedOut(issued),
		Headers: gen.CreateKey201ResponseHeaders{CacheControl: noStore, XRequestId: requestID(ctx)},
	}, nil
}

// ListKeys lists the keys of the caller's tenant, metadata only.
func (s *server) ListKeys(ctx context.Context, req gen.ListKeysRequestObject) (gen.ListKeysResponseObject, error) {
	p, _, err := caller(ctx)
	if err != nil {
		return nil, err
	}
	limit, err := pageLimit(req.Params.Limit)
	if err != nil {
		return nil, err
	}
	var after id.APIKeyID
	if req.Params.Cursor != nil {
		if after, err = id.Parse[id.APIKeyKind](*req.Params.Cursor); err != nil {
			return nil, errs.New(errs.InvalidRequest, "The cursor is invalid.")
		}
	}
	rows, next, err := s.mgr.ListKeys(ctx, p.TenantID, after, limit)
	if err != nil {
		return nil, err
	}
	body := gen.ApiKeyList{Items: make([]gen.ApiKey, len(rows))}
	for i, k := range rows {
		body.Items[i] = keyOut(k)
	}
	if !next.IsZero() {
		c := next.String()
		body.NextCursor = &c
	}
	return gen.ListKeys200JSONResponse{Body: body, Headers: gen.ListKeys200ResponseHeaders{XRequestId: requestID(ctx)}}, nil
}

// RotateKey replaces a key's secret in place. Admin keys may rotate any key of the tenant; any
// other key may rotate only itself (ADR 0018).
func (s *server) RotateKey(ctx context.Context, req gen.RotateKeyRequestObject) (gen.RotateKeyResponseObject, error) {
	p, actor, err := caller(ctx)
	if err != nil {
		return nil, err
	}
	keyID, idErr := id.Parse[id.APIKeyKind](req.KeyId)
	if !p.HasScope(db.ScopeAdmin) && (idErr != nil || keyID != p.KeyID) {
		return nil, errs.New(errs.Forbidden, "This key may rotate only itself unless it has the admin scope.")
	}
	if idErr != nil {
		return nil, errs.New(errs.NotFound, "No such key.")
	}
	overlap := auth.DefaultOverlap
	if req.Body != nil && req.Body.OverlapSeconds != nil {
		n := *req.Body.OverlapSeconds
		if n < 0 || n > int(auth.MaxOverlap/time.Second) {
			return nil, errs.New(errs.InvalidRequest, "overlap_seconds must be between 0 and 86400")
		}
		overlap = time.Duration(n) * time.Second
	}
	issued, err := s.mgr.RotateKey(ctx, p.TenantID, keyID, overlap, actor)
	if err != nil {
		return nil, err
	}
	return gen.RotateKey200JSONResponse{
		Body:    issuedOut(issued),
		Headers: gen.RotateKey200ResponseHeaders{CacheControl: noStore, XRequestId: requestID(ctx)},
	}, nil
}

// RevokeKey disables a key of the caller's tenant immediately.
func (s *server) RevokeKey(ctx context.Context, req gen.RevokeKeyRequestObject) (gen.RevokeKeyResponseObject, error) {
	p, actor, err := caller(ctx)
	if err != nil {
		return nil, err
	}
	keyID, err := id.Parse[id.APIKeyKind](req.KeyId)
	if err != nil {
		return nil, errs.New(errs.NotFound, "No such key.")
	}
	k, err := s.mgr.RevokeKey(ctx, p.TenantID, keyID, actor)
	if err != nil {
		return nil, err
	}
	return gen.RevokeKey200JSONResponse{Body: keyOut(k), Headers: gen.RevokeKey200ResponseHeaders{XRequestId: requestID(ctx)}}, nil
}
