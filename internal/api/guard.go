package api

import (
	"errors"
	"log/slog"
	"net/http"
	"strings"

	"github.com/venkataPhanindraVutla/cipherframe/internal/api/gen"
	"github.com/venkataPhanindraVutla/cipherframe/internal/auth"
	"github.com/venkataPhanindraVutla/cipherframe/internal/db"
	"github.com/venkataPhanindraVutla/cipherframe/internal/errs"
	"github.com/venkataPhanindraVutla/cipherframe/internal/httpx"
)

// operationScopes lists the scopes each authenticated operation requires, keyed by operationId.
// An empty list means any valid key. It is the single place scopes are enforced from; a contract
// test asserts that it equals the `security` requirements in spec/openapi.yaml.
//
// rotateKey lists no scope because its rule is "admin, or the key rotating itself", which needs
// the target key and is applied in the handler.
var operationScopes = map[string][]db.Scope{
	"GetWhoami":    {},
	"CreateClient": {db.ScopeAdmin},
	"ListClients":  {db.ScopeAdmin},
	"CreateKey":    {db.ScopeAdmin},
	"ListKeys":     {db.ScopeAdmin},
	"RotateKey":    {},
	"RevokeKey":    {db.ScopeAdmin},

	"CreateAsset": {db.ScopeAssetsWrite},
	"ListAssets":  {db.ScopeAssetsRead},
	"GetAsset":    {db.ScopeAssetsRead},
	"CommitAsset": {db.ScopeAssetsWrite},
	"AbortAsset":  {db.ScopeAssetsWrite},

	"CreatePlaybackSession":  {db.ScopeSessionsWrite},
	"GetPlaybackSession":     {db.ScopeSessionsWrite},
	"RevokePlaybackSession":  {db.ScopeSessionsWrite},
	"RevokePlaybackSessions": {db.ScopeSessionsWrite},
	"GetPlaybackSettings":    {db.ScopeAdmin},
	"UpdatePlaybackSettings": {db.ScopeAdmin},

	"ListPlaybackEvents":          {db.ScopeAssetsRead},
	"GetAssetAccessLog":           {db.ScopeAssetsRead},
	"GetAssetManifest":            {db.ScopeAssetsRead},
	"GetAssetManifestTimestamp":   {db.ScopeAssetsRead},
	"GetAssetProof":               {db.ScopeAssetsRead},
	"VerifyArtifact":              {db.ScopeAssetsRead},
	"GetPlaybackSessionAccessLog": {db.ScopeAssetsRead},
	"GetPrivacySettings":          {db.ScopeAdmin},
	"UpdatePrivacySettings":       {db.ScopeAdmin},

	"GetPlaybackAuth":              {db.ScopeAdmin},
	"UpdatePlaybackAuth":           {db.ScopeAdmin},
	"PutPlaybackJwtKey":            {db.ScopeAdmin},
	"DeletePlaybackJwtKey":         {db.ScopeAdmin},
	"RotatePlaybackCallbackSecret": {db.ScopeAdmin},

	"ListSigningKeys":  {db.ScopeAdmin},
	"RotateSigningKey": {db.ScopeAdmin},
	"RetireSigningKey": {db.ScopeAdmin},
}

// publicOperations are served without authentication.
var publicOperations = []string{"GetHealthz", "GetReadyz", "GetSigningKeySet"}

// OperationScopes returns a copy of the scope table keyed by the spec's operationId (lower
// camel case, for example "getWhoami"), with scopes as strings. The contract test compares it
// with the spec.
func OperationScopes() map[string][]string {
	out := make(map[string][]string, len(operationScopes))
	for op, scopes := range operationScopes {
		ss := make([]string, len(scopes))
		for i, s := range scopes {
			ss[i] = string(s)
		}
		out[strings.ToLower(op[:1])+op[1:]] = ss
	}
	return out
}

// PublicOperations returns the operationIds served without authentication.
func PublicOperations() []string {
	out := make([]string, len(publicOperations))
	for i, op := range publicOperations {
		out[i] = strings.ToLower(op[:1]) + op[1:]
	}
	return out
}

// authn authenticates a request and checks its scopes before the generated handler runs, so a
// request without a valid key never reaches body decoding or a handler.
type authn struct {
	verifier *auth.Verifier
	log      *slog.Logger
}

// run authenticates r for operation op and, on success, calls next with a request whose context
// carries the principal.
func (a *authn) run(op string, w http.ResponseWriter, r *http.Request, next func(*http.Request)) {
	p, err := a.authenticate(r)
	if err != nil {
		var e *errs.Error
		if errors.As(err, &e) && e.Code == errs.Unauthenticated {
			w.Header().Set("WWW-Authenticate", "Bearer")
		}
		httpx.ResponseErrorHandler(w, r, err)
		return
	}
	need, known := operationScopes[op]
	if !known { // fail closed: a guarded method with no table entry is a programming error
		httpx.Logger(r.Context()).Error("operation has no scope entry", slog.String("operation", op))
		httpx.ResponseErrorHandler(w, r, errs.New(errs.InternalError, "An internal error occurred."))
		return
	}
	for _, s := range need {
		if !p.HasScope(s) {
			httpx.ResponseErrorHandler(w, r, errs.New(errs.Forbidden, "This operation requires the "+string(s)+" scope."))
			return
		}
	}
	next(r.WithContext(auth.WithPrincipal(r.Context(), p)))
}

func (a *authn) authenticate(r *http.Request) (auth.Principal, error) {
	hdr := r.Header.Values("Authorization")
	if len(hdr) != 1 {
		return auth.Principal{}, errs.New(errs.Unauthenticated, "The API key is missing or invalid.")
	}
	token, ok := auth.BearerToken(hdr[0])
	if !ok {
		return auth.Principal{}, errs.New(errs.Unauthenticated, "The API key is missing or invalid.")
	}
	if a.verifier == nil {
		return auth.Principal{}, errs.New(errs.DependencyUnavailable, "Authentication is not available.")
	}
	return a.verifier.Authenticate(r.Context(), token)
}

// guarded wraps the generated server interface: every secured operation authenticates first.
// Health and readiness pass through unchanged.
type guarded struct {
	gen.ServerInterface
	a *authn
}

func (g guarded) GetWhoami(w http.ResponseWriter, r *http.Request) {
	g.a.run("GetWhoami", w, r, func(r *http.Request) { g.ServerInterface.GetWhoami(w, r) })
}

func (g guarded) CreateClient(w http.ResponseWriter, r *http.Request) {
	g.a.run("CreateClient", w, r, func(r *http.Request) { g.ServerInterface.CreateClient(w, r) })
}

func (g guarded) ListClients(w http.ResponseWriter, r *http.Request, params gen.ListClientsParams) {
	g.a.run("ListClients", w, r, func(r *http.Request) { g.ServerInterface.ListClients(w, r, params) })
}

func (g guarded) CreateKey(w http.ResponseWriter, r *http.Request) {
	g.a.run("CreateKey", w, r, func(r *http.Request) { g.ServerInterface.CreateKey(w, r) })
}

func (g guarded) ListKeys(w http.ResponseWriter, r *http.Request, params gen.ListKeysParams) {
	g.a.run("ListKeys", w, r, func(r *http.Request) { g.ServerInterface.ListKeys(w, r, params) })
}

func (g guarded) RotateKey(w http.ResponseWriter, r *http.Request, keyID gen.KeyId) {
	g.a.run("RotateKey", w, r, func(r *http.Request) { g.ServerInterface.RotateKey(w, r, keyID) })
}

func (g guarded) RevokeKey(w http.ResponseWriter, r *http.Request, keyID gen.KeyId) {
	g.a.run("RevokeKey", w, r, func(r *http.Request) { g.ServerInterface.RevokeKey(w, r, keyID) })
}

func (g guarded) CreateAsset(w http.ResponseWriter, r *http.Request) {
	g.a.run("CreateAsset", w, r, func(r *http.Request) { g.ServerInterface.CreateAsset(w, r) })
}

func (g guarded) CreatePlaybackSession(w http.ResponseWriter, r *http.Request) {
	g.a.run("CreatePlaybackSession", w, r, func(r *http.Request) { g.ServerInterface.CreatePlaybackSession(w, r) })
}

func (g guarded) GetPlaybackSession(w http.ResponseWriter, r *http.Request, sessionID gen.SessionIdPath) {
	g.a.run("GetPlaybackSession", w, r, func(r *http.Request) { g.ServerInterface.GetPlaybackSession(w, r, sessionID) })
}

func (g guarded) RevokePlaybackSession(w http.ResponseWriter, r *http.Request, sessionID gen.SessionIdPath) {
	g.a.run("RevokePlaybackSession", w, r, func(r *http.Request) { g.ServerInterface.RevokePlaybackSession(w, r, sessionID) })
}

func (g guarded) RevokePlaybackSessions(w http.ResponseWriter, r *http.Request) {
	g.a.run("RevokePlaybackSessions", w, r, func(r *http.Request) { g.ServerInterface.RevokePlaybackSessions(w, r) })
}

func (g guarded) GetPlaybackSettings(w http.ResponseWriter, r *http.Request) {
	g.a.run("GetPlaybackSettings", w, r, func(r *http.Request) { g.ServerInterface.GetPlaybackSettings(w, r) })
}

func (g guarded) UpdatePlaybackSettings(w http.ResponseWriter, r *http.Request) {
	g.a.run("UpdatePlaybackSettings", w, r, func(r *http.Request) { g.ServerInterface.UpdatePlaybackSettings(w, r) })
}

func (g guarded) GetPlaybackAuth(w http.ResponseWriter, r *http.Request) {
	g.a.run("GetPlaybackAuth", w, r, func(r *http.Request) { g.ServerInterface.GetPlaybackAuth(w, r) })
}

func (g guarded) UpdatePlaybackAuth(w http.ResponseWriter, r *http.Request) {
	g.a.run("UpdatePlaybackAuth", w, r, func(r *http.Request) { g.ServerInterface.UpdatePlaybackAuth(w, r) })
}

func (g guarded) PutPlaybackJwtKey(w http.ResponseWriter, r *http.Request, kid gen.KidPath) {
	g.a.run("PutPlaybackJwtKey", w, r, func(r *http.Request) { g.ServerInterface.PutPlaybackJwtKey(w, r, kid) })
}

func (g guarded) DeletePlaybackJwtKey(w http.ResponseWriter, r *http.Request, kid gen.KidPath) {
	g.a.run("DeletePlaybackJwtKey", w, r, func(r *http.Request) { g.ServerInterface.DeletePlaybackJwtKey(w, r, kid) })
}

func (g guarded) RotatePlaybackCallbackSecret(w http.ResponseWriter, r *http.Request) {
	g.a.run("RotatePlaybackCallbackSecret", w, r, func(r *http.Request) { g.ServerInterface.RotatePlaybackCallbackSecret(w, r) })
}

func (g guarded) ListAssets(w http.ResponseWriter, r *http.Request, params gen.ListAssetsParams) {
	g.a.run("ListAssets", w, r, func(r *http.Request) { g.ServerInterface.ListAssets(w, r, params) })
}

func (g guarded) GetAsset(w http.ResponseWriter, r *http.Request, assetID gen.AssetId) {
	g.a.run("GetAsset", w, r, func(r *http.Request) { g.ServerInterface.GetAsset(w, r, assetID) })
}

func (g guarded) CommitAsset(w http.ResponseWriter, r *http.Request, assetID gen.AssetId) {
	g.a.run("CommitAsset", w, r, func(r *http.Request) { g.ServerInterface.CommitAsset(w, r, assetID) })
}

func (g guarded) AbortAsset(w http.ResponseWriter, r *http.Request, assetID gen.AssetId) {
	g.a.run("AbortAsset", w, r, func(r *http.Request) { g.ServerInterface.AbortAsset(w, r, assetID) })
}

func (g guarded) GetAssetAccessLog(w http.ResponseWriter, r *http.Request, assetID gen.AssetId, params gen.GetAssetAccessLogParams) {
	g.a.run("GetAssetAccessLog", w, r, func(r *http.Request) { g.ServerInterface.GetAssetAccessLog(w, r, assetID, params) })
}

func (g guarded) GetPlaybackSessionAccessLog(w http.ResponseWriter, r *http.Request, sessionID gen.SessionIdPath, params gen.GetPlaybackSessionAccessLogParams) {
	g.a.run("GetPlaybackSessionAccessLog", w, r, func(r *http.Request) {
		g.ServerInterface.GetPlaybackSessionAccessLog(w, r, sessionID, params)
	})
}

func (g guarded) ListPlaybackEvents(w http.ResponseWriter, r *http.Request, params gen.ListPlaybackEventsParams) {
	g.a.run("ListPlaybackEvents", w, r, func(r *http.Request) { g.ServerInterface.ListPlaybackEvents(w, r, params) })
}

func (g guarded) GetPrivacySettings(w http.ResponseWriter, r *http.Request) {
	g.a.run("GetPrivacySettings", w, r, func(r *http.Request) { g.ServerInterface.GetPrivacySettings(w, r) })
}

func (g guarded) UpdatePrivacySettings(w http.ResponseWriter, r *http.Request) {
	g.a.run("UpdatePrivacySettings", w, r, func(r *http.Request) { g.ServerInterface.UpdatePrivacySettings(w, r) })
}

func (g guarded) ListSigningKeys(w http.ResponseWriter, r *http.Request) {
	g.a.run("ListSigningKeys", w, r, func(r *http.Request) { g.ServerInterface.ListSigningKeys(w, r) })
}

func (g guarded) RotateSigningKey(w http.ResponseWriter, r *http.Request) {
	g.a.run("RotateSigningKey", w, r, func(r *http.Request) { g.ServerInterface.RotateSigningKey(w, r) })
}

func (g guarded) RetireSigningKey(w http.ResponseWriter, r *http.Request, keyID gen.SigningKeyIdPath) {
	g.a.run("RetireSigningKey", w, r, func(r *http.Request) { g.ServerInterface.RetireSigningKey(w, r, keyID) })
}

func (g guarded) GetAssetManifest(w http.ResponseWriter, r *http.Request, assetID gen.AssetId) {
	g.a.run("GetAssetManifest", w, r, func(r *http.Request) { g.ServerInterface.GetAssetManifest(w, r, assetID) })
}

func (g guarded) GetAssetManifestTimestamp(w http.ResponseWriter, r *http.Request, assetID gen.AssetId) {
	g.a.run("GetAssetManifestTimestamp", w, r, func(r *http.Request) { g.ServerInterface.GetAssetManifestTimestamp(w, r, assetID) })
}

func (g guarded) GetAssetProof(w http.ResponseWriter, r *http.Request, assetID gen.AssetId, params gen.GetAssetProofParams) {
	g.a.run("GetAssetProof", w, r, func(r *http.Request) { g.ServerInterface.GetAssetProof(w, r, assetID, params) })
}

func (g guarded) VerifyArtifact(w http.ResponseWriter, r *http.Request) {
	g.a.run("VerifyArtifact", w, r, func(r *http.Request) { g.ServerInterface.VerifyArtifact(w, r) })
}
