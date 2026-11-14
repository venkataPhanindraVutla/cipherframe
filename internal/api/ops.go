package api

import (
	"context"

	"github.com/venkataPhanindraVutla/cipherframe/internal/api/gen"
	"github.com/venkataPhanindraVutla/cipherframe/internal/auth"
	"github.com/venkataPhanindraVutla/cipherframe/internal/db"
	"github.com/venkataPhanindraVutla/cipherframe/internal/health"
	"github.com/venkataPhanindraVutla/cipherframe/internal/playback"
	"github.com/venkataPhanindraVutla/cipherframe/internal/reqid"
	"github.com/venkataPhanindraVutla/cipherframe/internal/signing"
	"github.com/venkataPhanindraVutla/cipherframe/internal/uploads"
)

// server implements gen.StrictServerInterface.
type server struct {
	ready  *health.Runner
	mgr    *auth.Manager
	assets *uploads.Service
	// playback creates playback sessions and serves the playback settings (M4-1).
	playback *playback.Service
	// signing manages the integrity signing keys (M5-2); keyset serves the public set.
	signing *signing.Manager
	keyset  *signing.KeySet
	// repos reads manifests and artifacts for the integrity endpoints (M5-3).
	repos *db.Repos
}

var _ gen.StrictServerInterface = (*server)(nil)

// GetHealthz reports liveness. It checks no dependency.
func (s *server) GetHealthz(ctx context.Context, _ gen.GetHealthzRequestObject) (gen.GetHealthzResponseObject, error) {
	id, _ := reqid.FromContext(ctx)
	return gen.GetHealthz200JSONResponse{
		Body:    gen.HealthResponse{Status: gen.HealthResponseStatusOk},
		Headers: gen.GetHealthz200ResponseHeaders{XRequestId: id},
	}, nil
}

// GetReadyz runs the readiness checks and reports names and pass/fail only.
func (s *server) GetReadyz(ctx context.Context, _ gen.GetReadyzRequestObject) (gen.GetReadyzResponseObject, error) {
	id, _ := reqid.FromContext(ctx)
	rep := health.Report{OK: true}
	if s.ready != nil {
		rep = s.ready.Run(ctx)
	}
	body := gen.ReadyResponse{Status: gen.ReadyResponseStatusOk, Checks: make([]gen.ReadyCheck, 0, len(rep.Results))}
	for _, r := range rep.Results {
		st := gen.ReadyCheckStatusOk
		if !r.OK {
			st = gen.ReadyCheckStatusUnavailable
		}
		body.Checks = append(body.Checks, gen.ReadyCheck{Name: r.Name, Status: st})
	}
	if rep.OK {
		return gen.GetReadyz200JSONResponse{Body: body, Headers: gen.GetReadyz200ResponseHeaders{XRequestId: id}}, nil
	}
	body.Status = gen.ReadyResponseStatusUnavailable
	return gen.GetReadyz503JSONResponse{Body: body, Headers: gen.GetReadyz503ResponseHeaders{XRequestId: id}}, nil
}
