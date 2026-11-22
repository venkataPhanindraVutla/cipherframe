package server

import (
	"encoding/json"
	"net/http"

	"github.com/venkataPhanindraVutla/cipherframe/internal/health"
)

// workerHandler is the handler of the listener a worker-only process opens (CIPHERFRAME_WORKER_LISTEN):
// liveness and readiness in the shape the api and edge listeners answer with. /metrics is added
// around it by telemetry.Mount.
func workerHandler(ready *health.Runner) http.Handler {
	type check struct {
		Name   string `json:"name"`
		Status string `json:"status"`
	}
	type body struct {
		Status string  `json:"status"`
		Checks []check `json:"checks,omitempty"`
	}
	write := func(w http.ResponseWriter, code int, b body) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		_ = json.NewEncoder(w).Encode(b)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { write(w, http.StatusOK, body{Status: "ok"}) })
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		rep := health.Report{OK: true}
		if ready != nil {
			rep = ready.Run(r.Context())
		}
		b := body{Status: "ok", Checks: make([]check, 0, len(rep.Results))}
		for _, res := range rep.Results {
			st := "ok"
			if !res.OK {
				st = "unavailable"
			}
			b.Checks = append(b.Checks, check{Name: res.Name, Status: st})
		}
		if !rep.OK {
			b.Status = "unavailable"
			write(w, http.StatusServiceUnavailable, b)
			return
		}
		write(w, http.StatusOK, b)
	})
	return mux
}
