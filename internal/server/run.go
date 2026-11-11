package server

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/venkataPhanindraVutla/cipherframe/internal/api"
	"github.com/venkataPhanindraVutla/cipherframe/internal/auth"
	"github.com/venkataPhanindraVutla/cipherframe/internal/config"
	"github.com/venkataPhanindraVutla/cipherframe/internal/contentkey"
	"github.com/venkataPhanindraVutla/cipherframe/internal/db"
	"github.com/venkataPhanindraVutla/cipherframe/internal/edge"
	"github.com/venkataPhanindraVutla/cipherframe/internal/health"
	"github.com/venkataPhanindraVutla/cipherframe/internal/httpx"
	"github.com/venkataPhanindraVutla/cipherframe/internal/jobs"
	kmsregistry "github.com/venkataPhanindraVutla/cipherframe/internal/kms/registry"
	"github.com/venkataPhanindraVutla/cipherframe/internal/storage"
	"github.com/venkataPhanindraVutla/cipherframe/internal/worker"
)

// Timeouts.
const (
	// ShutdownGrace is how long in-flight requests get after SIGINT/SIGTERM. It is shorter than
	// Kubernetes' default 30 s termination grace period.
	ShutdownGrace = 25 * time.Second
	// ReadinessCheckTimeout bounds each readiness check.
	ReadinessCheckTimeout = 2 * time.Second
	// startupTimeout bounds connecting to the database and reading its version.
	startupTimeout = 30 * time.Second
)

// Options are the parsed command-line options of the serve command.
type Options struct {
	Roles []Role
	// Migrate applies pending database migrations before serving. Default off: schema changes are
	// an explicit operator action (`cipherframe-server migrate`) unless asked for.
	Migrate bool
}

// Migrate connects to the database, checks the server version, applies every pending migration and
// returns. It backs the `migrate` subcommand.
func Migrate(ctx context.Context, cfg *config.Config, log *slog.Logger) error {
	pool, err := openDatabase(ctx, cfg, log)
	if err != nil {
		return err
	}
	defer pool.Close()
	return migrate(ctx, pool, log)
}

// Run serves the requested roles until ctx is cancelled (the caller cancels it on SIGINT or
// SIGTERM), then shuts down gracefully. extra are additional readiness checkers: the job-queue
// task passes its queue checker here (see package health).
func Run(ctx context.Context, cfg *config.Config, log *slog.Logger, opts Options, extra ...health.Checker) error {
	if len(opts.Roles) == 0 {
		return errors.New("server: no roles")
	}
	// Build the key providers before touching anything else: a misconfigured or unavailable
	// provider stops the process here with a message that names the setting, never a value.
	kmsReg, err := kmsregistry.FromConfig(cfg, log)
	if err != nil {
		return err
	}
	pool, err := openDatabase(ctx, cfg, log)
	if err != nil {
		return err
	}
	defer pool.Close()
	if opts.Migrate {
		if err := migrate(ctx, pool, log); err != nil {
			return err
		}
	}

	// Refuse to serve when an active key was hashed with a pepper that is no longer configured
	// (ADR 0016); the error names version numbers only.
	repos := db.New(pool)
	if err := auth.CheckPeppers(ctx, repos, cfg.Peppers, time.Now()); err != nil {
		return fmt.Errorf("peppers: %w", err)
	}

	// Likewise refuse to serve when a stored content key needs a provider or a local KEK version
	// that is not configured (ADR 0020); the error names providers and versions only.
	if err := contentkey.CheckKEKs(ctx, repos, kmsReg); err != nil {
		return fmt.Errorf("content keys: %w", err)
	}

	contentKeys := contentkey.NewManager(pool, kmsReg, log)

	buckets, err := storage.New(ctx, cfg.S3)
	if err != nil {
		return fmt.Errorf("storage: %w", err)
	}
	checkers := append([]health.Checker{
		health.Database(pool),
		health.Storage("storage_source", buckets.Source),
		health.Storage("storage_delivery", buckets.Delivery),
		health.Queue(func(ctx context.Context) error { return jobs.CheckReady(ctx, pool) }),
	}, extra...)
	ready := health.NewRunner(log, ReadinessCheckTimeout, checkers...)

	var services []service
	cleanup := func() {
		for _, s := range services {
			s.close()
		}
	}
	if Has(opts.Roles, RoleAPI) {
		handler := api.New(api.Deps{
			Log:      log,
			Ready:    ready,
			Verifier: auth.NewVerifier(repos, cfg.Peppers, log, nil),
			Manager:  auth.NewManager(pool, cfg.Peppers, nil),

			ContentKeys: contentKeys,
		}).Handler()
		s, err := newHTTPService("api", cfg.APIListen, handler, log)
		if err != nil {
			cleanup()
			return err
		}
		services = append(services, s)
	}
	if Has(opts.Roles, RoleEdge) {
		s, err := newHTTPService("edge", cfg.EdgeListen, edge.New(edge.Deps{Log: log, Ready: ready, ContentKeys: contentKeys}).Handler(), log)
		if err != nil {
			cleanup()
			return err
		}
		services = append(services, s)
	}
	if Has(opts.Roles, RoleWorker) {
		w, err := newWorker(pool, contentKeys, log)
		if err != nil {
			cleanup()
			return err
		}
		services = append(services, workerService{w: w})
	}

	log.InfoContext(ctx, "serving", slog.Any("roles", opts.Roles))
	err = runServices(ctx, services)
	log.InfoContext(ctx, "stopped")
	return err
}

// workerConcurrency is how many jobs one worker process runs at once.
const workerConcurrency = 10

// newWorker builds the job registry and, when it has kinds, a working queue. Milestones register
// their job kinds here (for example transcoding in M3). The first real kind is kms.rewrap (M2-4).
func newWorker(pool *pgxpool.Pool, contentKeys *contentkey.Manager, log *slog.Logger) (*worker.Worker, error) {
	reg := jobs.NewRegistry()
	// A handler that chains the next run needs a queue to insert with. This one has no workers and
	// shares the registry, so it only inserts.
	inserter, err := jobs.NewQueue(pool, reg, jobs.Config{Logger: log})
	if err != nil {
		return nil, fmt.Errorf("worker: %w", err)
	}
	if err := contentkey.RegisterRewrapJob(reg, contentKeys, inserter, jobs.KindConfig{}); err != nil {
		return nil, fmt.Errorf("worker: %w", err)
	}
	kinds := reg.Kinds()
	if len(kinds) == 0 {
		return worker.New(log, nil, nil), nil
	}
	q, err := jobs.NewQueue(pool, reg, jobs.Config{Workers: workerConcurrency, Logger: log})
	if err != nil {
		return nil, fmt.Errorf("worker: %w", err)
	}
	return worker.New(log, q, kinds), nil
}

func openDatabase(ctx context.Context, cfg *config.Config, log *slog.Logger) (*pgxpool.Pool, error) {
	octx, cancel := context.WithTimeout(ctx, startupTimeout)
	defer cancel()
	pool, err := db.Open(octx, cfg)
	if err != nil {
		return nil, fmt.Errorf("database: %w", err)
	}
	if err := db.CheckServerVersion(octx, pool); err != nil {
		pool.Close()
		return nil, err
	}
	log.InfoContext(ctx, "database connected")
	return pool, nil
}

func migrate(ctx context.Context, pool *pgxpool.Pool, log *slog.Logger) error {
	log.InfoContext(ctx, "applying database migrations")
	if err := db.Migrate(ctx, pool); err != nil {
		return err
	}
	log.InfoContext(ctx, "database migrations applied")
	return nil
}

// service is one long-running part of the process.
type service interface {
	// run blocks until ctx is cancelled and the service has shut down, or it fails.
	run(ctx context.Context) error
	// close releases resources of a service that was built but never run.
	close()
}

// runServices runs every service until ctx is cancelled or one fails. A failure cancels the
// others. It returns the joined errors, and waits for every service to stop.
func runServices(ctx context.Context, services []service) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	var (
		wg   sync.WaitGroup
		mu   sync.Mutex
		errs []error
	)
	for _, s := range services {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := s.run(ctx); err != nil {
				mu.Lock()
				errs = append(errs, err)
				mu.Unlock()
				cancel()
			}
		}()
	}
	wg.Wait()
	return errors.Join(errs...)
}

// httpService is an HTTP listener with a bound socket, so address errors surface at startup.
type httpService struct {
	name string
	srv  *http.Server
	ln   net.Listener
	log  *slog.Logger
}

func newHTTPService(name, addr string, h http.Handler, log *slog.Logger) (*httpService, error) {
	var lc net.ListenConfig
	ln, err := lc.Listen(context.Background(), "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("%s listener: %w", name, err)
	}
	log.Info("listening", slog.String("listener", name), slog.String("addr", ln.Addr().String()))
	return &httpService{name: name, srv: httpx.NewServer(addr, h, log), ln: ln, log: log}, nil
}

func (s *httpService) run(ctx context.Context) error {
	if err := httpx.Serve(ctx, s.srv, s.ln, ShutdownGrace); err != nil {
		return fmt.Errorf("%s listener: %w", s.name, err)
	}
	s.log.InfoContext(ctx, "listener stopped", slog.String("listener", s.name))
	return nil
}

func (s *httpService) close() { _ = s.ln.Close() }

type workerService struct{ w *worker.Worker }

func (s workerService) run(ctx context.Context) error { return s.w.Run(ctx) }
func (workerService) close()                          {}
