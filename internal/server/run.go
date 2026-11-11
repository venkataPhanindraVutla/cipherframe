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

	"github.com/venkataPhanindraVutla/cipherframe/internal/accesslog"
	"github.com/venkataPhanindraVutla/cipherframe/internal/anomaly"
	"github.com/venkataPhanindraVutla/cipherframe/internal/api"
	"github.com/venkataPhanindraVutla/cipherframe/internal/auth"
	"github.com/venkataPhanindraVutla/cipherframe/internal/config"
	"github.com/venkataPhanindraVutla/cipherframe/internal/contentkey"
	"github.com/venkataPhanindraVutla/cipherframe/internal/db"
	"github.com/venkataPhanindraVutla/cipherframe/internal/edge"
	"github.com/venkataPhanindraVutla/cipherframe/internal/health"
	"github.com/venkataPhanindraVutla/cipherframe/internal/httpx"
	"github.com/venkataPhanindraVutla/cipherframe/internal/jobs"
	"github.com/venkataPhanindraVutla/cipherframe/internal/kms"
	kmsregistry "github.com/venkataPhanindraVutla/cipherframe/internal/kms/registry"
	"github.com/venkataPhanindraVutla/cipherframe/internal/outbound"
	"github.com/venkataPhanindraVutla/cipherframe/internal/pipeline"
	"github.com/venkataPhanindraVutla/cipherframe/internal/playback"
	"github.com/venkataPhanindraVutla/cipherframe/internal/playback/token"
	"github.com/venkataPhanindraVutla/cipherframe/internal/storage"
	"github.com/venkataPhanindraVutla/cipherframe/internal/uploads"
	"github.com/venkataPhanindraVutla/cipherframe/internal/viewerauth"
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
	// accessLogFlushTimeout bounds the final write of the access trail at shutdown.
	accessLogFlushTimeout = 5 * time.Second
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
	// The api role signs playback tokens and the edge role verifies them (ADR 0028); neither can
	// run without the keys.
	if Has(opts.Roles, RoleAPI) || Has(opts.Roles, RoleEdge) {
		if err := cfg.Playback.Require(); err != nil {
			return err
		}
	}
	// Only the worker role runs FFmpeg. Check it first, before any connection is opened, so a
	// worker with a missing or limited FFmpeg stops with a message that says what is missing.
	if Has(opts.Roles, RoleWorker) {
		if err := checkMediaTools(ctx, cfg, log); err != nil {
			return err
		}
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

	// The access trail (invariant I10): a best-effort queue and writer shared by the playback
	// service and the edge routes. It is flushed after every listener has stopped, so the events of
	// the last requests are not lost on a graceful shutdown.
	var access *accesslog.Recorder
	if Has(opts.Roles, RoleAPI) || Has(opts.Roles, RoleEdge) {
		access = accesslog.New(accesslog.Options{Store: repos, Log: log})
		defer func() {
			fctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), accessLogFlushTimeout)
			defer cancel()
			access.Close(fctx)
		}()
	}

	// The anomaly signals (M4-9): raised by the playback service (session limit, rapid session
	// creation), by the edge key route (key replay, key rate) and, as the recorder's segment sink,
	// from the segment counts (segments without a key). The recorder and the detector refer to
	// each other (a revocation writes an access-trail row), hence the setter.
	var anomalies *anomaly.Detector
	if access != nil {
		anomalies = anomaly.NewFromPool(pool, access, log, nil)
		access.SetSegmentSink(anomalies)
	}

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
		assets, err := newAssetService(pool, buckets, cfg, log)
		if err != nil {
			cleanup()
			return err
		}
		playbackSvc, err := newPlaybackService(pool, cfg, kmsReg, access, anomalies)
		if err != nil {
			cleanup()
			return err
		}
		handler := api.New(api.Deps{
			Log:      log,
			Ready:    ready,
			Verifier: auth.NewVerifier(repos, cfg.Peppers, log, nil),
			Manager:  auth.NewManager(pool, cfg.Peppers, nil),

			ContentKeys: contentKeys,
			Assets:      assets,
			Playback:    playbackSvc,
		}).Handler()
		s, err := newHTTPService("api", cfg.APIListen, handler, log)
		if err != nil {
			cleanup()
			return err
		}
		services = append(services, s)
	}
	if Has(opts.Roles, RoleEdge) {
		up, closeUploads, err := newEdgeUploads(ctx, pool, buckets, cfg)
		if err != nil {
			cleanup()
			return err
		}
		defer closeUploads()
		play, err := newEdgePlayback(pool, repos, buckets, contentKeys, kmsReg, access, anomalies, cfg, log)
		if err != nil {
			cleanup()
			return err
		}
		s, err := newHTTPService("edge", cfg.EdgeListen, edge.New(edge.Deps{Log: log, Ready: ready, Uploads: up, Playback: play}).Handler(), log)
		if err != nil {
			cleanup()
			return err
		}
		services = append(services, s, sweepService{repos: repos, log: log})
	}
	if Has(opts.Roles, RoleWorker) {
		w, err := newWorker(pool, contentKeys, log, &processing{Buckets: buckets, Config: cfg})
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

// lockPoolConns caps the connections that hold tus upload locks (one per active upload request).
const lockPoolConns = 16

// newAssetService builds the asset service of the api role. The api role needs the edge's public
// URL to tell clients where to upload; it refuses to start without it.
func newAssetService(pool *pgxpool.Pool, buckets *storage.Buckets, cfg *config.Config, log *slog.Logger) (*uploads.Service, error) {
	if cfg.Uploads.EdgePublicURL == "" {
		return nil, fmt.Errorf("%s is required when the api role runs", config.EnvEdgePublicURL)
	}
	// An insert-only queue: the api role enqueues asset.process, the worker role handles it.
	// The registry has no handlers, so it is told which queue asset.process runs on.
	reg := jobs.NewRegistry()
	if err := pipeline.Declare(reg); err != nil {
		return nil, fmt.Errorf("assets: %w", err)
	}
	queue, err := jobs.NewQueue(pool, reg, jobs.Config{Logger: log})
	if err != nil {
		return nil, fmt.Errorf("assets: %w", err)
	}
	svc, err := uploads.NewService(uploads.Deps{
		Pool: pool, Source: buckets.Source, Queue: queue, Limits: uploads.LimitsFrom(cfg.Uploads),
		EdgeURL: cfg.Uploads.EdgePublicURL, Log: log,
	})
	if err != nil {
		return nil, fmt.Errorf("assets: %w", err)
	}
	return svc, nil
}

// newPlaybackService builds the playback service of the api role: it signs playback tokens with
// the configured keyring (ADR 0028) and tells clients where the edge serves playlists, so it needs
// the edge's public URL (already required by the asset service). It wraps callback secrets with the
// key providers (ADR 0029).
func newPlaybackService(pool *pgxpool.Pool, cfg *config.Config, kmsReg *kms.Registry, access *accesslog.Recorder, anomalies *anomaly.Detector) (*playback.Service, error) {
	keyring, err := token.KeyringFromConfig(cfg.Playback)
	if err != nil {
		return nil, fmt.Errorf("playback: %w", err)
	}
	svc, err := playback.NewService(playback.Deps{Pool: pool, Keyring: keyring, EdgeURL: cfg.Uploads.EdgePublicURL, KMS: kmsReg, Access: access, Anomalies: anomalies})
	if err != nil {
		return nil, fmt.Errorf("playback: %w", err)
	}
	return svc, nil
}

// newEdgePlayback builds the playlist, segment and key routes of the edge role: it verifies
// playback tokens with the configured keyring (ADR 0028), reads sessions and settings from the
// database, streams segments from the delivery bucket and unwraps content keys through the key
// service. The key service is built for every role before this point, so an edge process with a
// missing or broken KMS configuration has already refused to start.
//
// It also builds the browser-session route (ADR 0031): playback sessions started by a viewer's
// browser with a JWT or a signed callback. That route makes outbound HTTPS requests, through the
// SSRF-guarded client of package outbound, to a tenant's JWKS URL or callback URL, and needs the
// edge's public URL to tell the player where its playlists are. Without the URL the route answers
// 503 and the process says so at startup.
func newEdgePlayback(pool *pgxpool.Pool, repos *db.Repos, buckets *storage.Buckets, contentKeys *contentkey.Manager, kmsReg *kms.Registry, access *accesslog.Recorder, anomalies *anomaly.Detector, cfg *config.Config, log *slog.Logger) (*edge.Playback, error) {
	if contentKeys == nil {
		return nil, errors.New("playback: the edge role needs the key service")
	}
	keyring, err := token.KeyringFromConfig(cfg.Playback)
	if err != nil {
		return nil, fmt.Errorf("playback: %w", err)
	}
	viewer, err := newEdgeViewerAuth(pool, repos, keyring, kmsReg, access, anomalies, cfg, log)
	if err != nil {
		return nil, err
	}
	p, err := edge.NewPlayback(edge.PlaybackDeps{
		Keyring: keyring, Store: repos, Delivery: buckets.Delivery, KeyStore: repos, ContentKeys: contentKeys, Viewer: viewer, Access: access, Anomalies: anomalies,
	})
	if err != nil {
		return nil, fmt.Errorf("playback: %w", err)
	}
	return p, nil
}

// jwksFetchTimeout bounds one JWKS fetch.
const jwksFetchTimeout = 3 * time.Second

// newEdgeViewerAuth builds the collaborators of the browser-session route. It returns nil, with a
// warning, when the edge's public URL is not configured.
func newEdgeViewerAuth(pool *pgxpool.Pool, repos *db.Repos, keyring *token.Keyring, kmsReg *kms.Registry, access *accesslog.Recorder, anomalies *anomaly.Detector, cfg *config.Config, log *slog.Logger) (*edge.ViewerDeps, error) {
	if cfg.Uploads.EdgePublicURL == "" {
		log.Warn("browser playback sessions are disabled: " + config.EnvEdgePublicURL + " is not set")
		return nil, nil
	}
	sessions, err := playback.NewService(playback.Deps{Pool: pool, Keyring: keyring, EdgeURL: cfg.Uploads.EdgePublicURL, KMS: kmsReg, Access: access, Anomalies: anomalies})
	if err != nil {
		return nil, fmt.Errorf("playback: %w", err)
	}
	verifier, err := viewerauth.NewVerifier(viewerauth.VerifierOptions{
		Client:         outbound.New(outbound.Options{Timeout: jwksFetchTimeout}),
		ValidateViewer: playback.ValidateViewerID,
	})
	if err != nil {
		return nil, fmt.Errorf("playback: %w", err)
	}
	callback, err := viewerauth.NewAuthorizer(viewerauth.AuthorizerOptions{
		Client:         outbound.New(outbound.Options{Timeout: viewerauth.CallbackTimeout}),
		ValidateViewer: playback.ValidateViewerID,
	})
	if err != nil {
		return nil, fmt.Errorf("playback: %w", err)
	}
	return &edge.ViewerDeps{
		Sessions: sessions, Store: repos, Secrets: viewerauth.NewSecretBox(kmsReg), Verifier: verifier, Callback: callback,
	}, nil
}

// newEdgeUploads builds the upload endpoints of the edge role: the token check, the multipart
// receiver and the tus data store with its cross-replica locker. The returned func releases the
// lock pool.
func newEdgeUploads(ctx context.Context, pool *pgxpool.Pool, buckets *storage.Buckets, cfg *config.Config) (*edge.Uploads, func(), error) {
	s3c, err := storage.NewS3Client(ctx, cfg.S3)
	if err != nil {
		return nil, nil, fmt.Errorf("uploads: %w", err)
	}
	limits := uploads.LimitsFrom(cfg.Uploads)
	tus, err := uploads.NewTusStore(uploads.TusDeps{Pool: pool, S3: s3c, Bucket: cfg.S3.SourceBucket, Limits: limits})
	if err != nil {
		return nil, nil, fmt.Errorf("uploads: %w", err)
	}
	lockPool, err := db.OpenSized(ctx, cfg, lockPoolConns)
	if err != nil {
		return nil, nil, fmt.Errorf("uploads: lock pool: %w", err)
	}
	repos := db.New(pool)
	return &edge.Uploads{
		Authz:     uploads.NewAuthorizer(repos, nil),
		Parts:     uploads.NewReceiver(repos, buckets.Source, limits, nil),
		Tus:       tus,
		Locker:    uploads.NewLocker(lockPool),
		Limits:    limits,
		PublicURL: cfg.Uploads.EdgePublicURL,
	}, lockPool.Close, nil
}

// workerConcurrency is how many jobs one worker process runs at once.
const workerConcurrency = 10 // the default queue; the media queue is sized by Media.Concurrency

// processing is what the asset.process job needs besides the database: the two buckets and the
// configuration (FFmpeg paths, limits, work directory, timeout).
type processing struct {
	Buckets *storage.Buckets
	Config  *config.Config
}

// newWorker builds the job registry and, when it has kinds, a working queue. Milestones register
// their job kinds here: kms.rewrap (M2-4) and asset.process (M3). proc may be nil, which leaves
// asset.process unregistered (tests that exercise only the other kinds).
func newWorker(pool *pgxpool.Pool, contentKeys *contentkey.Manager, log *slog.Logger, proc *processing) (*worker.Worker, error) {
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
	if proc != nil {
		if err := registerProcessing(reg, pool, contentKeys, proc, log); err != nil {
			return nil, fmt.Errorf("worker: %w", err)
		}
	}
	kinds := reg.Kinds()
	if len(kinds) == 0 {
		return worker.New(log, nil, nil), nil
	}
	jc := jobs.Config{Workers: workerConcurrency, Logger: log}
	if proc != nil {
		// asset.process has its own queue so a transcode never takes a slot from kms.rewrap.
		jc.Queues = map[string]int{jobs.QueueMedia: proc.Config.Media.Concurrency}
	}
	q, err := jobs.NewQueue(pool, reg, jc)
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

// sweepService runs the periodic playback housekeeping in the edge role: access-log partitions,
// key-fetch counters, used JWT ids and expired sessions.
type sweepService struct {
	repos *db.Repos
	log   *slog.Logger
}

func (s sweepService) run(ctx context.Context) error {
	playback.RunSweeper(ctx, s.repos, playback.SweepInterval, s.log)
	return nil
}
func (sweepService) close() {}

type workerService struct{ w *worker.Worker }

func (s workerService) run(ctx context.Context) error { return s.w.Run(ctx) }
func (workerService) close()                          {}
