package telemetry

import (
	"context"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/prometheus/client_golang/prometheus"
)

// jobStates are the River job states the queue gauge reports.
var jobStates = []string{"available", "scheduled", "retryable", "running"}

const (
	// jobCountTTL is how long counted queue depths are reused, so scrapes cannot hammer the
	// database.
	jobCountTTL     = 5 * time.Second
	jobCountTimeout = 2 * time.Second
)

type jobKey struct{ kind, state string }

// jobsCollector reports cipherframe_jobs{kind,state} from the River job table at scrape time.
type jobsCollector struct {
	desc  *prometheus.Desc
	count func(context.Context) (map[jobKey]int64, error)
	now   func() time.Time

	mu     sync.Mutex
	at     time.Time
	cached map[jobKey]int64
	kinds  map[string]bool // every kind seen, so a drained state reports 0 instead of vanishing
}

func newJobsCollector(count func(context.Context) (map[jobKey]int64, error), now func() time.Time) *jobsCollector {
	return &jobsCollector{
		desc:  prometheus.NewDesc("cipherframe_jobs", "Jobs in the queue by kind and state.", []string{"kind", "state"}, nil),
		count: count, now: now, kinds: map[string]bool{},
	}
}

func (c *jobsCollector) Describe(ch chan<- *prometheus.Desc) { ch <- c.desc }

func (c *jobsCollector) Collect(ch chan<- prometheus.Metric) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if now := c.now(); c.cached == nil || now.Sub(c.at) >= jobCountTTL {
		ctx, cancel := context.WithTimeout(context.Background(), jobCountTimeout)
		counts, err := c.count(ctx)
		cancel()
		if err == nil {
			c.cached, c.at = counts, now
			for k := range counts {
				c.kinds[k.kind] = true
			}
		} else if c.cached == nil {
			return // nothing to report yet; a database failure is not zero jobs
		}
	}
	for kind := range c.kinds {
		for _, state := range jobStates {
			ch <- prometheus.MustNewConstMetric(c.desc, prometheus.GaugeValue, float64(c.cached[jobKey{kind, state}]), kind, state)
		}
	}
}

// RegisterJobs adds the queue-depth gauge, read from the database behind pool. Call it only in a
// process that has a pool.
func (t *Telemetry) RegisterJobs(pool *pgxpool.Pool) error {
	return t.Registry.Register(newJobsCollector(func(ctx context.Context) (map[jobKey]int64, error) {
		rows, err := pool.Query(ctx, `SELECT kind, state::text, count(*) FROM river_job
			WHERE state IN ('available', 'scheduled', 'retryable', 'running') GROUP BY kind, state`)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		out := map[jobKey]int64{}
		for rows.Next() {
			var k jobKey
			var n int64
			if err := rows.Scan(&k.kind, &k.state, &n); err != nil {
				return nil, err
			}
			out[k] = n
		}
		return out, rows.Err()
	}, time.Now))
}
