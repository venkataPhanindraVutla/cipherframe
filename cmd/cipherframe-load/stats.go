package main

import (
	"encoding/csv"
	"fmt"
	"io"
	"math"
	"os"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

// The request kinds, in report order. A kind is what the request was for, never a URL.
var kinds = []string{"session_create", "master", "media", "key", "init", "segment", "heartbeat", "end", "upload", "transcode"}

// percentile is the nearest-rank percentile (p in 0..100) of an ascending slice; 0 for none.
func percentile(sorted []float64, p float64) float64 {
	if len(sorted) == 0 {
		return 0
	}
	rank := max(int(math.Ceil(p/100*float64(len(sorted)))), 1)
	return sorted[rank-1]
}

// rampTargets is the viewer count of each step: start, start+inc, ... up to and including maxViewers.
func rampTargets(start, inc, maxViewers int) []int {
	var out []int
	for n := start; n <= maxViewers && inc > 0; n += inc {
		out = append(out, n)
	}
	return out
}

type kindStats struct {
	errs int
	ms   []float64
}

// row is one summary line: a step and a kind ("all" for the step total).
type row struct {
	Step, Viewers, Requests, Errors int
	Kind                            string
	ReqPerSec, P50, P95, P99        float64
}

func (r row) errRate() float64 {
	if r.Requests == 0 {
		return 0
	}
	return float64(r.Errors) / float64(r.Requests)
}

// summarize turns one step's per-kind samples, measured over secs seconds, into rows (one per kind
// seen, then the total).
func summarize(step, viewers int, secs float64, per map[string]*kindStats) []row {
	var rows []row
	var all kindStats
	line := func(kind string, ks *kindStats) row {
		s := append([]float64(nil), ks.ms...)
		sort.Float64s(s)
		return row{
			step, viewers, len(s), ks.errs, kind, float64(len(s)) / secs,
			percentile(s, 50), percentile(s, 95), percentile(s, 99),
		}
	}
	for _, k := range kinds {
		ks := per[k]
		if ks == nil {
			continue
		}
		rows = append(rows, line(k, ks))
		all.errs += ks.errs
		all.ms = append(all.ms, ks.ms...)
	}
	return append(rows, line("all", &all))
}

// breach says why a step fails the thresholds, or "" when it passes.
func breach(rows []row, p99Limit time.Duration, maxErrRate float64) string {
	for _, r := range rows {
		switch {
		case r.Kind == "all" && r.errRate() > maxErrRate:
			return fmt.Sprintf("error rate %.2f%% over %.2f%%", 100*r.errRate(), 100*maxErrRate)
		case r.Kind == "segment" && r.P99 > float64(p99Limit.Milliseconds()):
			return fmt.Sprintf("segment p99 %.0f ms over %d ms", r.P99, p99Limit.Milliseconds())
		}
	}
	return ""
}

// collector records every request: a (sampled) raw CSV row, and, while counting, the window's samples.
type collector struct {
	mu       sync.Mutex
	raw      *csv.Writer
	sampleN  int64
	seen     int64
	counting atomic.Bool
	per      map[string]*kindStats
}

func newCollector(rawPath string, sampleN int) (*collector, io.Closer, error) {
	c := &collector{sampleN: int64(max(sampleN, 1)), per: map[string]*kindStats{}}
	if rawPath == "" {
		return c, closerFunc(func() error { return nil }), nil
	}
	f, err := os.Create(rawPath) //nolint:gosec // the operator names the output file
	if err != nil {
		return nil, nil, err
	}
	c.raw = csv.NewWriter(f)
	_ = c.raw.Write([]string{"timestamp", "viewer", "kind", "status", "latency_ms"})
	return c, closerFunc(func() error { c.raw.Flush(); return f.Close() }), nil
}

type closerFunc func() error

func (f closerFunc) Close() error { return f() }

// record notes one finished request. status 0 is a transport error. Failures are always written
// to the raw file; successes one in sampleN.
func (c *collector) record(viewer int, kind string, status int, d time.Duration) {
	ms := float64(d.Microseconds()) / 1000
	ok := status >= 200 && status < 300
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.raw != nil {
		c.seen++
		if !ok || c.seen%c.sampleN == 0 {
			_ = c.raw.Write([]string{
				time.Now().UTC().Format("2006-01-02T15:04:05.000Z"), strconv.Itoa(viewer), kind,
				strconv.Itoa(status), strconv.FormatFloat(ms, 'f', 1, 64),
			})
		}
	}
	if c.counting.Load() {
		ks := c.per[kind]
		if ks == nil {
			ks = &kindStats{}
			c.per[kind] = ks
		}
		ks.ms = append(ks.ms, ms)
		if !ok {
			ks.errs++
		}
	}
}

// take returns the samples of the window just ended and starts a fresh one.
func (c *collector) take() map[string]*kindStats {
	c.mu.Lock()
	defer c.mu.Unlock()
	p := c.per
	c.per = map[string]*kindStats{}
	return p
}

func writeSummary(path string, rows []row) error {
	f, err := os.Create(path) //nolint:gosec // the operator names the output file
	if err != nil {
		return err
	}
	w := csv.NewWriter(f)
	_ = w.Write([]string{"step", "viewers", "kind", "requests", "errors", "req_per_s", "p50_ms", "p95_ms", "p99_ms"})
	for _, r := range rows {
		_ = w.Write([]string{
			strconv.Itoa(r.Step), strconv.Itoa(r.Viewers), r.Kind, strconv.Itoa(r.Requests), strconv.Itoa(r.Errors),
			fmt.Sprintf("%.2f", r.ReqPerSec), fmt.Sprintf("%.1f", r.P50), fmt.Sprintf("%.1f", r.P95), fmt.Sprintf("%.1f", r.P99),
		})
	}
	w.Flush()
	if err := w.Error(); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}
