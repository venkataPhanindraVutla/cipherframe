package telemetry

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

func TestJobsCollectorCachesAndKeepsDrainedStates(t *testing.T) {
	now := time.Unix(1000, 0)
	calls := 0
	counts := map[jobKey]int64{{"asset.process", "available"}: 3, {"asset.process", "running"}: 1}
	var fail bool
	c := newJobsCollector(func(context.Context) (map[jobKey]int64, error) {
		calls++
		if fail {
			return nil, errors.New("db down")
		}
		return counts, nil
	}, func() time.Time { return now })
	reg := prometheus.NewRegistry()
	reg.MustRegister(c)

	value := func(kind, state string) float64 {
		t.Helper()
		fams, err := reg.Gather()
		if err != nil {
			t.Fatal(err)
		}
		for _, f := range fams {
			for _, m := range f.GetMetric() {
				l := m.GetLabel()
				if l[0].GetValue() == kind && l[1].GetValue() == state {
					return m.GetGauge().GetValue()
				}
			}
		}
		return -1
	}

	if v := value("asset.process", "available"); v != 3 {
		t.Fatalf("available = %v", v)
	}
	if v := value("asset.process", "retryable"); v != 0 {
		t.Fatalf("a state with no jobs must report 0, got %v", v)
	}
	value("asset.process", "available")
	if calls != 1 {
		t.Fatalf("queries = %d; scrapes inside the TTL must reuse the count", calls)
	}

	now = now.Add(jobCountTTL)
	counts = map[jobKey]int64{} // the queue drained
	if v := value("asset.process", "available"); v != 0 || calls != 2 {
		t.Fatalf("after TTL: available = %v, queries = %d", v, calls)
	}

	now = now.Add(jobCountTTL)
	fail = true
	if v := value("asset.process", "available"); v != 0 {
		t.Fatalf("a failed query must keep the last counts, got %v", v)
	}
}
