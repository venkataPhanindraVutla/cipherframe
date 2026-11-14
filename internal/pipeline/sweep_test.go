package pipeline

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestSweepStaleJobDirs(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()
	mk := func(name string, age time.Duration) string {
		p := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Join(p, "seg"), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(p, "seg", "s.m4s"), []byte("plaintext"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(p, now.Add(-age), now.Add(-age)); err != nil {
			t.Fatal(err)
		}
		return p
	}
	stale := mk("job-old", 10*time.Hour)
	staleMask := mk("job-mask-old", 10*time.Hour) // a masking job directory holds plaintext too
	live := mk("job-new", time.Minute)
	other := mk("keep-me", 10*time.Hour)

	n, err := sweepStaleJobDirs(dir, 7*time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Fatalf("removed %d, want 2", n)
	}
	for _, p := range []string{stale, staleMask} {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Fatalf("stale directory %s was not removed", filepath.Base(p))
		}
	}
	for _, p := range []string{live, other} {
		if _, err := os.Stat(p); err != nil {
			t.Fatalf("%s must be kept: %v", filepath.Base(p), err)
		}
	}
}
