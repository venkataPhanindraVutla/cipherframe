//go:build integration

package server

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/venkataPhanindraVutla/cipherframe/internal/config"
	"github.com/venkataPhanindraVutla/cipherframe/internal/contentkey"
	"github.com/venkataPhanindraVutla/cipherframe/internal/db/dbtest"
	"github.com/venkataPhanindraVutla/cipherframe/internal/signing"
	"github.com/venkataPhanindraVutla/cipherframe/internal/storage"
)

// stubSigner satisfies signing.Signer; the test never signs.
type stubSigner struct{}

func (stubSigner) Sign(context.Context, []byte) (string, []byte, error) {
	return "", nil, errors.New("stub signer does not sign")
}

func (stubSigner) PublicKeys(context.Context) ([]signing.PublicKey, error) { return nil, nil }

// The worker role registers asset.process next to kms.rewrap and creates its private work
// directory; a worker built without the processing settings (as in the tests that only exercise
// kms.rewrap) does not register it.
func TestNewWorkerRegistersAssetProcess(t *testing.T) {
	pool := dbtest.NewMigrated(t)
	buckets, err := storage.New(context.Background(), config.S3{
		Endpoint: "http://127.0.0.1:1", Region: "us-east-1", ForcePathStyle: true,
		SourceBucket: "src-bucket", DeliveryBucket: "dst-bucket",
		AccessKeyID: config.NewStaticCredential("AK"), SecretAccessKey: config.NewStaticCredential("SK"),
	})
	if err != nil {
		t.Fatal(err)
	}
	work := filepath.Join(t.TempDir(), "work")
	cfg := &config.Config{Media: config.Media{
		FFmpegPath: "ffmpeg", FFprobePath: "ffprobe", MaxSourceDuration: time.Hour, MaxSourceWidth: 3840, MaxSourceHeight: 2160,
		TranscodeTimeout: time.Hour, WorkDir: work, Concurrency: 1,
	}}
	w, err := newWorker(pool, managerFor(t, pool, localAt(t, 1)), slog.New(slog.DiscardHandler), &processing{Buckets: buckets, Config: cfg, Signer: stubSigner{}})
	if err != nil {
		t.Fatal(err)
	}
	if got := w.Kinds(); len(got) != 2 || got[0] != "asset.process" || got[1] != contentkey.RewrapKind {
		t.Fatalf("worker kinds = %v, want [asset.process %s]", got, contentkey.RewrapKind)
	}
	if st, err := os.Stat(work); err != nil || !st.IsDir() || st.Mode().Perm() != 0o700 {
		t.Fatalf("work directory: %v, %v", st, err)
	}
}
