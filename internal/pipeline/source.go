package pipeline

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/venkataPhanindraVutla/cipherframe/internal/storage"
)

// sourceResult is what one pass over the source measured.
type sourceResult struct {
	SHA256 [sha256.Size]byte
	Size   int64
}

// fetchSource streams the source object into dest and hashes it in the same pass: the bytes go
// through an io.TeeReader into the SHA-256 on their way to the file, so memory use is one copy
// buffer whatever the size and the file is never read a second time. The hash therefore describes
// exactly the bytes FFmpeg will decode.
//
// The file is created exclusively with mode 0600 inside the job's private directory. wantSize is
// the size the object store reports for the object; a body that ends early is an error even when
// the connection did not report one (a truncated transfer must not be transcoded).
func fetchSource(ctx context.Context, src storage.Store, key, dest string) (sourceResult, int64, error) {
	rc, info, err := src.Get(ctx, key, nil)
	if err != nil {
		return sourceResult{}, 0, fmt.Errorf("pipeline: get source: %w", err)
	}
	defer func() { _ = rc.Close() }()

	f, err := os.OpenFile(dest, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) //nolint:gosec // dest is inside the job's private directory
	if err != nil {
		return sourceResult{}, 0, fmt.Errorf("pipeline: create source file: %w", err)
	}
	h := sha256.New()
	n, copyErr := io.Copy(f, io.TeeReader(rc, h))
	closeErr := f.Close()
	if copyErr != nil {
		return sourceResult{}, 0, fmt.Errorf("pipeline: download source: %w", copyErr)
	}
	if closeErr != nil {
		return sourceResult{}, 0, fmt.Errorf("pipeline: write source file: %w", closeErr)
	}
	if info.Size >= 0 && n != info.Size {
		return sourceResult{}, 0, errors.New("pipeline: source download ended early")
	}
	res := sourceResult{Size: n}
	h.Sum(res.SHA256[:0])
	return res, info.Size, nil
}
