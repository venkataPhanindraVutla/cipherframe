// Package storage is Cipherframe's object-storage port (ADR 0014). A Store addresses one bucket;
// the service holds two, a source bucket and a delivery bucket (see Buckets). The S3 adapter is
// built with New.
//
// Rules every implementation follows:
//
//   - Bodies are streamed. Library code never reads a whole object into memory.
//   - Errors carry a Kind, the operation and the bucket role. They never carry credentials,
//     presigned URLs or object keys.
//   - Presigned URLs are bearer tokens until they expire. Treat them like secrets: do not log them.
package storage

import (
	"context"
	"io"
	"iter"
	"log/slog"
	"net/http"
	"time"
)

// MaxListLimit is the largest page List returns.
const MaxListLimit = 1000

// MaxDeleteBatch is the number of keys DeleteBatch sends per request (the S3 limit).
const MaxDeleteBatch = 1000

// MaxPresignTTL is the longest lifetime a presigned URL may have (the SigV4 limit).
const MaxPresignTTL = 7 * 24 * time.Hour

// Store is one bucket. Implementations are safe for concurrent use.
type Store interface {
	// Put writes size bytes from body under key. The body is streamed; pass an io.Seeker (for
	// example *os.File) when the request may need to be retried, because a one-way stream cannot
	// be rewound. contentType may be empty.
	Put(ctx context.Context, key string, body io.Reader, size int64, contentType string) error

	// Get opens an object. With a nil range it returns the whole object. The caller must close the
	// returned reader. ObjectInfo.Size is the size of the whole object, also for a ranged read.
	Get(ctx context.Context, key string, r *Range) (io.ReadCloser, ObjectInfo, error)

	// Head returns an object's metadata.
	Head(ctx context.Context, key string) (ObjectInfo, error)

	// List returns up to limit objects (1 to MaxListLimit) whose keys start with prefix, in key
	// order. Pass the empty cursor for the first page and Page.NextCursor for the next.
	List(ctx context.Context, prefix, cursor string, limit int) (Page, error)

	// DeleteBatch deletes keys, MaxDeleteBatch per request. Deleting a missing key succeeds. It
	// fails if any per-key error comes back, even inside a successful response, after trying every
	// chunk.
	DeleteBatch(ctx context.Context, keys []string) error

	// PresignGet returns a request that reads key until ttl has passed.
	PresignGet(ctx context.Context, key string, ttl time.Duration) (PresignedRequest, error)

	// PresignPut returns a request that writes key until ttl has passed. The client must send the
	// returned Header (it includes Content-Type).
	PresignPut(ctx context.Context, key string, ttl time.Duration, contentType string) (PresignedRequest, error)

	// CreateMultipart starts a multipart upload and returns its upload ID. contentType may be empty.
	CreateMultipart(ctx context.Context, key, contentType string) (uploadID string, err error)

	// PresignPart returns a request that uploads one part (1 to 10000) until ttl has passed. The
	// response's ETag header is needed for CompleteMultipart.
	PresignPart(ctx context.Context, key, uploadID string, partNumber int32, ttl time.Duration) (PresignedRequest, error)

	// UploadPart streams one part (1 to 10000) of size bytes from body into an upload started with
	// CreateMultipart and returns the part's ETag, which CompleteMultipart needs. The body is
	// streamed, never buffered whole; size must be the exact number of bytes it yields. Every part
	// but the last must be at least 5 MiB for the upload to complete.
	UploadPart(ctx context.Context, key, uploadID string, partNumber int32, body io.Reader, size int64) (etag string, err error)

	// CompleteMultipart assembles the uploaded parts, which must be listed in ascending order.
	CompleteMultipart(ctx context.Context, key, uploadID string, parts []CompletedPart) error

	// AbortMultipart discards an upload. An unknown upload ID is a NotFound error.
	AbortMultipart(ctx context.Context, key, uploadID string) error
}

// Range is a byte range. Offset is the first byte; Length is the number of bytes, or 0 for "to the
// end of the object".
type Range struct {
	Offset int64
	Length int64
}

// ObjectInfo describes an object. ContentType is empty in List results.
type ObjectInfo struct {
	Key          string
	Size         int64
	ETag         string
	ContentType  string
	LastModified time.Time
}

// Page is one page of List results. An empty NextCursor means there are no more pages.
type Page struct {
	Objects    []ObjectInfo
	NextCursor string
}

// CompletedPart names an uploaded part and the ETag its upload returned.
type CompletedPart struct {
	PartNumber int32
	ETag       string
}

// PresignedRequest is a request a plain HTTP client can send. The URL is a bearer token until it
// expires, so every printing path redacts it. Read it with URL only where it is used.
type PresignedRequest struct {
	// URL is the secret. Do not log it.
	URL string
	// Method is the HTTP method to use.
	Method string
	// Header holds headers the client must send unchanged (they are part of the signature).
	Header http.Header
}

// String implements fmt.Stringer without the URL.
func (p PresignedRequest) String() string { return p.Method + " [presigned URL redacted]" }

// GoString implements fmt.GoStringer without the URL.
func (p PresignedRequest) GoString() string { return "storage.PresignedRequest{" + p.String() + "}" }

// MarshalJSON implements json.Marshaler without the URL.
func (p PresignedRequest) MarshalJSON() ([]byte, error) {
	return []byte(`{"redacted":true}`), nil
}

// LogValue implements slog.LogValuer without the URL.
func (p PresignedRequest) LogValue() slog.Value { return slog.StringValue(p.String()) }

// ListAll iterates over every object under prefix by following the cursor. It stops after the
// first error, which it yields with a zero ObjectInfo.
func ListAll(ctx context.Context, s Store, prefix string) iter.Seq2[ObjectInfo, error] {
	return func(yield func(ObjectInfo, error) bool) {
		cursor := ""
		for {
			page, err := s.List(ctx, prefix, cursor, MaxListLimit)
			if err != nil {
				yield(ObjectInfo{}, err)
				return
			}
			for _, o := range page.Objects {
				if !yield(o, nil) {
					return
				}
			}
			if page.NextCursor == "" {
				return
			}
			if page.NextCursor == cursor {
				// A server that repeats a cursor would loop forever.
				yield(ObjectInfo{}, &Error{Kind: Other, Op: "list", Detail: "cursor did not advance"})
				return
			}
			cursor = page.NextCursor
		}
	}
}
