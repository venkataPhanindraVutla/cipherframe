package storage

import (
	"context"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"

	"github.com/venkataPhanindraVutla/cipherframe/internal/storage/keys"
)

// s3API is the part of the SDK client the adapter uses. Unit tests inject a fake.
type s3API interface {
	PutObject(ctx context.Context, in *s3.PutObjectInput, opts ...func(*s3.Options)) (*s3.PutObjectOutput, error)
	GetObject(ctx context.Context, in *s3.GetObjectInput, opts ...func(*s3.Options)) (*s3.GetObjectOutput, error)
	HeadObject(ctx context.Context, in *s3.HeadObjectInput, opts ...func(*s3.Options)) (*s3.HeadObjectOutput, error)
	ListObjectsV2(ctx context.Context, in *s3.ListObjectsV2Input, opts ...func(*s3.Options)) (*s3.ListObjectsV2Output, error)
	DeleteObjects(ctx context.Context, in *s3.DeleteObjectsInput, opts ...func(*s3.Options)) (*s3.DeleteObjectsOutput, error)
	CreateMultipartUpload(ctx context.Context, in *s3.CreateMultipartUploadInput, opts ...func(*s3.Options)) (*s3.CreateMultipartUploadOutput, error)
	UploadPart(ctx context.Context, in *s3.UploadPartInput, opts ...func(*s3.Options)) (*s3.UploadPartOutput, error)
	CompleteMultipartUpload(ctx context.Context, in *s3.CompleteMultipartUploadInput, opts ...func(*s3.Options)) (*s3.CompleteMultipartUploadOutput, error)
	AbortMultipartUpload(ctx context.Context, in *s3.AbortMultipartUploadInput, opts ...func(*s3.Options)) (*s3.AbortMultipartUploadOutput, error)
}

// s3Presigner is the part of the SDK presign client the adapter uses. It is built from the public
// client only.
type s3Presigner interface {
	PresignGetObject(ctx context.Context, in *s3.GetObjectInput, opts ...func(*s3.PresignOptions)) (*v4.PresignedHTTPRequest, error)
	PresignPutObject(ctx context.Context, in *s3.PutObjectInput, opts ...func(*s3.PresignOptions)) (*v4.PresignedHTTPRequest, error)
	PresignUploadPart(ctx context.Context, in *s3.UploadPartInput, opts ...func(*s3.PresignOptions)) (*v4.PresignedHTTPRequest, error)
}

// s3Store is a Store over one bucket.
type s3Store struct {
	api    s3API
	pre    s3Presigner
	bucket string
	role   keys.Bucket
}

var _ Store = (*s3Store)(nil)

func (s *s3Store) fail(op string, err error) error { return wrapErr(op, s.role, err) }

func (s *s3Store) bad(op, detail string) error { return invalid(op, s.role, detail) }

func (s *s3Store) checkKey(op, key string) error {
	if key == "" {
		return s.bad(op, "empty key")
	}
	if len(key) > 1024 {
		return s.bad(op, "key longer than 1024 bytes")
	}
	return nil
}

func (s *s3Store) checkTTL(op string, ttl time.Duration) error {
	if ttl < time.Second || ttl > MaxPresignTTL {
		return s.bad(op, "ttl must be between 1 second and 7 days")
	}
	return nil
}

// withUnsignedPayload signs the request without hashing the body. A one-way stream cannot be read
// twice, and the SDK would otherwise refuse it on a plain-HTTP endpoint.
func withUnsignedPayload(o *s3.Options) {
	o.APIOptions = append(o.APIOptions, v4.SwapComputePayloadSHA256ForUnsignedPayloadMiddleware)
}

func (s *s3Store) Put(ctx context.Context, key string, body io.Reader, size int64, contentType string) error {
	const op = "put"
	if err := s.checkKey(op, key); err != nil {
		return err
	}
	if body == nil || size < 0 {
		return s.bad(op, "need a body and a non-negative size")
	}
	in := &s3.PutObjectInput{
		Bucket:        aws.String(s.bucket),
		Key:           aws.String(key),
		Body:          body,
		ContentLength: aws.Int64(size),
	}
	if contentType != "" {
		in.ContentType = aws.String(contentType)
	}
	var opts []func(*s3.Options)
	if _, seekable := body.(io.Seeker); !seekable {
		opts = append(opts, withUnsignedPayload)
	}
	_, err := s.api.PutObject(ctx, in, opts...)
	return s.fail(op, err)
}

func rangeHeader(r *Range) (string, bool) {
	if r.Offset < 0 || r.Length < 0 {
		return "", false
	}
	if r.Length == 0 {
		return "bytes=" + strconv.FormatInt(r.Offset, 10) + "-", true
	}
	return "bytes=" + strconv.FormatInt(r.Offset, 10) + "-" + strconv.FormatInt(r.Offset+r.Length-1, 10), true
}

// totalFromContentRange reads the object size from "bytes 0-9/100".
func totalFromContentRange(cr string) (int64, bool) {
	i := strings.LastIndexByte(cr, '/')
	if i < 0 {
		return 0, false
	}
	n, err := strconv.ParseInt(cr[i+1:], 10, 64)
	if err != nil || n < 0 {
		return 0, false
	}
	return n, true
}

func (s *s3Store) Get(ctx context.Context, key string, r *Range) (io.ReadCloser, ObjectInfo, error) {
	const op = "get"
	if err := s.checkKey(op, key); err != nil {
		return nil, ObjectInfo{}, err
	}
	in := &s3.GetObjectInput{Bucket: aws.String(s.bucket), Key: aws.String(key)}
	if r != nil {
		h, ok := rangeHeader(r)
		if !ok {
			return nil, ObjectInfo{}, s.bad(op, "negative range")
		}
		in.Range = aws.String(h)
	}
	out, err := s.api.GetObject(ctx, in)
	if err != nil {
		return nil, ObjectInfo{}, s.fail(op, err)
	}
	info := ObjectInfo{
		Key:          key,
		Size:         aws.ToInt64(out.ContentLength),
		ETag:         aws.ToString(out.ETag),
		ContentType:  aws.ToString(out.ContentType),
		LastModified: aws.ToTime(out.LastModified),
	}
	if out.ContentRange != nil {
		if n, ok := totalFromContentRange(*out.ContentRange); ok {
			info.Size = n
		}
	}
	return out.Body, info, nil
}

func (s *s3Store) Head(ctx context.Context, key string) (ObjectInfo, error) {
	const op = "head"
	if err := s.checkKey(op, key); err != nil {
		return ObjectInfo{}, err
	}
	out, err := s.api.HeadObject(ctx, &s3.HeadObjectInput{Bucket: aws.String(s.bucket), Key: aws.String(key)})
	if err != nil {
		return ObjectInfo{}, s.fail(op, err)
	}
	return ObjectInfo{
		Key:          key,
		Size:         aws.ToInt64(out.ContentLength),
		ETag:         aws.ToString(out.ETag),
		ContentType:  aws.ToString(out.ContentType),
		LastModified: aws.ToTime(out.LastModified),
	}, nil
}

func (s *s3Store) List(ctx context.Context, prefix, cursor string, limit int) (Page, error) {
	const op = "list"
	if limit < 1 || limit > MaxListLimit {
		return Page{}, s.bad(op, "limit must be between 1 and 1000")
	}
	in := &s3.ListObjectsV2Input{
		Bucket:  aws.String(s.bucket),
		Prefix:  aws.String(prefix),
		MaxKeys: aws.Int32(int32(limit)), //nolint:gosec // limit is range-checked above
	}
	if cursor != "" {
		in.ContinuationToken = aws.String(cursor)
	}
	out, err := s.api.ListObjectsV2(ctx, in)
	if err != nil {
		return Page{}, s.fail(op, err)
	}
	page := Page{Objects: make([]ObjectInfo, 0, len(out.Contents))}
	for _, o := range out.Contents {
		page.Objects = append(page.Objects, ObjectInfo{
			Key:          aws.ToString(o.Key),
			Size:         aws.ToInt64(o.Size),
			ETag:         aws.ToString(o.ETag),
			LastModified: aws.ToTime(o.LastModified),
		})
	}
	if aws.ToBool(out.IsTruncated) {
		page.NextCursor = aws.ToString(out.NextContinuationToken)
		if page.NextCursor == "" {
			// Truncated with nothing to continue from: reporting "done" would hide objects.
			return Page{}, &Error{Kind: Other, Op: op, Role: s.role, Detail: "truncated listing without a continuation token"}
		}
	}
	return page, nil
}

func (s *s3Store) DeleteBatch(ctx context.Context, objKeys []string) error {
	const op = "delete_batch"
	for _, k := range objKeys {
		if err := s.checkKey(op, k); err != nil {
			return err
		}
	}
	failed := 0
	firstKind := Other
	var firstCode string
	var firstStatus int
	for start := 0; start < len(objKeys); start += MaxDeleteBatch {
		end := min(start+MaxDeleteBatch, len(objKeys))
		ids := make([]s3types.ObjectIdentifier, 0, end-start)
		for _, k := range objKeys[start:end] {
			ids = append(ids, s3types.ObjectIdentifier{Key: aws.String(k)})
		}
		out, err := s.api.DeleteObjects(ctx, &s3.DeleteObjectsInput{
			Bucket: aws.String(s.bucket),
			Delete: &s3types.Delete{Objects: ids, Quiet: aws.Bool(true)},
		})
		if err != nil {
			// A failed request: stop. The caller retries the whole call; deletes are idempotent.
			return s.fail(op, err)
		}
		for _, e := range out.Errors {
			if failed == 0 {
				c := aws.ToString(e.Code)
				firstKind = Other
				if k, ok := codeKinds[c]; ok {
					firstKind = k
				}
				if safeCode.MatchString(c) {
					firstCode = c
				}
				firstStatus = 0
			}
			failed++
		}
	}
	if failed > 0 {
		return &Error{
			Kind: firstKind, Op: op, Role: s.role, Code: firstCode, HTTPStatus: firstStatus,
			Detail: strconv.Itoa(failed) + " of " + strconv.Itoa(len(objKeys)) + " keys were not deleted",
		}
	}
	return nil
}

// presigned converts the SDK result. The Host header is dropped: an HTTP client derives it from the URL.
func presigned(r *v4.PresignedHTTPRequest) PresignedRequest {
	h := make(http.Header, len(r.SignedHeader))
	for k, v := range r.SignedHeader {
		if strings.EqualFold(k, "host") {
			continue
		}
		h[k] = append([]string(nil), v...)
	}
	return PresignedRequest{URL: r.URL, Method: r.Method, Header: h}
}

func expires(ttl time.Duration) func(*s3.PresignOptions) {
	return func(o *s3.PresignOptions) { o.Expires = ttl }
}

// deliveryStore is the delivery bucket's handle. PresignGet exists on this type only, so the source
// bucket's *s3Store cannot sign read URLs (I4).
type deliveryStore struct{ *s3Store }

// PresignGet implements GetPresigner.
func (s deliveryStore) PresignGet(ctx context.Context, key string, ttl time.Duration) (PresignedRequest, error) {
	const op = "presign_get"
	if err := s.checkKey(op, key); err != nil {
		return PresignedRequest{}, err
	}
	if err := s.checkTTL(op, ttl); err != nil {
		return PresignedRequest{}, err
	}
	r, err := s.pre.PresignGetObject(ctx, &s3.GetObjectInput{Bucket: aws.String(s.bucket), Key: aws.String(key)}, expires(ttl))
	if err != nil {
		return PresignedRequest{}, s.fail(op, err)
	}
	return presigned(r), nil
}

func (s *s3Store) PresignPut(ctx context.Context, key string, ttl time.Duration, contentType string) (PresignedRequest, error) {
	const op = "presign_put"
	if err := s.checkKey(op, key); err != nil {
		return PresignedRequest{}, err
	}
	if err := s.checkTTL(op, ttl); err != nil {
		return PresignedRequest{}, err
	}
	in := &s3.PutObjectInput{Bucket: aws.String(s.bucket), Key: aws.String(key)}
	if contentType != "" {
		in.ContentType = aws.String(contentType)
	}
	r, err := s.pre.PresignPutObject(ctx, in, expires(ttl))
	if err != nil {
		return PresignedRequest{}, s.fail(op, err)
	}
	return presigned(r), nil
}

func (s *s3Store) CreateMultipart(ctx context.Context, key, contentType string) (string, error) {
	const op = "create_multipart"
	if err := s.checkKey(op, key); err != nil {
		return "", err
	}
	in := &s3.CreateMultipartUploadInput{Bucket: aws.String(s.bucket), Key: aws.String(key)}
	if contentType != "" {
		in.ContentType = aws.String(contentType)
	}
	out, err := s.api.CreateMultipartUpload(ctx, in)
	if err != nil {
		return "", s.fail(op, err)
	}
	if aws.ToString(out.UploadId) == "" {
		return "", &Error{Kind: Other, Op: op, Role: s.role, Detail: "no upload ID returned"}
	}
	return *out.UploadId, nil
}

func (s *s3Store) PresignPart(ctx context.Context, key, uploadID string, partNumber int32, ttl time.Duration) (PresignedRequest, error) {
	const op = "presign_part"
	if err := s.checkKey(op, key); err != nil {
		return PresignedRequest{}, err
	}
	if uploadID == "" || partNumber < 1 || partNumber > 10000 {
		return PresignedRequest{}, s.bad(op, "need an upload ID and a part number from 1 to 10000")
	}
	if err := s.checkTTL(op, ttl); err != nil {
		return PresignedRequest{}, err
	}
	r, err := s.pre.PresignUploadPart(ctx, &s3.UploadPartInput{
		Bucket:     aws.String(s.bucket),
		Key:        aws.String(key),
		UploadId:   aws.String(uploadID),
		PartNumber: aws.Int32(partNumber),
	}, expires(ttl))
	if err != nil {
		return PresignedRequest{}, s.fail(op, err)
	}
	return presigned(r), nil
}

func (s *s3Store) UploadPart(ctx context.Context, key, uploadID string, partNumber int32, body io.Reader, size int64) (string, error) {
	const op = "upload_part"
	if err := s.checkKey(op, key); err != nil {
		return "", err
	}
	if uploadID == "" || partNumber < 1 || partNumber > 10000 {
		return "", s.bad(op, "need an upload ID and a part number from 1 to 10000")
	}
	if body == nil || size < 1 {
		return "", s.bad(op, "need a body and a positive size")
	}
	var opts []func(*s3.Options)
	if _, seekable := body.(io.Seeker); !seekable {
		opts = append(opts, withUnsignedPayload)
	}
	out, err := s.api.UploadPart(ctx, &s3.UploadPartInput{
		Bucket:        aws.String(s.bucket),
		Key:           aws.String(key),
		UploadId:      aws.String(uploadID),
		PartNumber:    aws.Int32(partNumber),
		Body:          body,
		ContentLength: aws.Int64(size),
	}, opts...)
	if err != nil {
		return "", s.fail(op, err)
	}
	if aws.ToString(out.ETag) == "" {
		return "", &Error{Kind: Other, Op: op, Role: s.role, Detail: "no ETag returned"}
	}
	return *out.ETag, nil
}

func (s *s3Store) CompleteMultipart(ctx context.Context, key, uploadID string, parts []CompletedPart) error {
	const op = "complete_multipart"
	if err := s.checkKey(op, key); err != nil {
		return err
	}
	if uploadID == "" || len(parts) == 0 || len(parts) > 10000 {
		return s.bad(op, "need an upload ID and 1 to 10000 parts")
	}
	cp := make([]s3types.CompletedPart, 0, len(parts))
	var prev int32
	for _, p := range parts {
		if p.PartNumber < 1 || p.PartNumber > 10000 || p.PartNumber <= prev || p.ETag == "" {
			return s.bad(op, "parts must have ascending numbers from 1 to 10000 and an ETag")
		}
		prev = p.PartNumber
		cp = append(cp, s3types.CompletedPart{PartNumber: aws.Int32(p.PartNumber), ETag: aws.String(p.ETag)})
	}
	_, err := s.api.CompleteMultipartUpload(ctx, &s3.CompleteMultipartUploadInput{
		Bucket:          aws.String(s.bucket),
		Key:             aws.String(key),
		UploadId:        aws.String(uploadID),
		MultipartUpload: &s3types.CompletedMultipartUpload{Parts: cp},
	})
	return s.fail(op, err)
}

func (s *s3Store) AbortMultipart(ctx context.Context, key, uploadID string) error {
	const op = "abort_multipart"
	if err := s.checkKey(op, key); err != nil {
		return err
	}
	if uploadID == "" {
		return s.bad(op, "need an upload ID")
	}
	_, err := s.api.AbortMultipartUpload(ctx, &s3.AbortMultipartUploadInput{
		Bucket:   aws.String(s.bucket),
		Key:      aws.String(key),
		UploadId: aws.String(uploadID),
	})
	return s.fail(op, err)
}
