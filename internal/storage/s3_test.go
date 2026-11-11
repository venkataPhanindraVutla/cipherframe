package storage

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"

	"github.com/venkataPhanindraVutla/cipherframe/internal/config"
	"github.com/venkataPhanindraVutla/cipherframe/internal/storage/keys"
)

// fakeAPI implements s3API. Unset hooks fail the test when called.
type fakeAPI struct {
	t        *testing.T
	put      func(*s3.PutObjectInput, []func(*s3.Options)) (*s3.PutObjectOutput, error)
	get      func(*s3.GetObjectInput) (*s3.GetObjectOutput, error)
	list     func(*s3.ListObjectsV2Input) (*s3.ListObjectsV2Output, error)
	del      func(*s3.DeleteObjectsInput) (*s3.DeleteObjectsOutput, error)
	delCalls int
	delSizes []int
	delQuiet []bool
}

func (f *fakeAPI) PutObject(_ context.Context, in *s3.PutObjectInput, o ...func(*s3.Options)) (*s3.PutObjectOutput, error) {
	return f.put(in, o)
}

func (f *fakeAPI) GetObject(_ context.Context, in *s3.GetObjectInput, _ ...func(*s3.Options)) (*s3.GetObjectOutput, error) {
	return f.get(in)
}

func (f *fakeAPI) HeadObject(context.Context, *s3.HeadObjectInput, ...func(*s3.Options)) (*s3.HeadObjectOutput, error) {
	f.t.Helper()
	f.t.Fatal("unexpected HeadObject")
	return nil, nil
}

func (f *fakeAPI) ListObjectsV2(_ context.Context, in *s3.ListObjectsV2Input, _ ...func(*s3.Options)) (*s3.ListObjectsV2Output, error) {
	return f.list(in)
}

func (f *fakeAPI) DeleteObjects(_ context.Context, in *s3.DeleteObjectsInput, _ ...func(*s3.Options)) (*s3.DeleteObjectsOutput, error) {
	f.delCalls++
	f.delSizes = append(f.delSizes, len(in.Delete.Objects))
	f.delQuiet = append(f.delQuiet, aws.ToBool(in.Delete.Quiet))
	return f.del(in)
}

func (f *fakeAPI) CreateMultipartUpload(context.Context, *s3.CreateMultipartUploadInput, ...func(*s3.Options)) (*s3.CreateMultipartUploadOutput, error) {
	f.t.Fatal("unexpected CreateMultipartUpload")
	return nil, nil
}

func (f *fakeAPI) UploadPart(context.Context, *s3.UploadPartInput, ...func(*s3.Options)) (*s3.UploadPartOutput, error) {
	f.t.Fatal("unexpected UploadPart")
	return nil, nil
}

func (f *fakeAPI) CompleteMultipartUpload(context.Context, *s3.CompleteMultipartUploadInput, ...func(*s3.Options)) (*s3.CompleteMultipartUploadOutput, error) {
	f.t.Fatal("unexpected CompleteMultipartUpload")
	return nil, nil
}

func (f *fakeAPI) AbortMultipartUpload(context.Context, *s3.AbortMultipartUploadInput, ...func(*s3.Options)) (*s3.AbortMultipartUploadOutput, error) {
	f.t.Fatal("unexpected AbortMultipartUpload")
	return nil, nil
}

func newFakeStore(t *testing.T, f *fakeAPI) *s3Store {
	t.Helper()
	f.t = t
	return &s3Store{api: f, bucket: "bkt", role: keys.Delivery}
}

func makeKeys(n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = "t/ten_x/a/ast_y/seg-" + strconv.Itoa(i)
	}
	return out
}

func TestDeleteBatchChunksAtOneThousand(t *testing.T) {
	f := &fakeAPI{del: func(*s3.DeleteObjectsInput) (*s3.DeleteObjectsOutput, error) {
		return &s3.DeleteObjectsOutput{}, nil
	}}
	s := newFakeStore(t, f)
	if err := s.DeleteBatch(context.Background(), makeKeys(2500)); err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(f.delSizes) != "[1000 1000 500]" {
		t.Fatalf("chunk sizes = %v", f.delSizes)
	}
	for _, q := range f.delQuiet {
		if !q {
			t.Fatal("delete must be quiet so only errors come back")
		}
	}
	// Exactly one full chunk, and the empty list.
	f.delCalls, f.delSizes = 0, nil
	if err := s.DeleteBatch(context.Background(), makeKeys(1000)); err != nil || f.delCalls != 1 {
		t.Fatalf("1000 keys: err=%v calls=%d", err, f.delCalls)
	}
	f.delCalls = 0
	if err := s.DeleteBatch(context.Background(), nil); err != nil || f.delCalls != 0 {
		t.Fatalf("no keys: err=%v calls=%d", err, f.delCalls)
	}
}

func TestDeleteBatchFailsOnPerKeyErrorInsideSuccess(t *testing.T) {
	srcKey := "t/ten_x/a/ast_y/source/original"
	f := &fakeAPI{del: func(in *s3.DeleteObjectsInput) (*s3.DeleteObjectsOutput, error) {
		// A 200 response that reports one failed key in the second chunk only.
		if f := aws.ToString(in.Delete.Objects[0].Key); f == "t/ten_x/a/ast_y/seg-1000" {
			return &s3.DeleteObjectsOutput{Errors: []s3types.Error{
				{Code: aws.String("AccessDenied"), Key: aws.String(srcKey), Message: aws.String("denied " + srcKey)},
			}}, nil
		}
		return &s3.DeleteObjectsOutput{}, nil
	}}
	s := newFakeStore(t, f)
	err := s.DeleteBatch(context.Background(), makeKeys(2500))
	if err == nil {
		t.Fatal("a per-key error inside a successful response must fail the call")
	}
	if KindOf(err) != PermissionDenied {
		t.Fatalf("kind = %v", KindOf(err))
	}
	if f.delCalls != 3 {
		t.Fatalf("want every chunk attempted, got %d calls", f.delCalls)
	}
	for _, bad := range []string{srcKey, "ast_y", "denied t/"} {
		if strings.Contains(err.Error(), bad) {
			t.Fatalf("error text leaks %q: %v", bad, err)
		}
	}
	if !strings.Contains(err.Error(), "1 of 2500") {
		t.Fatalf("want a count in the error: %v", err)
	}
}

func TestDeleteBatchUnknownPerKeyCodeIsOther(t *testing.T) {
	f := &fakeAPI{del: func(*s3.DeleteObjectsInput) (*s3.DeleteObjectsOutput, error) {
		return &s3.DeleteObjectsOutput{Errors: []s3types.Error{{Code: aws.String("Odd"), Key: aws.String("k")}}}, nil
	}}
	err := newFakeStore(t, f).DeleteBatch(context.Background(), []string{"k"})
	if err == nil || KindOf(err) != Other {
		t.Fatalf("got %v", err)
	}
}

func TestDeleteBatchRequestErrorStops(t *testing.T) {
	f := &fakeAPI{del: func(*s3.DeleteObjectsInput) (*s3.DeleteObjectsOutput, error) {
		return nil, apiErr(503, "SlowDown")
	}}
	err := newFakeStore(t, f).DeleteBatch(context.Background(), makeKeys(2500))
	if !errors.Is(err, ErrUnavailable) || f.delCalls != 1 {
		t.Fatalf("err=%v calls=%d", err, f.delCalls)
	}
}

func TestDeleteBatchRejectsEmptyKeyBeforeSending(t *testing.T) {
	f := &fakeAPI{}
	err := newFakeStore(t, f).DeleteBatch(context.Background(), []string{"a", ""})
	if !errors.Is(err, ErrInvalid) || f.delCalls != 0 {
		t.Fatalf("err=%v calls=%d", err, f.delCalls)
	}
}

func TestPutUsesUnsignedPayloadOnlyForOneWayStreams(t *testing.T) {
	var gotOpts int
	f := &fakeAPI{put: func(in *s3.PutObjectInput, o []func(*s3.Options)) (*s3.PutObjectOutput, error) {
		gotOpts = len(o)
		if aws.ToInt64(in.ContentLength) != 3 || aws.ToString(in.ContentType) != "text/plain" {
			t.Errorf("bad input: %+v", in)
		}
		return &s3.PutObjectOutput{}, nil
	}}
	s := newFakeStore(t, f)
	if err := s.Put(context.Background(), "k", bytes.NewReader([]byte("abc")), 3, "text/plain"); err != nil || gotOpts != 0 {
		t.Fatalf("seekable: err=%v opts=%d", err, gotOpts)
	}
	oneWay := io.MultiReader(strings.NewReader("abc"))
	if err := s.Put(context.Background(), "k", oneWay, 3, "text/plain"); err != nil || gotOpts != 1 {
		t.Fatalf("stream: err=%v opts=%d", err, gotOpts)
	}
	var o s3.Options
	withUnsignedPayload(&o)
	if len(o.APIOptions) != 1 {
		t.Fatal("option did not register a middleware")
	}
}

func TestPutValidation(t *testing.T) {
	s := newFakeStore(t, &fakeAPI{})
	ctx := context.Background()
	for name, err := range map[string]error{
		"empty key":     s.Put(ctx, "", strings.NewReader(""), 0, ""),
		"nil body":      s.Put(ctx, "k", nil, 0, ""),
		"negative size": s.Put(ctx, "k", strings.NewReader(""), -1, ""),
		"long key":      s.Put(ctx, strings.Repeat("a", 1025), strings.NewReader(""), 0, ""),
	} {
		if !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestGetRangeAndTotalSize(t *testing.T) {
	var gotRange string
	f := &fakeAPI{get: func(in *s3.GetObjectInput) (*s3.GetObjectOutput, error) {
		gotRange = aws.ToString(in.Range)
		return &s3.GetObjectOutput{
			Body: io.NopCloser(strings.NewReader("0123")), ContentLength: aws.Int64(4),
			ContentRange: aws.String("bytes 2-5/100"), ETag: aws.String("\"e\""),
		}, nil
	}}
	s := newFakeStore(t, f)
	rc, info, err := s.Get(context.Background(), "k", &Range{Offset: 2, Length: 4})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rc.Close() }()
	if gotRange != "bytes=2-5" || info.Size != 100 {
		t.Fatalf("range=%q size=%d", gotRange, info.Size)
	}
	if _, _, err := s.Get(context.Background(), "k", &Range{Offset: 7}); err != nil || gotRange != "bytes=7-" {
		t.Fatalf("open range: %v %q", err, gotRange)
	}
	if _, _, err := s.Get(context.Background(), "k", &Range{Offset: -1}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("negative offset: %v", err)
	}
}

func TestGetNotFoundIsNotFoundOnlyForNotFound(t *testing.T) {
	for _, tc := range []struct {
		err  error
		want Kind
	}{
		{apiErr(404, "NoSuchKey"), NotFound},
		{apiErr(500, "InternalError"), Unavailable},
		{errors.New("weird"), Other},
	} {
		f := &fakeAPI{get: func(*s3.GetObjectInput) (*s3.GetObjectOutput, error) { return nil, tc.err }}
		_, _, err := newFakeStore(t, f).Get(context.Background(), "k", nil)
		if KindOf(err) != tc.want {
			t.Errorf("%v: kind %v want %v", tc.err, KindOf(err), tc.want)
		}
	}
}

func TestListCursorAndLimits(t *testing.T) {
	f := &fakeAPI{list: func(in *s3.ListObjectsV2Input) (*s3.ListObjectsV2Output, error) {
		if aws.ToString(in.ContinuationToken) == "" {
			return &s3.ListObjectsV2Output{
				Contents:              []s3types.Object{{Key: aws.String("a"), Size: aws.Int64(1)}},
				IsTruncated:           aws.Bool(true),
				NextContinuationToken: aws.String("tok"),
			}, nil
		}
		return &s3.ListObjectsV2Output{Contents: []s3types.Object{{Key: aws.String("b")}}}, nil
	}}
	s := newFakeStore(t, f)
	var got []string
	for o, err := range ListAll(context.Background(), s, "p/") {
		if err != nil {
			t.Fatal(err)
		}
		got = append(got, o.Key)
	}
	if fmt.Sprint(got) != "[a b]" {
		t.Fatalf("got %v", got)
	}
	for _, limit := range []int{0, -1, 1001} {
		if _, err := s.List(context.Background(), "", "", limit); !errors.Is(err, ErrInvalid) {
			t.Errorf("limit %d: %v", limit, err)
		}
	}
}

func TestListTruncatedWithoutTokenIsAnError(t *testing.T) {
	f := &fakeAPI{list: func(*s3.ListObjectsV2Input) (*s3.ListObjectsV2Output, error) {
		return &s3.ListObjectsV2Output{IsTruncated: aws.Bool(true)}, nil
	}}
	if _, err := newFakeStore(t, f).List(context.Background(), "", "", 10); err == nil {
		t.Fatal("silently treating a truncated listing as complete would hide objects")
	}
}

type stuckStore struct{ Store }

func (stuckStore) List(context.Context, string, string, int) (Page, error) {
	return Page{Objects: []ObjectInfo{{Key: "x"}}, NextCursor: "same"}, nil
}

func TestListAllStopsOnStuckCursor(t *testing.T) {
	n, sawErr := 0, false
	for _, err := range ListAll(context.Background(), stuckStore{}, "") {
		if err != nil {
			sawErr = true
			break
		}
		if n++; n > 10 {
			t.Fatal("did not stop")
		}
	}
	if !sawErr {
		t.Fatal("expected an error for a cursor that does not advance")
	}
}

func TestMultipartValidation(t *testing.T) {
	s := newFakeStore(t, &fakeAPI{})
	ctx := context.Background()
	bad := [][]CompletedPart{
		nil,
		{{PartNumber: 0, ETag: "e"}},
		{{PartNumber: 2, ETag: "e"}, {PartNumber: 1, ETag: "e"}},
		{{PartNumber: 1, ETag: "e"}, {PartNumber: 1, ETag: "e"}},
		{{PartNumber: 1, ETag: ""}},
	}
	for i, parts := range bad {
		if err := s.CompleteMultipart(ctx, "k", "up", parts); !errors.Is(err, ErrInvalid) {
			t.Errorf("case %d: %v", i, err)
		}
	}
	if _, err := s.PresignPart(ctx, "k", "up", 0, time.Minute); !errors.Is(err, ErrInvalid) {
		t.Errorf("part 0: %v", err)
	}
	if _, err := s.PresignPart(ctx, "k", "up", 10001, time.Minute); !errors.Is(err, ErrInvalid) {
		t.Errorf("part 10001: %v", err)
	}
	d := deliveryStore{s}
	if _, err := d.PresignGet(ctx, "k", 0); !errors.Is(err, ErrInvalid) {
		t.Errorf("ttl 0: %v", err)
	}
	if _, err := d.PresignGet(ctx, "k", 8*24*time.Hour); !errors.Is(err, ErrInvalid) {
		t.Errorf("ttl 8d: %v", err)
	}
}

func staticCfg(endpoint, public string) config.S3 {
	return config.S3{
		Endpoint: endpoint, PublicEndpoint: public, Region: "us-east-1", ForcePathStyle: true,
		SourceBucket: "src", DeliveryBucket: "dlv",
		AccessKeyID:     config.NewStaticCredential("AKIATESTTESTTESTTEST"),
		SecretAccessKey: config.NewStaticCredential("test-secret-test-secret-test-secret"),
	}
}

func TestPublicClientSignsForPublicHostAndInternalClientDoesNot(t *testing.T) {
	cfg := staticCfg("http://internal.invalid:9000", "https://files.example.test")
	b, err := New(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	p, err := b.Delivery.PresignGet(context.Background(), "t/x/y", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(p.URL)
	if err != nil {
		t.Fatal(err)
	}
	if u.Scheme != "https" || u.Host != "files.example.test" || !strings.HasPrefix(u.Path, "/dlv/t/x/y") {
		t.Fatalf("presigned URL does not use the public endpoint with a path-style bucket: host=%q path=%q", u.Host, u.Path)
	}
	if strings.Contains(u.Query().Get("X-Amz-SignedHeaders"), "x-amz-checksum") || u.Query().Has("x-amz-checksum-mode") {
		t.Fatalf("checksum parameters in presigned URL: %v", u.Query())
	}
	if u.Query().Get("X-Amz-Expires") != "60" || p.Method != "GET" {
		t.Fatalf("bad presign: %v %s", u.Query(), p.Method)
	}
	if _, ok := p.Header["Host"]; ok {
		t.Fatal("Host header must not be returned")
	}

	put, err := b.Source.PresignPut(context.Background(), "k", time.Minute, "video/mp4")
	if err != nil {
		t.Fatal(err)
	}
	if put.Method != "PUT" || put.Header.Get("Content-Type") != "video/mp4" {
		t.Fatalf("put presign: %s %v", put.Method, put.Header)
	}
	part, err := b.Source.PresignPart(context.Background(), "k", "upload-1", 3, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	pu, _ := url.Parse(part.URL)
	if pu.Query().Get("partNumber") != "3" || pu.Query().Get("uploadId") != "upload-1" {
		t.Fatalf("part query: %v", pu.Query())
	}
}

func TestPublicEndpointFallsBackToInternal(t *testing.T) {
	b, err := New(context.Background(), staticCfg("http://s3.example.test:9000", ""))
	if err != nil {
		t.Fatal(err)
	}
	p, err := b.Delivery.PresignGet(context.Background(), "k", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if u, _ := url.Parse(p.URL); u.Host != "s3.example.test:9000" {
		t.Fatalf("host = %q", u.Host)
	}
}

func TestNewRejectsBadBuckets(t *testing.T) {
	cfg := staticCfg("http://x.test", "")
	cfg.DeliveryBucket = cfg.SourceBucket
	if _, err := New(context.Background(), cfg); err == nil {
		t.Error("equal buckets accepted")
	}
	cfg.DeliveryBucket = ""
	if _, err := New(context.Background(), cfg); err == nil {
		t.Error("empty bucket accepted")
	}
}

func TestCredentialStateSelection(t *testing.T) {
	ctx := context.Background()

	t.Run("static", func(t *testing.T) {
		p, err := credentialsFor(ctx, staticCfg("", ""))
		if err != nil {
			t.Fatal(err)
		}
		c, err := p.Retrieve(ctx)
		if err != nil || c.AccessKeyID != "AKIATESTTESTTESTTEST" || c.SecretAccessKey == "" || c.Source != "StaticCredentials" {
			t.Fatalf("got %+v err=%v", c.Source, err)
		}
	})

	t.Run("unset is anonymous", func(t *testing.T) {
		cfg := staticCfg("", "")
		cfg.AccessKeyID, cfg.SecretAccessKey = config.Credential{}, config.Credential{}
		p, err := credentialsFor(ctx, cfg)
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := p.(aws.AnonymousCredentials); !ok {
			t.Fatalf("got %T", p)
		}
	})

	t.Run("provider chain uses the SDK default chain", func(t *testing.T) {
		t.Setenv("AWS_ACCESS_KEY_ID", "AKIACHAINCHAINCHAIN")
		t.Setenv("AWS_SECRET_ACCESS_KEY", "chain-secret")
		t.Setenv("AWS_SESSION_TOKEN", "")
		t.Setenv("AWS_EC2_METADATA_DISABLED", "true")
		t.Setenv("AWS_CONFIG_FILE", "/nonexistent")
		t.Setenv("AWS_SHARED_CREDENTIALS_FILE", "/nonexistent")
		cfg := staticCfg("", "")
		cfg.AccessKeyID, cfg.SecretAccessKey = config.NewStaticCredential(""), config.NewStaticCredential("")
		if cfg.AccessKeyID.State() != config.ProviderChain {
			t.Fatal("test setup: want ProviderChain")
		}
		p, err := credentialsFor(ctx, cfg)
		if err != nil {
			t.Fatal(err)
		}
		c, err := p.Retrieve(ctx)
		if err != nil || c.AccessKeyID != "AKIACHAINCHAINCHAIN" {
			t.Fatalf("chain credentials not used: err=%v", err)
		}
	})

	t.Run("mixed states rejected", func(t *testing.T) {
		cfg := staticCfg("", "")
		cfg.SecretAccessKey = config.Credential{}
		if _, err := credentialsFor(ctx, cfg); err == nil {
			t.Fatal("mixed states accepted")
		}
	})
}

func TestNoCredentialsInErrorsOrLogs(t *testing.T) {
	cfg := staticCfg("http://x.test", "")
	cfg.SecretAccessKey = config.Credential{}
	_, err := New(context.Background(), cfg)
	if err == nil {
		t.Fatal("want error")
	}
	if strings.Contains(err.Error(), "AKIA") || strings.Contains(err.Error(), "test-secret") {
		t.Fatalf("credential in error: %v", err)
	}
}

func TestPresignedRequestNeverPrintsURL(t *testing.T) {
	p := PresignedRequest{URL: "https://h/b/k?X-Amz-Signature=SECRET", Method: "GET"}
	var buf bytes.Buffer
	slog.New(slog.NewJSONHandler(&buf, nil)).Info("x", "req", p)
	slog.New(slog.NewTextHandler(&buf, nil)).Info("x", "req", p)
	j, _ := json.Marshal(p)
	out := fmt.Sprintf("%v %+v %#v %s %s", p, p, p, buf.String(), j)
	if strings.Contains(out, "SECRET") || strings.Contains(out, "X-Amz") {
		t.Fatalf("presigned URL leaked: %s", out)
	}
}

// I4: only the delivery bucket can sign read URLs. The source bucket's type has no PresignGet
// method, so this is a compile-time property; the assertions document it.
func TestOnlyTheDeliveryBucketCanPresignReads(t *testing.T) {
	b, err := New(context.Background(), staticCfg("http://s3.example.test:9000", ""))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := b.Source.(GetPresigner); ok {
		t.Fatal("the source bucket must not implement GetPresigner")
	}
	if _, ok := b.Delivery.(GetPresigner); !ok {
		t.Fatal("the delivery bucket must implement GetPresigner")
	}
	st, err := NewStore(context.Background(), staticCfg("http://s3.example.test:9000", ""), "b", keys.Source)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := st.(GetPresigner); ok {
		t.Fatal("a source-role store must not implement GetPresigner")
	}
	var _ GetPresigner = deliveryStore{}
}
