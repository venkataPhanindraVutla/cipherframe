package storage

import (
	"bytes"
	"context"
	"io"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"

	"github.com/venkataPhanindraVutla/cipherframe/internal/storage/keys"
)

// partAPI records the UploadPart call.
type partAPI struct {
	*fakeAPI
	in   *s3.UploadPartInput
	opts int
	etag string
}

func (p *partAPI) UploadPart(_ context.Context, in *s3.UploadPartInput, o ...func(*s3.Options)) (*s3.UploadPartOutput, error) {
	p.in, p.opts = in, len(o)
	return &s3.UploadPartOutput{ETag: aws.String(p.etag)}, nil
}

type streamOnly struct{ io.Reader }

func TestUploadPartStreamsWithAnUnsignedPayload(t *testing.T) {
	api := &partAPI{fakeAPI: &fakeAPI{}, etag: `"abc"`}
	api.t = t
	s := &s3Store{api: api, bucket: "bkt", role: keys.Source}

	body := streamOnly{bytes.NewReader([]byte("hello"))}
	etag, err := s.UploadPart(context.Background(), "k", "uid", 3, body, 5)
	if err != nil || etag != `"abc"` {
		t.Fatalf("etag %q err %v", etag, err)
	}
	if aws.ToInt32(api.in.PartNumber) != 3 || aws.ToInt64(api.in.ContentLength) != 5 || aws.ToString(api.in.UploadId) != "uid" {
		t.Fatalf("unexpected input %+v", api.in)
	}
	if api.opts != 1 {
		t.Fatalf("a one-way body needs the unsigned payload option, got %d options", api.opts)
	}

	// A seekable body is signed normally.
	if _, err := s.UploadPart(context.Background(), "k", "uid", 1, bytes.NewReader([]byte("x")), 1); err != nil {
		t.Fatal(err)
	}
	if api.opts != 0 {
		t.Fatalf("a seekable body must not get the unsigned payload option, got %d", api.opts)
	}
}

func TestUploadPartRejectsBadInput(t *testing.T) {
	api := &partAPI{fakeAPI: &fakeAPI{}, etag: "x"}
	api.t = t
	s := &s3Store{api: api, bucket: "bkt", role: keys.Source}
	body := bytes.NewReader([]byte("x"))
	for name, call := range map[string]func() error{
		"part 0":         func() error { _, e := s.UploadPart(context.Background(), "k", "u", 0, body, 1); return e },
		"part 10001":     func() error { _, e := s.UploadPart(context.Background(), "k", "u", 10001, body, 1); return e },
		"empty upload":   func() error { _, e := s.UploadPart(context.Background(), "k", "", 1, body, 1); return e },
		"empty key":      func() error { _, e := s.UploadPart(context.Background(), "", "u", 1, body, 1); return e },
		"nil body":       func() error { _, e := s.UploadPart(context.Background(), "k", "u", 1, nil, 1); return e },
		"zero size body": func() error { _, e := s.UploadPart(context.Background(), "k", "u", 1, body, 0); return e },
	} {
		if err := call(); KindOf(err) != Invalid {
			t.Errorf("%s: err = %v, want an Invalid error", name, err)
		}
	}
	if api.in != nil {
		t.Fatal("a rejected call reached the SDK")
	}
}

func TestUploadPartNeedsAnETag(t *testing.T) {
	api := &partAPI{fakeAPI: &fakeAPI{}}
	api.t = t
	s := &s3Store{api: api, bucket: "bkt", role: keys.Source}
	if _, err := s.UploadPart(context.Background(), "k", "u", 1, bytes.NewReader([]byte("x")), 1); err == nil {
		t.Fatal("an empty ETag was accepted")
	}
}
