//go:build !nokms_aws

package awskms

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	awskmssdk "github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/aws/smithy-go"
	smithyhttp "github.com/aws/smithy-go/transport/http"

	"github.com/venkataPhanindraVutla/cipherframe/internal/config"
	"github.com/venkataPhanindraVutla/cipherframe/internal/kms"
)

const (
	testARN  = "arn:aws:kms:eu-west-1:123456789012:key/1234abcd-12ab-34cd-56ef-1234567890ab"
	otherARN = "arn:aws:kms:eu-west-1:123456789012:key/ffffffff-12ab-34cd-56ef-1234567890ab"
)

// fake is an in-memory KMS: it "encrypts" by prefixing the key ARN and the context, so a wrong
// context or key fails like KMS does.
type fake struct {
	describe func(*awskmssdk.DescribeKeyInput) (*awskmssdk.DescribeKeyOutput, error)
	err      error // returned by every call when set

	encryptIn []*awskmssdk.EncryptInput
	decryptIn []*awskmssdk.DecryptInput
	gotDL     bool
}

func seal(arn string, ec map[string]string, pt []byte) []byte {
	return []byte(arn + "|" + ec[ContextKey] + "|" + string(pt))
}

func (f *fake) DescribeKey(ctx context.Context, in *awskmssdk.DescribeKeyInput, _ ...func(*awskmssdk.Options)) (*awskmssdk.DescribeKeyOutput, error) {
	_, f.gotDL = ctx.Deadline()
	if f.err != nil {
		return nil, f.err
	}
	if f.describe != nil {
		return f.describe(in)
	}
	return &awskmssdk.DescribeKeyOutput{KeyMetadata: &kmstypes.KeyMetadata{
		Arn:      aws.String(testARN),
		KeyState: kmstypes.KeyStateEnabled,
		KeyUsage: kmstypes.KeyUsageTypeEncryptDecrypt,
		KeySpec:  kmstypes.KeySpecSymmetricDefault,
	}}, nil
}

func (f *fake) Encrypt(ctx context.Context, in *awskmssdk.EncryptInput, _ ...func(*awskmssdk.Options)) (*awskmssdk.EncryptOutput, error) {
	_, f.gotDL = ctx.Deadline()
	f.encryptIn = append(f.encryptIn, in)
	if f.err != nil {
		return nil, f.err
	}
	return &awskmssdk.EncryptOutput{KeyId: aws.String(testARN), CiphertextBlob: seal(testARN, in.EncryptionContext, in.Plaintext)}, nil
}

func (f *fake) Decrypt(ctx context.Context, in *awskmssdk.DecryptInput, _ ...func(*awskmssdk.Options)) (*awskmssdk.DecryptOutput, error) {
	_, f.gotDL = ctx.Deadline()
	f.decryptIn = append(f.decryptIn, in)
	if f.err != nil {
		return nil, f.err
	}
	arn, rest, _ := strings.Cut(string(in.CiphertextBlob), "|")
	ctxVal, pt, _ := strings.Cut(rest, "|")
	if arn != aws.ToString(in.KeyId) {
		return nil, &kmstypes.IncorrectKeyException{}
	}
	if ctxVal != in.EncryptionContext[ContextKey] {
		return nil, &kmstypes.InvalidCiphertextException{}
	}
	return &awskmssdk.DecryptOutput{KeyId: aws.String(arn), Plaintext: []byte(pt)}, nil
}

func newTest(f *fake) *Provider { return newProvider(f, "alias/cipherframe", time.Second) }

func TestCurrentResolvesToARN(t *testing.T) {
	f := &fake{}
	ref, err := newTest(f).Current(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if ref != (kms.KeyRef{KeyID: testARN, Version: Version}) {
		t.Fatalf("ref = %+v", ref)
	}
	if !f.gotDL {
		t.Fatal("the call had no deadline")
	}
}

func TestCurrentRefusesUnusableKeys(t *testing.T) {
	meta := func(m kmstypes.KeyMetadata) *fake {
		m.Arn = aws.String(testARN)
		return &fake{describe: func(*awskmssdk.DescribeKeyInput) (*awskmssdk.DescribeKeyOutput, error) {
			return &awskmssdk.DescribeKeyOutput{KeyMetadata: &m}, nil
		}}
	}
	for name, f := range map[string]*fake{
		"disabled":         meta(kmstypes.KeyMetadata{KeyState: kmstypes.KeyStateDisabled}),
		"pending deletion": meta(kmstypes.KeyMetadata{KeyState: kmstypes.KeyStatePendingDeletion}),
		"sign and verify":  meta(kmstypes.KeyMetadata{KeyState: kmstypes.KeyStateEnabled, KeyUsage: kmstypes.KeyUsageTypeSignVerify}),
		"asymmetric":       meta(kmstypes.KeyMetadata{KeyState: kmstypes.KeyStateEnabled, KeySpec: kmstypes.KeySpecRsa2048}),
	} {
		if _, err := newTest(f).Current(context.Background()); !errors.Is(err, kms.ErrNotConfigured) {
			t.Errorf("%s: want ErrNotConfigured, got %v", name, err)
		}
	}
	empty := &fake{describe: func(*awskmssdk.DescribeKeyInput) (*awskmssdk.DescribeKeyOutput, error) {
		return &awskmssdk.DescribeKeyOutput{}, nil
	}}
	if _, err := newTest(empty).Current(context.Background()); !errors.Is(err, kms.ErrOther) {
		t.Fatalf("empty metadata: want ErrOther, got %v", err)
	}
}

func TestWrapSendsEncryptionContextAndRecordsARN(t *testing.T) {
	f := &fake{}
	p := newTest(f)
	aad := []byte{0x01, 0x00, 0xff, 'a'}
	w, err := p.Wrap(context.Background(), []byte("0123456789abcdef"), aad)
	if err != nil {
		t.Fatal(err)
	}
	if w.Provider != Name || w.KeyID != testARN || w.Version != Version || len(w.Ciphertext) == 0 {
		t.Fatalf("wrapped = %+v", w)
	}
	in := f.encryptIn[0]
	if aws.ToString(in.KeyId) != "alias/cipherframe" {
		t.Fatal("Encrypt must use the configured key id (alias or ARN)")
	}
	if got := in.EncryptionContext; len(got) != 1 || got[ContextKey] != base64.StdEncoding.EncodeToString(aad) {
		t.Fatalf("encryption context = %v", got)
	}
	if in.EncryptionAlgorithm != kmstypes.EncryptionAlgorithmSpecSymmetricDefault {
		t.Fatal("wrong algorithm")
	}
	if !f.gotDL {
		t.Fatal("the call had no deadline")
	}
}

func TestUnwrapPinsStoredARNAndContext(t *testing.T) {
	f := &fake{}
	p := newTest(f)
	aad := []byte("aad")
	w, err := p.Wrap(context.Background(), []byte("0123456789abcdef"), aad)
	if err != nil {
		t.Fatal(err)
	}
	got, err := p.Unwrap(context.Background(), w, aad)
	if err != nil || string(got) != "0123456789abcdef" {
		t.Fatalf("unwrap: %v", err)
	}
	in := f.decryptIn[0]
	if aws.ToString(in.KeyId) != testARN {
		t.Fatal("Decrypt must pin the ARN stored in the wrapped key, not the configured alias")
	}
	if in.EncryptionContext[ContextKey] != base64.StdEncoding.EncodeToString(aad) {
		t.Fatal("Decrypt must send the same encryption context")
	}

	// Another aad: KMS rejects it.
	if got, err := p.Unwrap(context.Background(), w, []byte("other")); !errors.Is(err, kms.ErrInvalid) || got != nil {
		t.Fatalf("wrong aad: want ErrInvalid, got %v", err)
	}
	// A different stored ARN: KMS rejects it as the wrong key.
	w2 := w
	w2.KeyID = otherARN
	if got, err := p.Unwrap(context.Background(), w2, aad); !errors.Is(err, kms.ErrInvalid) || got != nil {
		t.Fatalf("wrong key: want ErrInvalid, got %v", err)
	}
}

func TestUnwrapRejectsAKeyOtherThanStored(t *testing.T) {
	// A service that answers with another key than the one pinned must not yield a key.
	f := &fake{}
	p := newTest(f)
	w, _ := p.Wrap(context.Background(), []byte("0123456789abcdef"), []byte("aad"))
	p.api = decryptReports{f, otherARN}
	if got, err := p.Unwrap(context.Background(), w, []byte("aad")); !errors.Is(err, kms.ErrInvalid) || got != nil {
		t.Fatalf("want ErrInvalid and no key, got %v", err)
	}
}

type decryptReports struct {
	*fake
	arn string
}

func (d decryptReports) Decrypt(ctx context.Context, in *awskmssdk.DecryptInput, o ...func(*awskmssdk.Options)) (*awskmssdk.DecryptOutput, error) {
	out, err := d.fake.Decrypt(ctx, in, o...)
	if out != nil {
		out.KeyId = aws.String(d.arn)
	}
	return out, err
}

func TestInputValidationMakesNoCall(t *testing.T) {
	f := &fake{}
	p := newTest(f)
	ctx := context.Background()
	if _, err := p.Wrap(ctx, nil, []byte("a")); !errors.Is(err, kms.ErrInvalid) {
		t.Errorf("empty plaintext: %v", err)
	}
	if _, err := p.Wrap(ctx, []byte("x"), nil); !errors.Is(err, kms.ErrInvalid) {
		t.Errorf("empty aad: %v", err)
	}
	if _, err := p.Wrap(ctx, make([]byte, maxPlaintext+1), []byte("a")); !errors.Is(err, kms.ErrInvalid) {
		t.Errorf("long plaintext: %v", err)
	}
	good := kms.Wrapped{Provider: Name, KeyID: testARN, Version: Version, Ciphertext: []byte("c")}
	for name, w := range map[string]kms.Wrapped{
		"provider":   {Provider: "vault", KeyID: testARN, Version: Version, Ciphertext: []byte("c")},
		"ciphertext": {Provider: Name, KeyID: testARN, Version: Version},
		"key id":     {Provider: Name, Version: Version, Ciphertext: []byte("c")},
		"version":    {Provider: Name, KeyID: testARN, Version: "7", Ciphertext: []byte("c")},
	} {
		if got, err := p.Unwrap(ctx, w, []byte("a")); err == nil || got != nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := p.Unwrap(ctx, good, nil); !errors.Is(err, kms.ErrInvalid) {
		t.Errorf("empty aad on unwrap: %v", err)
	}
	if len(f.encryptIn)+len(f.decryptIn) != 0 {
		t.Fatal("a rejected request reached KMS")
	}
}

func TestDeadContextIsUnavailableWithoutACall(t *testing.T) {
	f := &fake{}
	p := newTest(f)
	dead, cancel := context.WithCancel(context.Background())
	cancel()
	w := kms.Wrapped{Provider: Name, KeyID: testARN, Version: Version, Ciphertext: []byte("c")}
	_, e1 := p.Current(dead)
	_, e2 := p.Wrap(dead, []byte("x"), []byte("a"))
	_, e3 := p.Unwrap(dead, w, []byte("a"))
	for i, err := range []error{e1, e2, e3} {
		if !errors.Is(err, kms.ErrUnavailable) || !errors.Is(err, context.Canceled) {
			t.Errorf("call %d: %v", i, err)
		}
	}
	if len(f.encryptIn)+len(f.decryptIn) != 0 {
		t.Fatal("a dead context reached KMS")
	}
}

// apiErr is a smithy API error with an HTTP status, as the SDK returns.
type apiErr struct {
	code   string
	msg    string
	status int
}

func (e *apiErr) Error() string                 { return e.code + ": " + e.msg }
func (e *apiErr) ErrorCode() string             { return e.code }
func (e *apiErr) ErrorMessage() string          { return e.msg }
func (e *apiErr) ErrorFault() smithy.ErrorFault { return smithy.FaultUnknown }

// responseErr adds the HTTP status the way the SDK's ResponseError does.
func responseErr(status int, inner error) error {
	return &awshttp.ResponseError{
		ResponseError: &smithyhttp.ResponseError{
			Response: &smithyhttp.Response{Response: &http.Response{StatusCode: status}},
			Err:      inner,
		},
	}
}

type timeoutErr struct{}

func (timeoutErr) Error() string   { return "i/o timeout" }
func (timeoutErr) Timeout() bool   { return true }
func (timeoutErr) Temporary() bool { return true }

func TestErrorMapping(t *testing.T) {
	const secretish = "arn:aws:kms:eu-west-1:123456789012:key/SECRET-MARKER request id 99"
	tests := []struct {
		name string
		err  error
		want kms.Kind
		code string
	}{
		{"invalid state", &kmstypes.KMSInvalidStateException{}, kms.NotConfigured, "KMSInvalidStateException"},
		{"disabled", &kmstypes.DisabledException{}, kms.NotConfigured, "DisabledException"},
		{"not found", &kmstypes.NotFoundException{}, kms.NotConfigured, "NotFoundException"},
		{"access denied", &apiErr{code: "AccessDeniedException", msg: secretish}, kms.Denied, "AccessDeniedException"},
		{"bad token", &apiErr{code: "UnrecognizedClientException", msg: secretish}, kms.Denied, "UnrecognizedClientException"},
		{"expired token", &apiErr{code: "ExpiredTokenException"}, kms.Denied, "ExpiredTokenException"},
		{"invalid ciphertext", &kmstypes.InvalidCiphertextException{}, kms.Invalid, "InvalidCiphertextException"},
		{"incorrect key", &kmstypes.IncorrectKeyException{}, kms.Invalid, "IncorrectKeyException"},
		{"validation", &apiErr{code: "ValidationException"}, kms.Invalid, "ValidationException"},
		{"throttling", &apiErr{code: "ThrottlingException"}, kms.Unavailable, "ThrottlingException"},
		{"limit", &kmstypes.LimitExceededException{}, kms.Unavailable, "LimitExceededException"},
		{"internal", &kmstypes.KMSInternalException{}, kms.Unavailable, "KMSInternalException"},
		{"dependency timeout", &kmstypes.DependencyTimeoutException{}, kms.Unavailable, "DependencyTimeoutException"},
		{"key unavailable", &kmstypes.KeyUnavailableException{}, kms.Unavailable, "KeyUnavailableException"},
		{"503 no code", responseErr(503, errors.New(secretish)), kms.Unavailable, ""},
		{"429 no code", responseErr(429, errors.New(secretish)), kms.Unavailable, ""},
		{"403 no code", responseErr(403, errors.New(secretish)), kms.Denied, ""},
		{"418 unknown", responseErr(418, errors.New(secretish)), kms.Other, ""},
		{"unknown code", &apiErr{code: "SomethingNew", msg: secretish}, kms.Other, "SomethingNew"},
		{"hostile code", &apiErr{code: "bad code with spaces " + secretish}, kms.Other, ""},
		{"connection refused", &net.OpError{Op: "dial", Err: syscall.ECONNREFUSED}, kms.Unavailable, ""},
		{"reset", fmt.Errorf("read: %w", syscall.ECONNRESET), kms.Unavailable, ""},
		{"eof", io.ErrUnexpectedEOF, kms.Unavailable, ""},
		{"net timeout", timeoutErr{}, kms.Unavailable, ""},
		{"opaque", errors.New(secretish), kms.Other, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := newTest(&fake{err: fmt.Errorf("operation error KMS: %w", tc.err)})
			w := kms.Wrapped{Provider: Name, KeyID: testARN, Version: Version, Ciphertext: []byte("c")}
			_, e1 := p.Current(context.Background())
			_, e2 := p.Wrap(context.Background(), []byte("x"), []byte("a"))
			got, e3 := p.Unwrap(context.Background(), w, []byte("a"))
			if got != nil {
				t.Fatal("a failed unwrap returned a key")
			}
			for _, err := range []error{e1, e2, e3} {
				if k := kms.KindOf(err); k != tc.want {
					t.Fatalf("kind = %v, want %v (%v)", k, tc.want, err)
				}
				if strings.Contains(err.Error(), "SECRET-MARKER") || strings.Contains(err.Error(), "123456789012") ||
					strings.Contains(err.Error(), "request id") {
					t.Fatalf("error leaks SDK text: %v", err)
				}
				if tc.code != "" && !strings.Contains(err.Error(), tc.code) {
					t.Fatalf("error lost the AWS code: %v", err)
				}
			}
		})
	}
}

func TestErrorsKeepTheHTTPStatus(t *testing.T) {
	p := newTest(&fake{err: responseErr(503, &apiErr{code: "KMSInternalException"})})
	_, err := p.Wrap(context.Background(), []byte("x"), []byte("a"))
	if err == nil || !strings.Contains(err.Error(), "http 503") || !strings.Contains(err.Error(), "KMSInternalException") {
		t.Fatalf("got %v", err)
	}
}

func TestTimeoutAppliesToEachCall(t *testing.T) {
	blocked := &blockingAPI{}
	p := newProvider(blocked, "alias/x", 30*time.Millisecond)
	start := time.Now()
	_, err := p.Wrap(context.Background(), []byte("x"), []byte("a"))
	if !errors.Is(err, kms.ErrUnavailable) {
		t.Fatalf("want ErrUnavailable, got %v", err)
	}
	if time.Since(start) > 5*time.Second {
		t.Fatal("the call did not time out")
	}
}

type blockingAPI struct{ fake }

func (b *blockingAPI) Encrypt(ctx context.Context, _ *awskmssdk.EncryptInput, _ ...func(*awskmssdk.Options)) (*awskmssdk.EncryptOutput, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

func TestPrintedFormsAreFixed(t *testing.T) {
	p := newTest(&fake{})
	for _, s := range []string{fmt.Sprintf("%v", p), fmt.Sprintf("%+v", p), fmt.Sprintf("%#v", p), fmt.Sprintf("%s", p)} { //nolint:gosimple // exercising every verb
		if s != "awskms.Provider" {
			t.Fatalf("printed %q", s)
		}
	}
}

func TestEncryptionContextIsBase64OfTheAAD(t *testing.T) {
	aad := bytes.Repeat([]byte{0xfe}, 40)
	ec := encryptionContext(aad)
	raw, err := base64.StdEncoding.DecodeString(ec[ContextKey])
	if err != nil || !bytes.Equal(raw, aad) || len(ec) != 1 {
		t.Fatal("encryption context does not round-trip the aad")
	}
}

func TestCredentialsFor(t *testing.T) {
	ctx := context.Background()
	t.Setenv("AWS_ACCESS_KEY_ID", "")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "")
	static := config.NewStaticCredential("v")
	chain := config.NewStaticCredential("")
	var unset config.Credential

	if _, err := credentialsFor(ctx, config.KMSAWS{Region: "us-east-1", AccessKeyID: static, SecretAccessKey: chain}); err == nil {
		t.Error("mixed states accepted")
	}
	if _, err := credentialsFor(ctx, config.KMSAWS{Region: "us-east-1", AccessKeyID: static, SecretAccessKey: unset}); err == nil {
		t.Error("mixed states accepted")
	}
	c, err := credentialsFor(ctx, config.KMSAWS{Region: "us-east-1", AccessKeyID: static, SecretAccessKey: static})
	if err != nil {
		t.Fatal(err)
	}
	got, err := c.Retrieve(ctx)
	if err != nil || got.AccessKeyID != "v" || got.SecretAccessKey != "v" {
		t.Fatalf("static credentials not used: %v", err)
	}
	for name, cr := range map[string]config.Credential{"chain": chain, "unset": unset} {
		if c, err := credentialsFor(ctx, config.KMSAWS{Region: "us-east-1", AccessKeyID: cr, SecretAccessKey: cr}); err != nil || c == nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestNewDoesNotCallTheNetworkAndNeedsKeyAndRegion(t *testing.T) {
	cfg := config.KMSAWS{
		KeyID: "alias/x", Region: "us-east-1", Endpoint: "http://127.0.0.1:1",
		AccessKeyID: config.NewStaticCredential("a"), SecretAccessKey: config.NewStaticCredential("b"),
	}
	p, err := New(context.Background(), cfg, nil)
	if err != nil || p.Name() != Name {
		t.Fatalf("New: %v", err)
	}
	for _, bad := range []config.KMSAWS{{Region: "us-east-1"}, {KeyID: "alias/x"}} {
		if _, err := New(context.Background(), bad, nil); err == nil {
			t.Error("incomplete config accepted")
		}
	}
}
