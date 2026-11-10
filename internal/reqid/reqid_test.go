package reqid

import (
	"context"
	"testing"
	"uuid"
)

func TestNewIsUUIDv7(t *testing.T) {
	a, b := New(), New()
	if a == b {
		t.Fatal("duplicate request IDs")
	}
	u, err := uuid.Parse(a)
	if err != nil {
		t.Fatalf("not a UUID: %v", err)
	}
	if u[6]>>4 != 7 {
		t.Fatalf("version = %d, want 7", u[6]>>4)
	}
}

func TestContext(t *testing.T) {
	if _, ok := FromContext(context.Background()); ok {
		t.Fatal("unexpected ID in empty context")
	}
	ctx := WithContext(context.Background(), "abc")
	if got, ok := FromContext(ctx); !ok || got != "abc" {
		t.Fatalf("got %q, %v", got, ok)
	}
	if _, ok := FromContext(WithContext(context.Background(), "")); ok {
		t.Fatal("empty ID reported present")
	}
}

func TestSanitize(t *testing.T) {
	good := New()
	if got, ok := Sanitize(good); !ok || got != good {
		t.Fatalf("Sanitize(%q) = %q, %v", good, got, ok)
	}
	if got, ok := Sanitize("0195C8A2-7B1E-7C3D-9A4F-2E6D8B1C0F35"); !ok || got != "0195c8a2-7b1e-7c3d-9a4f-2e6d8b1c0f35" {
		t.Fatalf("uppercase not normalised: %q, %v", got, ok)
	}
	for _, bad := range []string{
		"", "abc", "0195c8a27b1e7c3d9a4f2e6d8b1c0f35", "{0195c8a2-7b1e-7c3d-9a4f-2e6d8b1c0f35}",
		"urn:uuid:0195c8a2-7b1e-7c3d-9a4f-2e6d8b1c0f35", "0195c8a2-7b1e-7c3d-9a4f-2e6d8b1c0f3g",
		"0195c8a2-7b1e-7c3d-9a4f-2e6d8b1c0f35\n", "0195c8a2-7b1e-7c3d-9a4f-2e6d8b1c0f35 ",
	} {
		if got, ok := Sanitize(bad); ok {
			t.Errorf("Sanitize(%q) accepted as %q", bad, got)
		}
	}
}
