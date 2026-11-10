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
