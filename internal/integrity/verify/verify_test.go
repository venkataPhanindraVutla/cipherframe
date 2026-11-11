package verify

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"testing"
)

func TestClassify(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want Outcome
	}{
		{"nil", nil, Verified},
		{"tampered", ErrTampered, Tampered},
		{"wrapped tampered", fmt.Errorf("segment 3: %w", ErrTampered), Tampered},
		{"untrusted", fmt.Errorf("x: %w", ErrUntrustedKey), UntrustedKey},
		{"malformed", fmt.Errorf("x: %w", ErrMalformed), Malformed},
		{"plain error", errors.New("boom"), CannotSay},
		{"eof", io.ErrUnexpectedEOF, CannotSay},
		{"permission", fs.ErrPermission, CannotSay},
		{"not exist", fs.ErrNotExist, CannotSay},
		{"timeout", context.DeadlineExceeded, CannotSay},
		{"canceled", context.Canceled, CannotSay},
		{"net", &net.OpError{Op: "dial", Err: errors.New("refused")}, CannotSay},
		{"unknown wrapper", Unknown(io.EOF), CannotSay},
		{"cannot-say beats tampered", Unknown(ErrTampered), CannotSay},
		{"joined io then tampered", errors.Join(io.ErrClosedPipe, ErrTampered), Tampered},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := Classify(tc.err); got != tc.want {
				t.Fatalf("Classify = %v, want %v", got, tc.want)
			}
		})
	}
	if Unknown(nil) != nil {
		t.Fatal("Unknown(nil) must be nil")
	}
	if Tampered.String() != "tampered" || CannotSay.String() != "cannot-say" {
		t.Fatal("String")
	}
}
