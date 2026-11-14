package main

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/venkataPhanindraVutla/cipherframe/internal/integrity/verify/offline"
)

// Timestamp statuses (ADR 0041).
const (
	tsAnchored   = "anchored"
	tsUnanchored = "unanchored"
	tsInvalid    = "invalid"
)

// tsStatus is the outcome of checking the --timestamp file. Anchoring is an extra: an invalid
// timestamp makes the exit code 2 (cannot say) and is never "modified".
type tsStatus struct {
	Status  string `json:"status"`
	GenTime string `json:"gen_time,omitempty"`
	TSAURL  string `json:"tsa_url,omitempty"`
	Reason  string `json:"reason,omitempty"`
}

func (t *tsStatus) text() string {
	switch t.Status {
	case tsAnchored:
		return fmt.Sprintf("anchored  %s  (%s)", t.GenTime, t.TSAURL)
	case tsUnanchored:
		return tsUnanchored
	}
	return "timestamp invalid (" + t.Reason + ")"
}

// checkTimestamp verifies the timestamp file against the manifest envelope. envelope is nil when
// the manifest could not be read. caFile, when set, replaces the system roots.
func checkTimestamp(file, caFile string, envelope []byte) *tsStatus {
	invalid := func(format string, a ...any) *tsStatus {
		return &tsStatus{Status: tsInvalid, Reason: fmt.Sprintf(format, a...)}
	}
	data, err := readLimited(file, offline.MaxTimestampBytes)
	if err != nil {
		return invalid("cannot read the timestamp file: %v", err)
	}
	if isNotAnchored(data) {
		return &tsStatus{Status: tsUnanchored}
	}
	doc, err := offline.ParseTimestamp(data)
	if err != nil {
		return invalid("%v", err)
	}
	if envelope == nil {
		return invalid("the manifest could not be read")
	}
	roots, err := loadRoots(caFile)
	if err != nil {
		return invalid("%v", err)
	}
	gen, err := offline.VerifyTimestamp(envelope, *doc, roots)
	if err != nil {
		return invalid("%s", offline.TimestampReason(err))
	}
	return &tsStatus{Status: tsAnchored, GenTime: gen.UTC().Format(time.RFC3339), TSAURL: doc.TSAURL}
}

// isNotAnchored recognises what the API answers for a manifest without a token (the problem with
// code not_anchored, saved by curl), and an empty file.
func isNotAnchored(data []byte) bool {
	if len(bytes.TrimSpace(data)) == 0 {
		return true
	}
	var p struct {
		Code string `json:"code"`
	}
	return json.Unmarshal(data, &p) == nil && p.Code == "not_anchored"
}

func loadRoots(caFile string) (*x509.CertPool, error) {
	if caFile == "" {
		pool, err := x509.SystemCertPool()
		if err != nil {
			return nil, errors.New("the system trust store is not available; pass --tsa-ca")
		}
		return pool, nil
	}
	pem, err := readLimited(caFile, offline.MaxTimestampBytes)
	if err != nil {
		return nil, fmt.Errorf("cannot read --tsa-ca: %w", err)
	}
	return offline.RootsFromPEM(pem)
}

func printTimestamp(w io.Writer, t *tsStatus) {
	if t != nil {
		_, _ = fmt.Fprintln(w, t.text())
	}
}
