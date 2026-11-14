package main

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/venkataPhanindraVutla/cipherframe/internal/integrity/deletion"
	"github.com/venkataPhanindraVutla/cipherframe/internal/integrity/verify/offline"
)

// maxDeletionRecordBytes bounds a deletion record envelope. A record holds one line per bucket,
// kind and variant and one per content key, so a real one is a few kilobytes.
const maxDeletionRecordBytes = 4 << 20

// runVerifyDeletion checks the signature of a deletion record and prints what it says. The outcome
// is "ours" (a trusted key signed it) or "cannot say" with the reason; a record has no file to
// compare, so there is no "modified". It never touches the network except for --keys-url.
func runVerifyDeletion(recordFile, keysFile, keysURL string, asJSON bool, stdout io.Writer) int {
	keys, err := loadKeys(keysFile, keysURL)
	var res offline.Result
	var signed *offline.SignedDeletion
	if err == nil {
		var env []byte
		if env, err = readLimited(recordFile, maxDeletionRecordBytes); err == nil {
			res, signed = offline.VerifyDeletion(env, keys)
		}
	}
	if err != nil {
		res = offline.FromError(err)
	}
	code := exitCannot
	if res.Outcome == offline.Ours {
		code = exitOurs
	}
	outcome := res.Outcome.String()
	if asJSON {
		doc := struct {
			Outcome string           `json:"outcome"`
			Reason  string           `json:"reason"`
			Detail  string           `json:"detail,omitempty"`
			Record  *deletion.Record `json:"record,omitempty"`
		}{Outcome: replaceSpaces(outcome), Reason: string(res.Reason), Detail: detailIfNotOurs(res)}
		if signed != nil {
			doc.Record = &signed.Record
		}
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(doc)
		return code
	}
	_, _ = fmt.Fprintf(stdout, "%-11s deletion record  (%s%s)\n", outcome, res.Reason, detailIfNotOursText(res))
	if signed == nil {
		return code
	}
	r := signed.Record
	_, _ = fmt.Fprintf(stdout, "asset %s of tenant %s\n", r.AssetID, r.TenantID)
	_, _ = fmt.Fprintf(stdout, "requested %s (%s), completed %s\n", r.RequestedAt, r.Reason, r.CompletedAt)
	_, _ = fmt.Fprintf(stdout, "deleted %d objects, %d bytes\n", r.ObjectsDeleted, r.BytesDeleted)
	for _, o := range r.Objects {
		variant := o.Variant
		if variant == "" {
			variant = "-"
		}
		_, _ = fmt.Fprintf(stdout, "  %-9s %-9s %-9s %6d objects %12d bytes\n", o.Bucket, o.Kind, variant, o.Count, o.Bytes)
	}
	_, _ = fmt.Fprintf(stdout, "content keys destroyed: %d\n", r.ContentKeys.Destroyed)
	for _, k := range r.ContentKeys.Keys {
		_, _ = fmt.Fprintf(stdout, "  %s (%s)\n", k.ID, k.Variant)
	}
	if r.ManifestRoot != "" {
		_, _ = fmt.Fprintf(stdout, "manifest root: %s\n", r.ManifestRoot)
	}
	_, _ = fmt.Fprintf(stdout, "purge run by Cipherframe %s\n", r.PipelineVersion)
	return code
}

func replaceSpaces(s string) string {
	out := []byte(s)
	for i, c := range out {
		if c == ' ' {
			out[i] = '_'
		}
	}
	return string(out)
}

func detailIfNotOurs(r offline.Result) string {
	if r.Outcome == offline.Ours {
		return ""
	}
	return r.Detail
}

func detailIfNotOursText(r offline.Result) string {
	if d := detailIfNotOurs(r); d != "" {
		return ": " + d
	}
	return ""
}
