package purge

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"fmt"
	"time"

	"github.com/venkataPhanindraVutla/cipherframe/internal/db"
	"github.com/venkataPhanindraVutla/cipherframe/internal/integrity/deletion"
	"github.com/venkataPhanindraVutla/cipherframe/internal/integrity/dsse"
	"github.com/venkataPhanindraVutla/cipherframe/internal/version"
)

// sealRecord builds the deletion record of the asset (what the tally counted, the keys that were
// destroyed, the manifest's top-level root if there was one), signs it as a DSSE envelope with the
// current signing key and returns the row to store. A signer failure is an ordinary error: the
// caller's transaction rolls back (the keys are not destroyed) and the job retries. Neither the
// payload nor the signature is ever logged.
func (p *Purger) sealRecord(ctx context.Context, asset db.Asset, t *tally, destroyed []db.DestroyedKey, manifestRoot []byte, at time.Time) (db.DeletionRecord, error) {
	in := deletion.Input{
		AssetID: asset.ID.String(), TenantID: asset.TenantID.String(),
		RequestedAt: *asset.DeletionRequestedAt, CompletedAt: at, Reason: asset.DeletionReason,
		PipelineVersion: version.Get().Version, ManifestRoot: manifestRoot,
	}
	for c, n := range t.classes {
		in.Objects = append(in.Objects, deletion.ObjectCount{
			Bucket: string(c.Bucket), Kind: string(c.Kind), Variant: c.Variant, Count: n.Objects, Bytes: n.Bytes,
		})
	}
	for _, k := range destroyed {
		in.Keys = append(in.Keys, deletion.KeyRef{ID: k.ID.String(), Variant: k.Variant.String()})
	}
	built, err := deletion.Build(in)
	if err != nil {
		return db.DeletionRecord{}, fmt.Errorf("purge: build the deletion record: %w", err)
	}
	keyID, sig, err := p.Signer.Sign(ctx, dsse.PAE(deletion.PayloadType, built.Canonical))
	if err != nil {
		return db.DeletionRecord{}, fmt.Errorf("purge: sign the deletion record: %w", err)
	}
	if keyID == "" || len(sig) != ed25519.SignatureSize {
		return db.DeletionRecord{}, errors.New("purge: the signer returned an unusable signature")
	}
	encoded, err := (&dsse.Envelope{
		PayloadType: deletion.PayloadType, Payload: built.Canonical, Signatures: []dsse.Signature{{KeyID: keyID, Sig: sig}},
	}).Encode()
	if err != nil {
		return db.DeletionRecord{}, fmt.Errorf("purge: encode the envelope: %w", err)
	}
	sum := sha256.Sum256(built.Canonical)
	return db.DeletionRecord{
		AssetID: asset.ID, TenantID: asset.TenantID, Reason: asset.DeletionReason,
		RequestedAt: *asset.DeletionRequestedAt, CompletedAt: at, KeyID: keyID, PayloadSHA256: sum[:], Envelope: encoded,
	}, nil
}
