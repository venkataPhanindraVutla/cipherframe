package pipeline

import (
	"context"
	"fmt"

	"github.com/venkataPhanindraVutla/cipherframe/internal/db"
	"github.com/venkataPhanindraVutla/cipherframe/internal/storage"
	"github.com/venkataPhanindraVutla/cipherframe/internal/storage/keys"
)

// cleanDelivery removes every HLS object the asset has in the delivery bucket and every artifact
// row it has, and the asset's integrity manifest. It enumerates the prefix from the key layout
// (keys.HLSPrefix), not from the registry, so it also removes objects an attempt uploaded but never
// got to register. The content key is not touched: it is reused.
func (p *Processor) cleanDelivery(ctx context.Context, asset db.Asset) error {
	prefix := keys.HLSPrefix(asset.TenantID, asset.ID)
	var batch []string
	flush := func() error {
		if len(batch) == 0 {
			return nil
		}
		err := p.Delivery.DeleteBatch(ctx, batch)
		batch = batch[:0]
		return err
	}
	for obj, err := range storage.ListAll(ctx, p.Delivery, prefix) {
		if err != nil {
			return fmt.Errorf("pipeline: list delivery objects: %w", err)
		}
		batch = append(batch, obj.Key)
		if len(batch) >= storage.MaxDeleteBatch {
			if err := flush(); err != nil {
				return fmt.Errorf("pipeline: delete delivery objects: %w", err)
			}
		}
	}
	if err := flush(); err != nil {
		return fmt.Errorf("pipeline: delete delivery objects: %w", err)
	}
	if _, err := p.Repo.DeleteHLSArtifacts(ctx, asset.ID); err != nil {
		return err
	}
	// The manifest describes the objects just removed; a stale one must never survive a retry.
	if _, err := p.Repo.DeleteManifest(ctx, asset.ID); err != nil {
		return err
	}
	return nil
}
