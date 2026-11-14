package pipeline

import (
	"context"
	"fmt"

	"github.com/venkataPhanindraVutla/cipherframe/internal/db"
	"github.com/venkataPhanindraVutla/cipherframe/internal/storage"
	"github.com/venkataPhanindraVutla/cipherframe/internal/storage/keys"
)

// cleanDelivery removes every HLS object the asset's original variant has in the delivery bucket
// and every artifact row it has, and the asset's integrity manifest. The masked variant is not
// touched: asset.process only runs before it exists.
func (p *Processor) cleanDelivery(ctx context.Context, asset db.Asset) error {
	if err := p.cleanVariant(ctx, asset, keys.Original); err != nil {
		return err
	}
	// The manifest describes the objects just removed; a stale one must never survive a retry.
	if _, err := p.Repo.DeleteManifest(ctx, asset.ID); err != nil {
		return err
	}
	return nil
}

// cleanVariant removes every HLS object of one variant and its artifact rows, and nothing of the
// other variant (their prefixes do not overlap). It enumerates the prefix from the key layout
// (keys.VariantHLSPrefix), not from the registry, so it also removes objects an attempt uploaded
// but never got to register. The content key is not touched: it is reused.
func (p *Processor) cleanVariant(ctx context.Context, asset db.Asset, variant keys.Variant) error {
	prefix := keys.VariantHLSPrefix(asset.TenantID, asset.ID, variant)
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
	_, err := p.Repo.DeleteHLSArtifacts(ctx, asset.ID, variant.String())
	return err
}
