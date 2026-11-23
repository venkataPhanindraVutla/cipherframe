package purge

import (
	"context"

	"github.com/venkataPhanindraVutla/cipherframe/internal/jobs"
)

// RunCDN works one asset.cdn_purge job with the given attempt numbers.
func RunCDN(d CDNDeps, ctx context.Context, args CDNArgs, attempt, maxAttempts int) error { //nolint:revive // test helper
	return d.handle(ctx, jobs.Job[CDNArgs]{Args: args, Attempt: attempt, MaxAttempts: maxAttempts})
}
