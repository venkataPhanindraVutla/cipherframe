package uploads

import (
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/venkataPhanindraVutla/cipherframe/internal/config"
	"github.com/venkataPhanindraVutla/cipherframe/internal/db"
	"github.com/venkataPhanindraVutla/cipherframe/internal/errs"
)

// MinPartBytes is the smallest part S3 accepts for any part but the last.
const MinPartBytes = config.MinUploadPartBytes

// Limits are the configured bounds on uploads.
type Limits struct {
	// MaxSourceBytes is the largest source an asset may declare (checked at create and commit).
	MaxSourceBytes int64
	// PartBytes is the part size multipart clients are told to use; no part may be larger.
	PartBytes int64
	// TokenTTL is how long an upload token works.
	TokenTTL time.Duration
}

// LimitsFrom builds Limits from the loaded configuration.
func LimitsFrom(c config.Uploads) Limits {
	return Limits{MaxSourceBytes: c.MaxSourceBytes, PartBytes: c.PartBytes, TokenTTL: c.TokenTTL}
}

// Validate checks the limits themselves.
func (l Limits) Validate() error {
	switch {
	case l.MaxSourceBytes < 1:
		return fmt.Errorf("uploads: max source size must be positive")
	case l.PartBytes < MinPartBytes || l.PartBytes > config.MaxUploadPartBytes:
		return fmt.Errorf("uploads: part size must be between %d and %d bytes", MinPartBytes, config.MaxUploadPartBytes)
	case l.TokenTTL < time.Second:
		return fmt.Errorf("uploads: token TTL must be positive")
	case (l.MaxSourceBytes+l.PartBytes-1)/l.PartBytes > config.MaxUploadParts:
		return fmt.Errorf("uploads: part size is too small for the maximum source size")
	}
	return nil
}

// CheckSize rejects a declared size outside 1 byte to MaxSourceBytes. It backs both the create
// and the commit check.
func (l Limits) CheckSize(size int64) error {
	switch {
	case size < 1:
		return errs.New(errs.InvalidRequest, "size_bytes must be at least 1.")
	case size > l.MaxSourceBytes:
		return errs.New(errs.PayloadTooLarge, "size_bytes exceeds the maximum source size.")
	}
	return nil
}

// contentTypePattern is a bare lower-case media type: no parameters, no whitespace.
var contentTypePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9!#$&^_.+-]{0,126}/[a-z0-9][a-z0-9!#$&^_.+-]{0,126}$`)

// CheckContentType validates an optional content type. The empty string is allowed. The value
// becomes object metadata only; the probe step (M3-3) decides what the media really is.
func CheckContentType(ct string) error {
	if ct == "" {
		return nil
	}
	if len(ct) > 255 || !contentTypePattern.MatchString(strings.ToLower(ct)) || ct != strings.ToLower(ct) {
		return errs.New(errs.InvalidRequest, "content_type must be a lower-case media type such as video/mp4.")
	}
	return nil
}

// CheckPartNumber validates a part number (1 to 10000).
func CheckPartNumber(n int) error {
	if n < 1 || n > int(config.MaxUploadParts) {
		return errs.New(errs.InvalidRequest, "part_number must be between 1 and 10000.")
	}
	return nil
}

// CheckPart validates one incoming part against the asset: its size must be positive and at most
// PartBytes, and together with the other received parts must not exceed the declared size.
// otherBytes is the total size of the asset's other received parts.
func (l Limits) CheckPart(size, declared, otherBytes int64) error {
	switch {
	case size < 1:
		return errs.New(errs.InvalidRequest, "A part must not be empty.")
	case size > l.PartBytes:
		return errs.New(errs.PayloadTooLarge, "The part is larger than the part size for this upload.")
	case otherBytes+size > declared:
		return errs.New(errs.InvalidRequest, "The parts together are larger than the declared size.")
	}
	return nil
}

// ValidateParts checks the received parts of a multipart upload before completing it: numbered
// 1..N without gaps, every part but the last at least MinPartBytes and none above partBytes, and
// the sizes adding up to the declared size. The errors are conflicts that name the problem
// without any object-store detail.
func ValidateParts(parts []db.UploadPart, declared, partBytes int64) error {
	if len(parts) == 0 {
		return errs.New(errs.Conflict, "No parts have been uploaded.")
	}
	var total int64
	for i, p := range parts {
		last := i == len(parts)-1
		switch {
		case p.PartNumber != i+1:
			return errs.New(errs.Conflict, fmt.Sprintf("Part %d is missing.", i+1))
		case p.SizeBytes > partBytes:
			return errs.New(errs.Conflict, fmt.Sprintf("Part %d is larger than the part size.", p.PartNumber))
		case !last && p.SizeBytes < MinPartBytes:
			return errs.New(errs.Conflict, fmt.Sprintf("Part %d is smaller than the 5 MiB minimum for a part that is not the last.", p.PartNumber))
		}
		total += p.SizeBytes
	}
	if total != declared {
		return errs.New(errs.Conflict, "The uploaded parts do not add up to the declared size.")
	}
	return nil
}
