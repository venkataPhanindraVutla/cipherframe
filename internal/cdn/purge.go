package cdn

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/cloudfront"
	"github.com/aws/aws-sdk-go-v2/service/cloudfront/types"
	"golang.org/x/oauth2/google"

	"github.com/venkataPhanindraVutla/cipherframe/internal/config"
)

// ErrBadPrefix is returned for a prefix that is not one of Cipherframe's object key prefixes.
var ErrBadPrefix = errors.New("cdn: unexpected purge prefix")

// purgePath turns an object key prefix into the path both providers take: a leading slash and a
// trailing wildcard, "/t/<tenant>/a/<asset>/*".
func purgePath(prefix string) (string, error) {
	if !keyRE.MatchString(prefix) || !strings.HasSuffix(prefix, "/") || strings.HasPrefix(prefix, "/") || strings.Contains(prefix, "..") {
		return "", ErrBadPrefix
	}
	return "/" + prefix + "*", nil
}

// NewPurger builds the purger for cfg. The Cloud CDN purger needs Application Default
// Credentials and fails here, at startup, when there are none. cfg must be Enabled.
func NewPurger(ctx context.Context, cfg config.CDN) (Purger, error) {
	switch cfg.Provider {
	case config.CDNCloudFront:
		// CloudFront is a global service whose API is signed for us-east-1.
		ac, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion("us-east-1"))
		if err != nil {
			return nil, errors.New("cdn: cannot load the AWS configuration")
		}
		return NewCloudFrontPurger(cloudfront.NewFromConfig(ac), cfg.CloudFrontDistributionID), nil
	case config.CDNCloudCDN:
		c, err := google.DefaultClient(ctx, "https://www.googleapis.com/auth/cloud-platform")
		if err != nil {
			return nil, errors.New("cdn: cannot load Google Application Default Credentials")
		}
		c.Timeout = purgeTimeout
		return NewCloudCDNPurger(c, computeEndpoint, cfg.CloudCDNProject, cfg.CloudCDNURLMap), nil
	}
	return nil, errors.New("cdn: no provider configured")
}

const (
	purgeTimeout    = 30 * time.Second
	computeEndpoint = "https://compute.googleapis.com"
)

// invalidationAPI is the part of the CloudFront client the purger uses.
type invalidationAPI interface {
	CreateInvalidation(ctx context.Context, in *cloudfront.CreateInvalidationInput, opts ...func(*cloudfront.Options)) (*cloudfront.CreateInvalidationOutput, error)
}

type cloudFrontPurger struct {
	api          invalidationAPI
	distribution string
}

// NewCloudFrontPurger purges through CloudFront invalidations of one distribution.
func NewCloudFrontPurger(api invalidationAPI, distributionID string) Purger {
	return &cloudFrontPurger{api: api, distribution: distributionID}
}

// Purge creates one invalidation with a wildcard path. The caller reference is derived from the
// path, so a retry of the same purge returns the invalidation that already exists instead of
// creating (and being billed for) another.
func (p *cloudFrontPurger) Purge(ctx context.Context, prefix string) error {
	path, err := purgePath(prefix)
	if err != nil {
		return err
	}
	_, err = p.api.CreateInvalidation(ctx, &cloudfront.CreateInvalidationInput{
		DistributionId: &p.distribution,
		InvalidationBatch: &types.InvalidationBatch{
			CallerReference: ptr("cipherframe-purge-" + strings.NewReplacer("/", "-").Replace(strings.Trim(prefix, "/"))),
			Paths:           &types.Paths{Quantity: ptr(int32(1)), Items: []string{path}},
		},
	})
	if err != nil {
		// The SDK error names the operation and the HTTP status, not the request; keep it for the
		// operator's logs (it holds no URL, key or credential).
		return fmt.Errorf("cdn: cloudfront invalidation failed: %w", err)
	}
	return nil
}

func ptr[T any](v T) *T { return &v }

type cloudCDNPurger struct {
	client   *http.Client
	endpoint string
	project  string
	urlMap   string
}

// NewCloudCDNPurger purges through the Compute API's urlMaps.invalidateCache. client carries the
// credentials; endpoint is the API's origin.
func NewCloudCDNPurger(client *http.Client, endpoint, project, urlMap string) Purger {
	return &cloudCDNPurger{client: client, endpoint: strings.TrimSuffix(endpoint, "/"), project: project, urlMap: urlMap}
}

// Purge sends the invalidation. The API accepts it as an operation and runs it asynchronously;
// an accepted request is a success here.
func (p *cloudCDNPurger) Purge(ctx context.Context, prefix string) error {
	path, err := purgePath(prefix)
	if err != nil {
		return err
	}
	body, err := json.Marshal(map[string]string{"path": path})
	if err != nil {
		return err
	}
	u := p.endpoint + "/compute/v1/projects/" + url.PathEscape(p.project) + "/global/urlMaps/" + url.PathEscape(p.urlMap) + "/invalidateCache"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := p.client.Do(req)
	if err != nil {
		// Do's error wraps the URL, which holds no secret here, but report only the class.
		return errors.New("cdn: cloud cdn invalidation request failed")
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("cdn: cloud cdn invalidation refused with status %d", resp.StatusCode)
	}
	return nil
}
