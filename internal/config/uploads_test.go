package config

import (
	"strings"
	"testing"
	"time"
)

func TestUploadDefaults(t *testing.T) {
	c, err := load(base, nil)
	if err != nil {
		t.Fatal(err)
	}
	u := c.Uploads
	if u.EdgePublicURL != "" || u.MaxSourceBytes != 10<<30 || u.TokenTTL != 24*time.Hour || u.PartBytes != 64<<20 {
		t.Fatalf("unexpected defaults: %+v", u)
	}
}

func TestUploadValues(t *testing.T) {
	c, err := load(base.with(
		EnvEdgePublicURL, "https://media.example.com/",
		EnvMaxSourceBytes, "1073741824",
		EnvUploadTokenTTL, "90m",
		EnvUploadPartBytes, "8388608",
	), nil)
	if err != nil {
		t.Fatal(err)
	}
	u := c.Uploads
	if u.EdgePublicURL != "https://media.example.com" || u.MaxSourceBytes != 1<<30 ||
		u.TokenTTL != 90*time.Minute || u.PartBytes != 8<<20 {
		t.Fatalf("unexpected values: %+v", u)
	}
}

func TestUploadValidation(t *testing.T) {
	for name, tc := range map[string]struct {
		kv   []string
		want string
	}{
		"edge url without scheme":    {[]string{EnvEdgePublicURL, "media.example.com"}, EnvEdgePublicURL},
		"edge url with a path":       {[]string{EnvEdgePublicURL, "https://media.example.com/edge"}, EnvEdgePublicURL},
		"edge url with credentials":  {[]string{EnvEdgePublicURL, "https://u:p@media.example.com"}, EnvEdgePublicURL},
		"edge url with a query":      {[]string{EnvEdgePublicURL, "https://media.example.com?x=1"}, EnvEdgePublicURL},
		"max source not a number":    {[]string{EnvMaxSourceBytes, "10GiB"}, EnvMaxSourceBytes},
		"max source zero":            {[]string{EnvMaxSourceBytes, "0"}, EnvMaxSourceBytes},
		"max source above ceiling":   {[]string{EnvMaxSourceBytes, "9999999999999999"}, EnvMaxSourceBytes},
		"ttl not a duration":         {[]string{EnvUploadTokenTTL, "soon"}, EnvUploadTokenTTL},
		"ttl too short":              {[]string{EnvUploadTokenTTL, "5s"}, EnvUploadTokenTTL},
		"ttl too long":               {[]string{EnvUploadTokenTTL, "9999h"}, EnvUploadTokenTTL},
		"part below the S3 minimum":  {[]string{EnvUploadPartBytes, "1048576"}, EnvUploadPartBytes},
		"part above the S3 maximum":  {[]string{EnvUploadPartBytes, "9999999999"}, EnvUploadPartBytes},
		"too many parts at the size": {[]string{EnvMaxSourceBytes, "1099511627776", EnvUploadPartBytes, "5242880"}, "at most 10000 parts"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := load(base.with(tc.kv...), nil)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want it to mention %q", err, tc.want)
			}
		})
	}
}
