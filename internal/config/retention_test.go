package config

import (
	"strings"
	"testing"
)

func TestRetentionDefaultAndOverride(t *testing.T) {
	c, err := load(base, nil)
	if err != nil || c.Retention.AccessLogDays != 90 {
		t.Fatalf("default = %+v, %v", c.Retention, err)
	}
	for in, want := range map[string]int{"1": 1, "30": 30, "3650": 3650} {
		c, err := load(base.with(EnvAccessLogRetentionDays, in), nil)
		if err != nil || c.Retention.AccessLogDays != want {
			t.Errorf("%s: %+v, %v", in, c.Retention, err)
		}
	}
}

func TestRetentionInvalid(t *testing.T) {
	for _, v := range []string{"0", "-1", "3651", "ninety", "1.5", "30d", " "} {
		_, err := load(base.with(EnvAccessLogRetentionDays, v), nil)
		if err == nil || !strings.Contains(err.Error(), EnvAccessLogRetentionDays) {
			t.Errorf("%q: error = %v", v, err)
		}
		if err != nil && strings.Contains(err.Error(), v) && strings.TrimSpace(v) != "" && len(v) > 2 {
			t.Errorf("%q: the error quotes the value: %v", v, err)
		}
	}
}
