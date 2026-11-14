package config

import "strconv"

// Retention variables (M6-4, ADR 0040).
const (
	EnvAccessLogRetentionDays = "CIPHERFRAME_ACCESS_LOG_RETENTION_DAYS"
)

// Retention defaults and bounds.
const (
	// DefaultAccessLogRetentionDays is how long the access trail and the anomaly events are kept
	// (ADR 0040).
	DefaultAccessLogRetentionDays = 90
	// MinAccessLogRetentionDays and MaxAccessLogRetentionDays bound CIPHERFRAME_ACCESS_LOG_RETENTION_DAYS:
	// a day to ten years.
	MinAccessLogRetentionDays = 1
	MaxAccessLogRetentionDays = 3650
)

// Retention configures how long records about playback are kept. Assets are kept until deleted,
// unless a time-to-live applies (a per-asset or tenant setting, not a deployment one).
type Retention struct {
	// AccessLogDays is the age, in days, after which rows of the access trail (playback_access_log)
	// and of the anomaly events (playback_events) are removed.
	AccessLogDays int
}

func (l *loader) retention() Retention {
	r := Retention{AccessLogDays: DefaultAccessLogRetentionDays}
	v := l.plain(EnvAccessLogRetentionDays, "")
	if v == "" {
		return r
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < MinAccessLogRetentionDays || n > MaxAccessLogRetentionDays {
		l.errf("%s must be a whole number of days from %d to %d", EnvAccessLogRetentionDays,
			MinAccessLogRetentionDays, MaxAccessLogRetentionDays)
		return r
	}
	r.AccessLogDays = n
	return r
}
