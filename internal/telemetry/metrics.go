package telemetry

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// Fixed label values. A label is never built from request or database data.
const (
	// Key endpoint outcomes.
	KeyServed   = "served"
	KeyDenied   = "denied"
	KeyNotFound = "not_found"
	KeyError    = "error"

	// Refusal reasons.
	ReasonQuotaExceeded = "quota_exceeded"
	ReasonRateLimited   = "rate_limited"

	// Job and transcode outcomes.
	OutcomeSucceeded = "succeeded"
	OutcomeFailed    = "failed"
	OutcomeCancelled = "cancelled"
	OutcomeSnoozed   = "snoozed"

	// Encoder fallback stages: the startup test, or one job's encode.
	StageStartup = "startup"
	StageJob     = "job"

	// RouteOther labels a request that matched no route.
	RouteOther = "other"
)

// longBuckets suit jobs and transcodes: one second to about 34 minutes.
var longBuckets = prometheus.ExponentialBuckets(1, 2, 12)

type metrics struct {
	httpDuration      *prometheus.HistogramVec
	jobDuration       *prometheus.HistogramVec
	transcodeDuration *prometheus.HistogramVec
	transcodeMedia    prometheus.Counter
	encoderFallbacks  *prometheus.CounterVec
	keyDuration       *prometheus.HistogramVec
	anomalies         *prometheus.CounterVec
	refusals          *prometheus.CounterVec
	tenantLabel       bool
}

func newMetrics(reg *prometheus.Registry, tenantLabel bool) *metrics {
	refusalLabels := []string{"reason"}
	if tenantLabel {
		refusalLabels = append(refusalLabels, "tenant_id")
	}
	m := &metrics{
		tenantLabel: tenantLabel,
		httpDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name: "cipherframe_http_request_duration_seconds", Help: "HTTP request duration by route template.",
			Buckets: prometheus.DefBuckets,
		}, []string{"service", "route", "method", "status_class"}),
		jobDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name: "cipherframe_job_duration_seconds", Help: "Duration of one job attempt by kind and outcome.",
			Buckets: longBuckets,
		}, []string{"kind", "outcome"}),
		transcodeDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name: "cipherframe_transcode_duration_seconds", Help: "Duration of one FFmpeg transcode of a whole rendition ladder.",
			Buckets: longBuckets,
		}, []string{"outcome", "encoder"}),
		encoderFallbacks: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "cipherframe_encoder_fallbacks_total", Help: "Times a hardware encoder was replaced by software, by encoder and stage.",
		}, []string{"encoder", "stage"}),
		transcodeMedia: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "cipherframe_transcode_seconds_of_media_total", Help: "Seconds of source media transcoded successfully.",
		}),
		keyDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name: "cipherframe_key_request_duration_seconds", Help: "Duration of content key requests at the edge by outcome.",
			Buckets: prometheus.DefBuckets,
		}, []string{"outcome"}),
		anomalies: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "cipherframe_anomalies_total", Help: "Playback anomaly events recorded, by kind.",
		}, []string{"kind"}),
		refusals: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "cipherframe_refusals_total", Help: "Requests refused by a quota or a rate limit.",
		}, refusalLabels),
	}
	reg.MustRegister(m.httpDuration, m.jobDuration, m.transcodeDuration, m.transcodeMedia, m.encoderFallbacks, m.keyDuration, m.anomalies, m.refusals)
	return m
}

// ObserveHTTP records one finished request.
func ObserveHTTP(service, route, method, statusClass string, d time.Duration) {
	if t := cur(); t != nil {
		t.m.httpDuration.WithLabelValues(service, route, method, statusClass).Observe(d.Seconds())
	}
}

// ObserveJob records one job attempt. outcome is one of the Outcome constants.
func ObserveJob(kind, outcome string, d time.Duration) {
	if t := cur(); t != nil {
		t.m.jobDuration.WithLabelValues(kind, outcome).Observe(d.Seconds())
	}
}

// EncoderFallback counts one switch from a hardware encoder to software. encoder is one of the
// fixed encoder names and stage is StageStartup or StageJob.
func EncoderFallback(encoder, stage string) {
	if t := cur(); t != nil {
		t.m.encoderFallbacks.WithLabelValues(encoder, stage).Inc()
	}
}

// ObserveTranscode records one transcode. encoder is one of the fixed encoder names (five values,
// so the label stays small). media is the source duration; it is counted only on success.
func ObserveTranscode(outcome, encoder string, d, media time.Duration) {
	if t := cur(); t != nil {
		t.m.transcodeDuration.WithLabelValues(outcome, encoder).Observe(d.Seconds())
		if outcome == OutcomeSucceeded {
			t.m.transcodeMedia.Add(media.Seconds())
		}
	}
}

// ObserveKeyRequest records one key request. outcome is one of the Key constants.
func ObserveKeyRequest(outcome string, d time.Duration) {
	if t := cur(); t != nil {
		t.m.keyDuration.WithLabelValues(outcome).Observe(d.Seconds())
	}
}

// Anomaly counts one recorded anomaly event. kind is a fixed event kind (package db).
func Anomaly(kind string) {
	if t := cur(); t != nil {
		t.m.anomalies.WithLabelValues(kind).Inc()
	}
}

// Refusal counts one refusal. tenant is added as the tenant_id label only when
// CIPHERFRAME_METRICS_TENANT_LABEL is on, and ignored otherwise.
func Refusal(reason, tenant string) {
	t := cur()
	if t == nil {
		return
	}
	if t.m.tenantLabel {
		t.m.refusals.WithLabelValues(reason, tenant).Inc()
		return
	}
	t.m.refusals.WithLabelValues(reason).Inc()
}
