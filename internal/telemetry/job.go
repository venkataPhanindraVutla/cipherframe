package telemetry

import (
	"context"
	"encoding/json"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"
	"go.opentelemetry.io/otel/trace/noop"
)

// metaTraceparent is the job metadata key that carries the W3C traceparent from the process that
// inserted a job to the worker that runs it.
const metaTraceparent = "traceparent"

var noopTracer = noop.NewTracerProvider().Tracer(tracerName)

func tracer() trace.Tracer {
	if t := cur(); t != nil {
		return t.tracer
	}
	return noopTracer
}

// JobMetadata returns the JSON object to store in a job's metadata so that the worker's span
// continues the inserting request's trace, or nil when ctx carries no sampled trace (tracing off,
// or no active span).
func JobMetadata(ctx context.Context) []byte {
	carrier := propagation.MapCarrier{}
	propagator.Inject(ctx, carrier)
	tp := carrier.Get(metaTraceparent)
	if tp == "" {
		return nil
	}
	b, err := json.Marshal(map[string]string{metaTraceparent: tp})
	if err != nil {
		return nil
	}
	return b
}

// StartJob starts the span of one job attempt, a child of the trace stored in the job's metadata
// (when there is one). kind is the job kind, a fixed identifier. The returned function ends the
// span and records cipherframe_job_duration_seconds; outcome is one of the Outcome constants.
func StartJob(ctx context.Context, kind string, metadata []byte, attempt int) (context.Context, func(outcome string)) {
	var meta map[string]string
	if len(metadata) > 0 && json.Unmarshal(metadata, &meta) == nil {
		ctx = propagator.Extract(ctx, propagation.MapCarrier(meta))
	}
	start := time.Now()
	ctx, span := tracer().Start(ctx, "job "+kind, trace.WithSpanKind(trace.SpanKindConsumer), trace.WithAttributes(
		attribute.String("cipherframe.job.kind", kind),
		attribute.Int("cipherframe.job.attempt", attempt),
	))
	return ctx, func(outcome string) {
		span.SetAttributes(attribute.String("cipherframe.job.outcome", outcome))
		if outcome == OutcomeFailed {
			span.SetStatus(codes.Error, "")
		}
		span.End()
		ObserveJob(kind, outcome, time.Since(start))
	}
}

// StartFFmpeg starts the span "ffmpeg <operation>" as a child of the span in ctx. operation is a
// fixed name (transcode, probe), never a command line, path or URL. The returned function ends
// the span, marking it failed when err is not nil; the error text is not recorded.
func StartFFmpeg(ctx context.Context, operation string) (context.Context, func(err error)) {
	ctx, span := tracer().Start(ctx, "ffmpeg "+operation, trace.WithAttributes(attribute.String("cipherframe.ffmpeg.operation", operation)))
	return ctx, func(err error) {
		if err != nil {
			span.SetStatus(codes.Error, "")
		}
		span.End()
	}
}
