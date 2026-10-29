package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/url"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploggrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploghttp"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	otellog "go.opentelemetry.io/otel/log"
	sdklog "go.opentelemetry.io/otel/sdk/log"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
)

// sendTest emits one span, one log with the same trace id, and one gauge, then prints
// trace_id=<hex>. It returns an error if any exporter fails to deliver.
func sendTest(ctx context.Context, endpoint, key, protocol string, out io.Writer) error {
	u, err := url.Parse(endpoint)
	if err != nil || u.Host == "" {
		return fmt.Errorf("bad --endpoint %q (want http(s)://host:port)", endpoint)
	}
	hdr := map[string]string{"Authorization": "Bearer " + key}
	insecure := u.Scheme == "http"

	var te sdktrace.SpanExporter
	var le sdklog.Exporter
	var me sdkmetric.Exporter
	switch protocol {
	case "http":
		topts := []otlptracehttp.Option{otlptracehttp.WithEndpoint(u.Host), otlptracehttp.WithHeaders(hdr), otlptracehttp.WithRetry(otlptracehttp.RetryConfig{})}
		lopts := []otlploghttp.Option{otlploghttp.WithEndpoint(u.Host), otlploghttp.WithHeaders(hdr), otlploghttp.WithRetry(otlploghttp.RetryConfig{})}
		mopts := []otlpmetrichttp.Option{otlpmetrichttp.WithEndpoint(u.Host), otlpmetrichttp.WithHeaders(hdr), otlpmetrichttp.WithRetry(otlpmetrichttp.RetryConfig{})}
		if insecure {
			topts, lopts, mopts = append(topts, otlptracehttp.WithInsecure()), append(lopts, otlploghttp.WithInsecure()), append(mopts, otlpmetrichttp.WithInsecure())
		}
		if te, err = otlptracehttp.New(ctx, topts...); err != nil {
			return err
		}
		if le, err = otlploghttp.New(ctx, lopts...); err != nil {
			return err
		}
		if me, err = otlpmetrichttp.New(ctx, mopts...); err != nil {
			return err
		}
	case "grpc":
		topts := []otlptracegrpc.Option{otlptracegrpc.WithEndpoint(u.Host), otlptracegrpc.WithHeaders(hdr), otlptracegrpc.WithRetry(otlptracegrpc.RetryConfig{})}
		lopts := []otlploggrpc.Option{otlploggrpc.WithEndpoint(u.Host), otlploggrpc.WithHeaders(hdr), otlploggrpc.WithRetry(otlploggrpc.RetryConfig{})}
		mopts := []otlpmetricgrpc.Option{otlpmetricgrpc.WithEndpoint(u.Host), otlpmetricgrpc.WithHeaders(hdr), otlpmetricgrpc.WithRetry(otlpmetricgrpc.RetryConfig{})}
		if insecure {
			topts, lopts, mopts = append(topts, otlptracegrpc.WithInsecure()), append(lopts, otlploggrpc.WithInsecure()), append(mopts, otlpmetricgrpc.WithInsecure())
		}
		if te, err = otlptracegrpc.New(ctx, topts...); err != nil {
			return err
		}
		if le, err = otlploggrpc.New(ctx, lopts...); err != nil {
			return err
		}
		if me, err = otlpmetricgrpc.New(ctx, mopts...); err != nil {
			return err
		}
	default:
		return fmt.Errorf("unknown --protocol %q (grpc|http)", protocol)
	}

	res := resource.NewSchemaless(semconv.ServiceName("wtctl-send-test"))
	tp := sdktrace.NewTracerProvider(sdktrace.WithResource(res), sdktrace.WithBatcher(te))
	lp := sdklog.NewLoggerProvider(sdklog.WithResource(res), sdklog.WithProcessor(sdklog.NewBatchProcessor(le)))
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithResource(res), sdkmetric.WithReader(sdkmetric.NewPeriodicReader(me, sdkmetric.WithInterval(time.Hour))))

	sctx, span := tp.Tracer("wtctl").Start(ctx, "wtctl.send-test")
	traceID := span.SpanContext().TraceID()
	var rec otellog.Record
	rec.SetTimestamp(time.Now())
	rec.SetSeverity(otellog.SeverityInfo)
	rec.SetBody(attribute.StringValue("wtctl send-test"))
	lp.Logger("wtctl").Emit(sctx, rec) // span context in ctx gives the record its trace id
	g, err := mp.Meter("wtctl").Float64Gauge("wtctl.send_test.gauge")
	if err != nil {
		return err
	}
	g.Record(sctx, 1)
	span.End()

	// Flush and shut down every provider; the export error is the exit status.
	var errs []error
	for _, f := range []func(context.Context) error{tp.Shutdown, lp.Shutdown, mp.Shutdown} {
		errs = append(errs, f(ctx))
	}
	if err := errors.Join(errs...); err != nil {
		return err
	}
	fmt.Fprintf(out, "trace_id=%s\n", traceID)
	return nil
}
