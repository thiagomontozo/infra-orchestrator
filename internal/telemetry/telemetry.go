package telemetry

import (
	"context"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/thiagomontozo/infra-orchestrator/internal/store"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"net/http"
)

func Init(ctx context.Context, name string, enabled bool) (func(context.Context) error, error) {
	if !enabled {
		return func(context.Context) error { return nil }, nil
	}
	exp, e := otlptracehttp.New(ctx)
	if e != nil {
		return nil, e
	}
	r := resource.NewWithAttributes("", attribute.String("service.name", name))
	provider := sdktrace.NewTracerProvider(sdktrace.WithBatcher(exp), sdktrace.WithResource(r), sdktrace.WithSampler(sdktrace.ParentBased(sdktrace.TraceIDRatioBased(0.1))))
	otel.SetTracerProvider(provider)
	return provider.Shutdown, nil
}

type Collector struct {
	DB                           *store.DB
	operations, hosts, resources *prometheus.Desc
}

func (c *Collector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.operations
	ch <- c.hosts
	ch <- c.resources
}
func (c *Collector) Collect(ch chan<- prometheus.Metric) {
	ctx, cancel := context.WithTimeout(context.Background(), 2e9)
	defer cancel()
	rows, e := c.DB.Pool.Query(ctx, "SELECT state,count(*) FROM operations GROUP BY state")
	if e == nil {
		for rows.Next() {
			var state string
			var n float64
			if rows.Scan(&state, &n) == nil {
				ch <- prometheus.MustNewConstMetric(c.operations, prometheus.GaugeValue, n, state)
			}
		}
		rows.Close()
	}
	for _, v := range []struct {
		query string
		desc  *prometheus.Desc
	}{{"SELECT document->>'state',count(*) FROM hosts GROUP BY document->>'state'", c.hosts}, {"SELECT document->>'health',count(*) FROM resources GROUP BY document->>'health'", c.resources}} {
		rows, e := c.DB.Pool.Query(ctx, v.query)
		if e != nil {
			continue
		}
		for rows.Next() {
			var state string
			var n float64
			if rows.Scan(&state, &n) == nil {
				ch <- prometheus.MustNewConstMetric(v.desc, prometheus.GaugeValue, n, state)
			}
		}
		rows.Close()
	}
}
func Handler(db *store.DB) http.Handler {
	reg := prometheus.NewRegistry()
	reg.MustRegister(prometheus.NewGoCollector(), prometheus.NewProcessCollector(prometheus.ProcessCollectorOpts{}), &Collector{DB: db, operations: prometheus.NewDesc("infra_operations", "Durable operations by state", []string{"state"}, nil), hosts: prometheus.NewDesc("infra_hosts", "Hosts by connection state", []string{"state"}, nil), resources: prometheus.NewDesc("infra_resources", "Resources by health", []string{"health"}, nil)})
	return promhttp.HandlerFor(reg, promhttp.HandlerOpts{})
}
