package relay

import (
	"fmt"
	"log/slog"
	"net/http"
	"sync/atomic"
	"time"
)

// Observability: structured per-request logging + a Prometheus-style /metrics
// endpoint. Content-blind — it records method, path, status, and latency, never
// request/response bodies or tokens, so it's safe on the E2EE relay.

type metrics struct {
	total    atomic.Int64
	inFlight atomic.Int64
	byClass  [6]atomic.Int64 // index = status/100 (1xx…5xx); [0] unused
}

func newMetrics() *metrics { return &metrics{} }

// statusRecorder captures the response status for logging/metrics while staying
// transparent to the handler. It passes Flush through and exposes Unwrap so the
// SSE handler's http.ResponseController (SetWriteDeadline / Flush) still reaches
// the real ResponseWriter — otherwise streaming would break.
type statusRecorder struct {
	http.ResponseWriter
	status int
	wrote  bool
}

func (r *statusRecorder) WriteHeader(code int) {
	if !r.wrote {
		r.status = code
		r.wrote = true
	}
	r.ResponseWriter.WriteHeader(code)
}

func (r *statusRecorder) Write(b []byte) (int, error) {
	if !r.wrote {
		r.status = http.StatusOK
		r.wrote = true
	}
	return r.ResponseWriter.Write(b)
}

func (r *statusRecorder) Unwrap() http.ResponseWriter { return r.ResponseWriter }

func (r *statusRecorder) Flush() {
	if f, ok := r.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (m *metrics) observe(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		m.inFlight.Add(1)
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)
		m.inFlight.Add(-1)
		m.total.Add(1)
		if class := rec.status / 100; class >= 1 && class <= 5 {
			m.byClass[class].Add(1)
		}
		slog.Info("request",
			"method", r.Method,
			"path", r.URL.Path,
			"status", rec.status,
			"dur_ms", time.Since(start).Milliseconds(),
			"remote", r.RemoteAddr,
		)
	})
}

func (m *metrics) handler(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	fmt.Fprintf(w, "# HELP hive_relay_requests_total Total HTTP requests handled.\n")
	fmt.Fprintf(w, "# TYPE hive_relay_requests_total counter\n")
	fmt.Fprintf(w, "hive_relay_requests_total %d\n", m.total.Load())
	fmt.Fprintf(w, "# HELP hive_relay_requests_by_class HTTP requests by status class.\n")
	fmt.Fprintf(w, "# TYPE hive_relay_requests_by_class counter\n")
	for c := 1; c <= 5; c++ {
		fmt.Fprintf(w, "hive_relay_requests_by_class{class=\"%dxx\"} %d\n", c, m.byClass[c].Load())
	}
	fmt.Fprintf(w, "# HELP hive_relay_requests_in_flight In-flight requests right now.\n")
	fmt.Fprintf(w, "# TYPE hive_relay_requests_in_flight gauge\n")
	fmt.Fprintf(w, "hive_relay_requests_in_flight %d\n", m.inFlight.Load())
}
