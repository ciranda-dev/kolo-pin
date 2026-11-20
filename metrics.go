package pin

import (
	"errors"
	"sync/atomic"

	kololog "github.com/ciranda-dev/kolo-log"
	"github.com/prometheus/client_golang/prometheus"
)

// Label values; the only ones the metrics use, so no key, ID or address ever becomes a label.
var (
	metricOps     = []string{"add", "remove", "status", "revoke", "sync_pull"}
	refuseReasons = []string{"bad_token", "expired_token", "replayed_token", "revoked", "quota_exceeded",
		"disk_full", "owner_limit", "oversized_entry", "bad_signature", "bad_proof", "other"}
	durationBuckets = []float64{0.01, 0.05, 0.1, 0.5, 1, 5, 10, 30, 60, 300}
)

type metrics struct {
	requests    *prometheus.CounterVec
	refused     *prometheus.CounterVec
	markers     prometheus.Counter
	received    prometheus.Counter
	conns       prometheus.Gauge
	pulls       atomic.Int64 // pulls from owners running now
	pullSeconds prometheus.Histogram
	reqSeconds  *prometheus.HistogramVec
}

func newMetrics() *metrics {
	m := &metrics{
		requests: prometheus.NewCounterVec(prometheus.CounterOpts{Name: "kolo_pin_requests_total",
			Help: "Requests answered, by operation; sync_pull counts kolo-sync streams other peers open on a hosted log, pulls and fetches."}, []string{"op"}),
		refused: prometheus.NewCounterVec(prometheus.CounterOpts{Name: "kolo_pin_refused_total",
			Help: "Requests refused, by reason."}, []string{"reason"}),
		markers: prometheus.NewCounter(prometheus.CounterOpts{Name: "kolo_pin_delete_markers_applied_total",
			Help: "Owner delete markers applied, each dropping one entry's ciphertext the peer held."}),
		received: prometheus.NewCounter(prometheus.CounterOpts{Name: "kolo_pin_bytes_received_total",
			Help: "Bytes of new entries (records and ciphertexts) pulled from owners and stored."}),
		conns: prometheus.NewGauge(prometheus.GaugeOpts{Name: "kolo_pin_active_connections",
			Help: "Open kolo-secure connections."}),
		pullSeconds: prometheus.NewHistogram(prometheus.HistogramOpts{Name: "kolo_pin_sync_pull_duration_seconds",
			Help: "Duration of the pulls from owners that Add runs.", Buckets: durationBuckets}),
		reqSeconds: prometheus.NewHistogramVec(prometheus.HistogramOpts{Name: "kolo_pin_request_duration_seconds",
			Help: "Duration of pin requests, by operation; kolo-sync streams are not timed.", Buckets: durationBuckets}, []string{"op"}),
	}
	for _, op := range metricOps {
		m.requests.WithLabelValues(op)
		if op != "sync_pull" {
			m.reqSeconds.WithLabelValues(op)
		}
	}
	for _, r := range refuseReasons {
		m.refused.WithLabelValues(r)
	}
	return m
}

// collectors returns every metric of s, the storage gauges read when scraped.
func (s *server) collectors() []prometheus.Collector {
	m := s.m
	gauge := func(name, help string, f func() float64) prometheus.Collector {
		return prometheus.NewGaugeFunc(prometheus.GaugeOpts{Name: name, Help: help}, f)
	}
	cs := []prometheus.Collector{m.requests, m.refused, m.markers, m.received, m.conns, m.pullSeconds, m.reqSeconds,
		prometheus.NewCounterFunc(prometheus.CounterOpts{Name: "kolo_pin_bytes_served_total",
			Help: "Bytes kolo-sync wrote to peers pulling hosted logs, every frame included."},
			func() float64 { return float64(s.sync.Stats().BytesSent) }),
		gauge("kolo_pin_active_sync_streams", "kolo-sync streams running now: those served to pulling peers plus the pulls from owners.",
			func() float64 { return float64(int64(s.sync.Stats().ActiveStreams) + m.pulls.Load()) }),
		gauge("kolo_pin_active_pulls", "Pulls from owners into the store running now, part of kolo_pin_active_sync_streams.",
			func() float64 { return float64(m.pulls.Load()) }),
		gauge("kolo_pin_bytes_used", "Bytes stored for all owners, keys and values.", func() float64 {
			s.disk.mu.Lock()
			defer s.disk.mu.Unlock()
			return float64(s.disk.used)
		}),
		gauge("kolo_pin_bytes_max", "The most bytes the peer stores for all owners.", func() float64 { return float64(s.disk.max) }),
		gauge("kolo_pin_owner_records", "Owner records stored, including those of owners with nothing held.", func() float64 {
			s.disk.mu.Lock()
			defer s.disk.mu.Unlock()
			return float64(s.disk.records)
		}),
		gauge("kolo_pin_owner_records_max", "The most owner records the peer keeps.", func() float64 { return float64(s.disk.maxRecords) }),
		gauge("kolo_pin_owners", "Owners with a capability in use or a held log.", func() float64 { return float64(s.totals().owners) }),
		gauge("kolo_pin_logs", "Held logs, including logs whose delete failed.", func() float64 { return float64(s.totals().logs) }),
		gauge("kolo_pin_entries", "Entries of all held logs, including logs whose delete failed.", func() float64 { return float64(s.totals().entries) }),
	}
	if _, ok := diskFree(s.dir); ok {
		cs = append(cs, gauge("kolo_pin_disk_free_bytes", "Free bytes on the filesystem of the data directory.", func() float64 {
			n, _ := diskFree(s.dir)
			return float64(n)
		}))
	}
	return cs
}

type totals struct{ owners, logs, entries uint64 }

func (s *server) totals() totals {
	s.mu.Lock()
	owners := make([]*owner, 0, len(s.owners))
	for _, o := range s.owners {
		owners = append(owners, o)
	}
	s.mu.Unlock()
	var t totals
	for _, o := range owners {
		o.mu.Lock()
		if o.capb != nil || len(o.logs) > 0 {
			t.owners++
		}
		t.logs += uint64(len(o.logs))
		for _, h := range o.logs {
			t.entries += h.entries.Load()
		}
		o.mu.Unlock()
	}
	return t
}

// reason is the refused_total label of a refusal.
func reason(err error) string {
	switch {
	case errors.Is(err, errReplayed):
		return "replayed_token"
	case errors.Is(err, ErrRevoked):
		return "revoked"
	case errors.Is(err, ErrExpired):
		return "expired_token"
	case errors.Is(err, errBadSignature):
		return "bad_signature"
	case errors.Is(err, ErrUnauthorized):
		return "bad_token"
	case errors.Is(err, ErrQuotaExceeded):
		return "quota_exceeded"
	case errors.Is(err, ErrDiskFull):
		return "disk_full"
	case errors.Is(err, ErrOwnerLimit):
		return "owner_limit"
	case errors.Is(err, ErrTooLarge):
		return "oversized_entry"
	case errors.Is(err, kololog.ErrBadProof), errors.Is(err, kololog.ErrDiverged):
		return "bad_proof"
	case errors.Is(err, ErrInvalid):
		return "bad_signature"
	}
	return "other"
}
