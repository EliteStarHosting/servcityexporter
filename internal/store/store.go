// Package store holds the exporter's current set of metric samples and
// exposes them to Prometheus. The ServCity API mixes fully-documented
// response shapes (tunnels, account limits, DDoS config) with several
// undocumented ones (DDoS metrics/attacks/firewall — see README), so the
// exporter can't declare a fixed metric schema up front for those. Store
// implements prometheus.Collector as an "unchecked" collector: samples are
// written by the poll loops in internal/poller and served from an
// in-memory snapshot on every scrape, so a slow or failing upstream call
// never blocks or blanks out /metrics.
package store

import (
	"sort"
	"strings"
	"sync"

	"github.com/prometheus/client_golang/prometheus"
)

// Point is a single observed metric sample.
type Point struct {
	Name   string
	Help   string
	Type   prometheus.ValueType
	Labels map[string]string
	Value  float64
}

type key struct {
	name   string
	labels string
}

func keyFor(name string, labels map[string]string) key {
	names := make([]string, 0, len(labels))
	for n := range labels {
		names = append(names, n)
	}
	sort.Strings(names)
	var b strings.Builder
	for _, n := range names {
		b.WriteString(n)
		b.WriteByte('=')
		b.WriteString(labels[n])
		b.WriteByte('\x00')
	}
	return key{name: name, labels: b.String()}
}

// Store is a thread-safe collection of the latest known value for every
// metric series the exporter produces.
type Store struct {
	mu     sync.RWMutex
	points map[key]Point
}

// New returns an empty Store.
func New() *Store {
	return &Store{points: make(map[key]Point)}
}

// Set records or overwrites the current value of a series.
func (s *Store) Set(p Point) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.points[keyFor(p.Name, p.Labels)] = p
}

// SetAll records/overwrites several series at once.
func (s *Store) SetAll(points []Point) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, p := range points {
		s.points[keyFor(p.Name, p.Labels)] = p
	}
}

// DeleteWhere removes every series matched by pred. Used to drop stale
// per-resource series (e.g. an IP or tunnel no longer on the account) so
// they don't linger in /metrics forever.
func (s *Store) DeleteWhere(pred func(Point) bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, p := range s.points {
		if pred(p) {
			delete(s.points, k)
		}
	}
}

// Describe intentionally sends nothing: this makes Store an "unchecked"
// prometheus.Collector, since the exact set of metrics is only known once
// the ServCity API has actually been polled.
func (s *Store) Describe(ch chan<- *prometheus.Desc) {}

// Collect implements prometheus.Collector.
func (s *Store) Collect(ch chan<- prometheus.Metric) {
	s.mu.RLock()
	snapshot := make([]Point, 0, len(s.points))
	for _, p := range s.points {
		snapshot = append(snapshot, p)
	}
	s.mu.RUnlock()

	for _, p := range snapshot {
		labelNames := make([]string, 0, len(p.Labels))
		labelValues := make([]string, 0, len(p.Labels))
		for n, v := range p.Labels {
			labelNames = append(labelNames, n)
			labelValues = append(labelValues, v)
		}
		desc := prometheus.NewDesc(p.Name, p.Help, labelNames, nil)
		m, err := prometheus.NewConstMetric(desc, p.Type, p.Value, labelValues...)
		if err != nil {
			// Skip a single malformed sample rather than failing the whole
			// scrape; this should only happen if two callers disagree on
			// the label set for the same metric name, which is a bug in a
			// poller, not something an operator can act on.
			continue
		}
		ch <- m
	}
}
