package poller

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"

	"github.com/elitestarhosting/servcityexporter/internal/servcity"
	"github.com/elitestarhosting/servcityexporter/internal/store"
)

// TestPollFastHandlesDiscoveredResponseShapes runs the poller against a
// fake server that serves exactly the JSON shapes reverse-engineered from
// the ServCity dashboard's public JS bundle (see internal/servcity/
// types.go), to catch a regression in the poller<->types wiring that a
// types-only unit test wouldn't.
func TestPollFastHandlesDiscoveredResponseShapes(t *testing.T) {
	mux := http.NewServeMux()
	writeJSON := func(w http.ResponseWriter, v interface{}) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(v)
	}

	mux.HandleFunc("/ddos/config/1.2.3.4", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]interface{}{"firewall_enable": true})
	})
	mux.HandleFunc("/ddos/metrics/1.2.3.4", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]interface{}{
			"graph_data": []map[string]interface{}{
				{"metric_name": "passed", "data": []map[string]interface{}{{"timestamp": 1, "value": 42}}},
				{"metric_name": "tcp_generic_drop", "data": []map[string]interface{}{{"timestamp": 1, "value": 7}}},
			},
		})
	})
	mux.HandleFunc("/ddos/attacks/1.2.3.4", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]interface{}{"attacks": []map[string]interface{}{
			{"attack_uuid": "a1", "attack_start_time": 100, "attack_end_time": 0, "attack_peakbps": 999, "attack_peakpps": 111},
		}})
	})
	mux.HandleFunc("/ddos/firewall/1.2.3.4", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]interface{}{"rules": []map[string]interface{}{{}, {}}})
	})
	mux.HandleFunc("/tunnel", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]interface{}{"account_tunnels": []interface{}{}})
	})

	srv := httptest.NewServer(mux)
	defer srv.Close()

	client := servcity.NewClient(srv.URL, "test-key", 5*time.Second)
	st := store.New()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	p := New(client, st, log, time.Second, time.Second)

	ctx := context.Background()
	p.mu.Lock()
	p.discoveredIPs = []string{"1.2.3.4"}
	p.mu.Unlock()
	p.pollFast(ctx)

	families := gather(t, st)

	assertGaugeValue(t, families, "servcity_ddos_traffic_passed", map[string]string{"ip": "1.2.3.4"}, 42)
	assertGaugeValue(t, families, "servcity_ddos_traffic_tcp_generic_drop", map[string]string{"ip": "1.2.3.4"}, 7)
	assertGaugeValue(t, families, "servcity_ddos_attack_latest_active", map[string]string{"ip": "1.2.3.4"}, 1)
	assertGaugeValue(t, families, "servcity_ddos_attack_latest_peak_bps", map[string]string{"ip": "1.2.3.4"}, 999)
	assertGaugeValue(t, families, "servcity_ddos_firewall_rules", map[string]string{"ip": "1.2.3.4"}, 2)
	assertGaugeValue(t, families, "servcity_ddos_config_firewall_enable", map[string]string{"ip": "1.2.3.4"}, 1)

	if _, ok := families["servcity_ddos_metric_passed"]; ok {
		t.Error("expected the typed traffic-metrics path to be used, not the generic fallback (servcity_ddos_metric_* should be absent)")
	}
}

func gather(t *testing.T, st *store.Store) map[string]*dto.MetricFamily {
	t.Helper()
	reg := prometheus.NewRegistry()
	reg.MustRegister(st)
	mfs, err := reg.Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	out := make(map[string]*dto.MetricFamily, len(mfs))
	for _, mf := range mfs {
		out[mf.GetName()] = mf
	}
	return out
}

func assertGaugeValue(t *testing.T, families map[string]*dto.MetricFamily, name string, labels map[string]string, want float64) {
	t.Helper()
	fam, ok := families[name]
	if !ok {
		t.Errorf("expected metric family %q to be present", name)
		return
	}
	for _, m := range fam.GetMetric() {
		if !labelsMatch(m, labels) {
			continue
		}
		got := m.GetGauge().GetValue()
		if got != want {
			t.Errorf("%s%v = %v, want %v", name, labels, got, want)
		}
		return
	}
	t.Errorf("no series of %q matched labels %v", name, labels)
}

func labelsMatch(m *dto.Metric, want map[string]string) bool {
	got := map[string]string{}
	for _, lp := range m.GetLabel() {
		got[lp.GetName()] = lp.GetValue()
	}
	for k, v := range want {
		if got[k] != v {
			return false
		}
	}
	return true
}
