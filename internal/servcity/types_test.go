package servcity

import (
	"encoding/json"
	"testing"
)

// These fixtures mirror the shapes reverse-engineered from the ServCity
// DDoS Protection dashboard's public JS bundle (see types.go's package
// comment) - not a live API response. They exist to lock in that
// understanding and catch a silent decode regression, not to prove the
// real API matches.

func TestTrafficMetricsResponseDecodesGraphData(t *testing.T) {
	raw := `{
		"graph_data": [
			{"metric_name": "passed", "data": [{"timestamp": 100, "value": 1000}, {"timestamp": 200, "value": 2000}]},
			{"metric_name": "tcp_generic_drop", "data": [{"timestamp": 100, "value": 5}]},
			{"metric_name": "udp_amplification_drop", "data": []}
		]
	}`

	var tm TrafficMetricsResponse
	if err := json.Unmarshal([]byte(raw), &tm); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(tm.GraphData) != 3 {
		t.Fatalf("expected 3 series, got %d", len(tm.GraphData))
	}

	passed := tm.GraphData[0]
	if passed.MetricName != "passed" {
		t.Errorf("expected first series name 'passed', got %q", passed.MetricName)
	}
	latest, ok := passed.Latest()
	if !ok {
		t.Fatal("expected passed series to have a latest point")
	}
	if latest.Value != 2000 || latest.Timestamp != 200 {
		t.Errorf("expected latest={200,2000}, got %+v", latest)
	}

	if _, ok := tm.GraphData[2].Latest(); ok {
		t.Error("expected empty series to report no latest point")
	}
}

func TestTrafficMetricSeriesStats(t *testing.T) {
	s := TrafficMetricSeries{
		MetricName: "tcp_generic_drop",
		Data: []TrafficMetricPoint{
			{Timestamp: 100, Value: 10},
			{Timestamp: 200, Value: 50}, // spike between polls a "latest only" metric would miss
			{Timestamp: 300, Value: 20},
		},
	}
	stats, ok := s.Stats()
	if !ok {
		t.Fatal("expected stats for non-empty series")
	}
	if stats.Latest != 20 {
		t.Errorf("Latest = %v, want 20", stats.Latest)
	}
	if stats.Max != 50 {
		t.Errorf("Max = %v, want 50", stats.Max)
	}
	if stats.Min != 10 {
		t.Errorf("Min = %v, want 10", stats.Min)
	}
	if stats.Avg != (10.0+50.0+20.0)/3.0 {
		t.Errorf("Avg = %v, want %v", stats.Avg, (10.0+50.0+20.0)/3.0)
	}
}

func TestTrafficMetricSeriesStatsEmpty(t *testing.T) {
	s := TrafficMetricSeries{MetricName: "passed"}
	if _, ok := s.Stats(); ok {
		t.Error("expected ok=false for an empty series")
	}
}

func TestTrafficMetricSeriesLatestFallsBackWithoutTimestamps(t *testing.T) {
	s := TrafficMetricSeries{
		MetricName: "passed",
		Data: []TrafficMetricPoint{
			{Value: 1},
			{Value: 2},
			{Value: 3},
		},
	}
	latest, ok := s.Latest()
	if !ok || latest.Value != 3 {
		t.Errorf("expected fallback to last element (value=3), got %+v, ok=%v", latest, ok)
	}
}

func TestAttacksForIPResponseDecodesAttacksList(t *testing.T) {
	raw := `{
		"attacks": [
			{"attack_uuid": "a1", "attack_target_ip": "1.2.3.4", "attack_type": "udp_flood", "attack_start_time": 1000, "attack_end_time": 0, "attack_peakbps": 123456, "attack_peakpps": 789},
			{"attack_uuid": "a0", "attack_target_ip": "1.2.3.4", "attack_type": "syn_flood", "attack_start_time": 500, "attack_end_time": 900, "attack_peakbps": 111, "attack_peakpps": 222}
		]
	}`

	var af AttacksForIPResponse
	if err := json.Unmarshal([]byte(raw), &af); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(af.Attacks) != 2 {
		t.Fatalf("expected 2 attacks, got %d", len(af.Attacks))
	}
	latest := af.Attacks[0]
	if latest.AttackUUID != "a1" {
		t.Errorf("expected first attack to be a1 (list is newest-first per the dashboard), got %q", latest.AttackUUID)
	}
	if latest.AttackEnd != 0 {
		t.Errorf("expected ongoing attack to have AttackEnd=0, got %v", latest.AttackEnd)
	}
}

func TestFirewallRulesResponseDecodesRulesList(t *testing.T) {
	raw := `{"rules": [{"fw_key": {"ip": "1.2.3.4", "proto": "tcp", "port": 25565}}, {"fw_key": {"ip": "1.2.3.4", "proto": "udp", "port": 0}}]}`

	var fw FirewallRulesResponse
	if err := json.Unmarshal([]byte(raw), &fw); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(fw.Rules) != 2 {
		t.Fatalf("expected 2 rules, got %d", len(fw.Rules))
	}
}

func TestConfigBoolFieldsOmitsAbsentFields(t *testing.T) {
	raw := `{"firewall_enable": true, "strict": false}`
	var cfg Config
	if err := json.Unmarshal([]byte(raw), &cfg); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	fields := cfg.BoolFields()
	if len(fields) != 2 {
		t.Fatalf("expected exactly 2 present fields, got %d (%v)", len(fields), fields)
	}
	if !fields["firewall_enable"] {
		t.Error("expected firewall_enable=true")
	}
	if fields["strict"] {
		t.Error("expected strict=false")
	}
	if _, present := fields["very_strict"]; present {
		t.Error("expected absent field 'very_strict' to be omitted, not defaulted to false")
	}
}
