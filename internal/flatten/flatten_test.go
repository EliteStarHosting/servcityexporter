package flatten

import (
	"encoding/json"
	"testing"
)

func TestSanitizeMetricName(t *testing.T) {
	cases := map[string]string{
		"packetsPerSecond": "packets_per_second",
		"very_strict":      "very_strict",
		"webhook-url":      "webhook_url",
		"2fast":            "_2fast",
		"":                 "field",
		"ALLCAPS":          "allcaps",
	}
	for in, want := range cases {
		if got := SanitizeMetricName(in); got != want {
			t.Errorf("SanitizeMetricName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestNumericFlattensNestedNumericAndBoolLeaves(t *testing.T) {
	var v interface{}
	raw := `{"pps": 1234.5, "underAttack": true, "meta": {"droppedPackets": 7}, "ignored": "text", "nested": {"arr": [1,2,3]}}`
	if err := json.Unmarshal([]byte(raw), &v); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	got := Numeric(v, 3)

	want := map[string]float64{
		"pps":                  1234.5,
		"under_attack":         1,
		"meta_dropped_packets": 7,
	}
	for k, wantV := range want {
		gotV, ok := got[k]
		if !ok {
			t.Errorf("missing key %q in %v", k, got)
			continue
		}
		if gotV != wantV {
			t.Errorf("got[%q] = %v, want %v", k, gotV, wantV)
		}
	}
	if _, ok := got["ignored"]; ok {
		t.Errorf("expected non-numeric string field to be skipped, got %v", got["ignored"])
	}
	if _, ok := got["nested_arr"]; ok {
		t.Errorf("expected array field not to be descended into, got %v", got["nested_arr"])
	}
}

func TestNumericRespectsMaxDepth(t *testing.T) {
	var v interface{}
	raw := `{"a": {"b": {"c": {"d": 1}}}}`
	if err := json.Unmarshal([]byte(raw), &v); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	got := Numeric(v, 1)
	if _, ok := got["a_b_c_d"]; ok {
		t.Errorf("expected depth limit to stop before reaching a_b_c_d, got %v", got)
	}

	got = Numeric(v, 10)
	if got["a_b_c_d"] != 1 {
		t.Errorf("expected a_b_c_d=1 at sufficient depth, got %v", got)
	}
}

func TestLatestByTimePicksNewestTimestamp(t *testing.T) {
	var v []interface{}
	raw := `[{"timestamp": 100, "v": "old"}, {"timestamp": 300, "v": "newest"}, {"timestamp": 200, "v": "mid"}]`
	if err := json.Unmarshal([]byte(raw), &v); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	got := LatestByTime(v)
	obj, ok := got.(map[string]interface{})
	if !ok {
		t.Fatalf("expected object, got %T", got)
	}
	if obj["v"] != "newest" {
		t.Errorf("got v=%v, want newest", obj["v"])
	}
}

func TestLatestByTimeFallsBackToLastElement(t *testing.T) {
	var v []interface{}
	raw := `[{"v": "first"}, {"v": "last"}]`
	if err := json.Unmarshal([]byte(raw), &v); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	got := LatestByTime(v)
	obj, ok := got.(map[string]interface{})
	if !ok {
		t.Fatalf("expected object, got %T", got)
	}
	if obj["v"] != "last" {
		t.Errorf("got v=%v, want last (no timestamp field present, should fall back to last element)", obj["v"])
	}
}

func TestParseTimestamp(t *testing.T) {
	if _, ok := ParseTimestamp("0"); ok {
		t.Errorf(`ParseTimestamp("0") should report ok=false (WireGuard "never" sentinel)`)
	}
	if _, ok := ParseTimestamp(""); ok {
		t.Errorf(`ParseTimestamp("") should report ok=false`)
	}
	if got, ok := ParseTimestamp("1700000000"); !ok || got != 1700000000 {
		t.Errorf(`ParseTimestamp("1700000000") = %v, %v; want 1700000000, true`, got, ok)
	}
	if got, ok := ParseTimestamp("1700000000000"); !ok || got != 1700000000 {
		t.Errorf(`ParseTimestamp("1700000000000") = %v, %v; want 1700000000, true (ms detection)`, got, ok)
	}
	if got, ok := ParseTimestamp("2023-11-14T22:13:20Z"); !ok || got != 1700000000 {
		t.Errorf(`ParseTimestamp(RFC3339) = %v, %v; want 1700000000, true`, got, ok)
	}
}
