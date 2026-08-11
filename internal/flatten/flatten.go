// Package flatten turns arbitrary/undocumented JSON payloads into
// Prometheus-safe metric name fragments and numeric samples.
//
// Several ServCity API responses (IPMetrics, AttacksForIP, FWForIP) are
// referenced in the upstream OpenAPI spec but never defined there, so the
// exporter can't hard-code their field names. Instead it discovers numeric
// and boolean leaves at runtime and turns each one into a metric name
// fragment derived from its JSON key path, bounded to a shallow depth so a
// surprising response shape can't explode metric cardinality.
package flatten

import (
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"
)

var (
	invalidChars = regexp.MustCompile(`[^a-z0-9_]+`)
	leadingDigit = regexp.MustCompile(`^[0-9]`)
)

// SanitizeMetricName converts an arbitrary JSON key (camelCase, kebab-case,
// or otherwise) into a lowercase snake_case fragment safe to embed in a
// Prometheus metric name.
func SanitizeMetricName(s string) string {
	s = toSnakeCase(s)
	s = strings.ToLower(s)
	s = invalidChars.ReplaceAllString(s, "_")
	s = strings.Trim(s, "_")
	if s == "" {
		s = "field"
	}
	if leadingDigit.MatchString(s) {
		s = "_" + s
	}
	return s
}

func toSnakeCase(s string) string {
	var b strings.Builder
	runes := []rune(s)
	for i, r := range runes {
		if unicode.IsUpper(r) {
			if i > 0 && (unicode.IsLower(runes[i-1]) || unicode.IsDigit(runes[i-1])) {
				b.WriteByte('_')
			}
			b.WriteRune(unicode.ToLower(r))
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

// Numeric walks a decoded JSON value (as produced by encoding/json into
// interface{}) and returns every numeric or boolean leaf found, keyed by
// its '_'-joined field path. Booleans become 0/1. Arrays are not descended
// into: callers that need to summarize an array (count it, or pick one
// element to flatten) should do so before calling Numeric on the result -
// see LatestByTime and Count.
//
// maxDepth bounds how many nested object levels are followed, to keep
// output bounded for a response shape we don't control.
func Numeric(v interface{}, maxDepth int) map[string]float64 {
	out := make(map[string]float64)
	walk(v, "", maxDepth, out)
	return out
}

func walk(v interface{}, prefix string, depth int, out map[string]float64) {
	switch t := v.(type) {
	case float64:
		if prefix != "" {
			out[prefix] = t
		}
	case bool:
		if prefix != "" {
			if t {
				out[prefix] = 1
			} else {
				out[prefix] = 0
			}
		}
	case string:
		// Some APIs encode numbers as strings; recover them but never
		// silently coerce non-numeric strings (label-like text such as
		// status codes should stay out of a gauge's value).
		if prefix != "" {
			if f, err := strconv.ParseFloat(t, 64); err == nil {
				out[prefix] = f
			}
		}
	case map[string]interface{}:
		if depth <= 0 {
			return
		}
		for k, val := range t {
			frag := SanitizeMetricName(k)
			p := frag
			if prefix != "" {
				p = prefix + "_" + frag
			}
			walk(val, p, depth-1, out)
		}
	default:
		// nil, arrays: skip.
	}
}

// Count returns the length of v if it is a JSON array, and false
// otherwise.
func Count(v interface{}) (int, bool) {
	arr, ok := v.([]interface{})
	if !ok {
		return 0, false
	}
	return len(arr), true
}

// timeKeyCandidates are JSON object keys (case-insensitive) checked, in
// order, when picking the "most recent" element out of an array of
// objects.
var timeKeyCandidates = []string{
	"timestamp", "time", "date", "starttime", "start_time", "start",
	"endtime", "end_time", "end", "createdat", "created_at", "updatedat", "updated_at",
}

// LatestByTime picks the element of a JSON array judged most recent, by
// scanning each element for the first recognizable timestamp field (unix
// seconds/milliseconds, or an RFC3339 string). If no element carries a
// recognizable timestamp, it falls back to the last element of the array,
// which for naturally-ordered API responses (oldest first) is usually the
// newest.
func LatestByTime(arr []interface{}) interface{} {
	if len(arr) == 0 {
		return nil
	}
	bestIdx := len(arr) - 1
	bestTS := float64(-1)
	found := false

	for i, item := range arr {
		obj, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		ts, ok := extractTimestamp(obj)
		if !ok {
			continue
		}
		if !found || ts > bestTS {
			bestTS = ts
			bestIdx = i
			found = true
		}
	}
	return arr[bestIdx]
}

func extractTimestamp(obj map[string]interface{}) (float64, bool) {
	lower := make(map[string]interface{}, len(obj))
	for k, v := range obj {
		lower[strings.ToLower(k)] = v
	}
	for _, k := range timeKeyCandidates {
		raw, ok := lower[k]
		if !ok {
			continue
		}
		switch t := raw.(type) {
		case float64:
			return t, true
		case string:
			if ts, ok := parseTimeToUnix(t); ok {
				return ts, true
			}
			if f, err := strconv.ParseFloat(t, 64); err == nil {
				return f, true
			}
		}
	}
	return 0, false
}

// ParseTimestamp interprets s as either a Unix timestamp (seconds, or
// milliseconds if the magnitude implies it) or a common time string, and
// returns Unix seconds. It returns ok=false for the empty string and for
// "0", since "0" is WireGuard's conventional sentinel for "no handshake
// yet" rather than the Unix epoch - callers should treat that as no data,
// not as a real point in time.
func ParseTimestamp(s string) (float64, bool) {
	s = strings.TrimSpace(s)
	if s == "" || s == "0" {
		return 0, false
	}
	if f, err := strconv.ParseFloat(s, 64); err == nil {
		if f > 1e12 { // magnitude implies milliseconds, not seconds
			f = f / 1000
		}
		return f, true
	}
	return parseTimeToUnix(s)
}

func parseTimeToUnix(s string) (float64, bool) {
	layouts := []string{
		time.RFC3339,
		time.RFC3339Nano,
		"2006-01-02 15:04:05",
		"2006-01-02T15:04:05",
	}
	for _, layout := range layouts {
		if t, err := time.Parse(layout, s); err == nil {
			return float64(t.Unix()), true
		}
	}
	return 0, false
}
