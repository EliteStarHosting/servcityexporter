package servcity

import "encoding/json"

// The types below mirror the ServCity User API's documented response
// schemas (https://servcity.org/uapi/swagger.yml). Boolean config fields
// use pointers so the collector can distinguish "field absent from this
// account/response" from "field present and false" rather than silently
// treating both as false.
//
// IPMetrics, AttacksForIP, and FWForIP (below) are NOT defined in that
// spec - they're $ref'd but never given a schema. Their shapes here were
// reverse-engineered from the ServCity DDoS Protection dashboard's public,
// unauthenticated JS bundle (prot.servcity.org/_next/static/chunks/app/
// dashboard/page-*.js), which calls its own backend-for-frontend at
// /api/traffic-metrics, /api/attacks, and /api/firewall - each a thin
// proxy in front of the corresponding /ddos/* endpoint on this same User
// API. That's strong evidence for the real shape, but it's still once
// removed from the raw uapi response: treat it as a well-informed best
// guess, not a confirmed contract, and expect internal/poller's
// generic-flattening fallback to kick in if a live account's raw response
// doesn't decode into these structs.

// AccountLimits is the response of GET /user/limits.
type AccountLimits struct {
	AllowedRemainingProxies int      `json:"allowedRemainingProxies"`
	AuthorizedTargetSubnets []string `json:"authorizedTargetSubnets"`
}

// AuthorizedIPs is the response of GET /ddos/getAllowedIps.
type AuthorizedIPs struct {
	AuthorizedIPs []string `json:"authorizedIps"`
}

// AllowedProxiesList is the response of GET /minecraft/getAllowedProxies.
type AllowedProxiesList struct {
	AllowedProxies []string `json:"allowedProxies"`
}

// Config is the DDoS protection config for one IP, from
// GET /ddos/config/{IP}. Field names/casing match the upstream JSON
// verbatim (e.g. "very_strict", not "veryStrict").
type Config struct {
	Nulled         *bool `json:"nulled"`
	ConntrackTCP   *bool `json:"conntrack_tcp"`
	ConntrackUDP   *bool `json:"conntrack_udp"`
	Strict         *bool `json:"strict"`
	VeryStrict     *bool `json:"very_strict"`
	DropUDPAmp     *bool `json:"drop_udp_amp"`
	SynfloodFilter *bool `json:"synflood_filter"`
	PcapOnAttack   *bool `json:"pcap_on_attack"`
	Symmetric      *bool `json:"symmetric"`
	Whitelisted    *bool `json:"whitelisted"`
	BlockNewConn   *bool `json:"block_new_conn"`
	DefaultL7      *bool `json:"default_l7"`
	LearningMode   *bool `json:"learning_mode"`
	FirewallEnable *bool `json:"firewall_enable"`
	WhitelistUDP   *bool `json:"whitelist_udp"`
	DynamicFilter  *bool `json:"dynamic_filter"`
}

// BoolFields returns every present boolean field as (config-field-name,
// value), for driving a generic gauge-per-toggle exporter loop instead of
// one hand-written metric per field.
func (c Config) BoolFields() map[string]bool {
	out := map[string]bool{}
	add := func(name string, v *bool) {
		if v != nil {
			out[name] = *v
		}
	}
	add("nulled", c.Nulled)
	add("conntrack_tcp", c.ConntrackTCP)
	add("conntrack_udp", c.ConntrackUDP)
	add("strict", c.Strict)
	add("very_strict", c.VeryStrict)
	add("drop_udp_amp", c.DropUDPAmp)
	add("synflood_filter", c.SynfloodFilter)
	add("pcap_on_attack", c.PcapOnAttack)
	add("symmetric", c.Symmetric)
	add("whitelisted", c.Whitelisted)
	add("block_new_conn", c.BlockNewConn)
	add("default_l7", c.DefaultL7)
	add("learning_mode", c.LearningMode)
	add("firewall_enable", c.FirewallEnable)
	add("whitelist_udp", c.WhitelistUDP)
	add("dynamic_filter", c.DynamicFilter)
	return out
}

// TunnelConf describes one WireGuard-style tunnel. Fully documented by the
// upstream spec, used both as an element of GetTunnelsReply and as the
// base of the tunnel-creation reply.
type TunnelConf struct {
	PublicKey         string   `json:"public_key"`
	UUID              string   `json:"uuid"`
	PresharedKey      string   `json:"preshared_key"`
	AllowedIPs        []string `json:"allowed_ips"`
	LastHandshakeTime string   `json:"last_handshake_time"`
	ReceiveBytes      *int64   `json:"receive_bytes"`
	TransmitBytes     *int64   `json:"transmit_bytes"`
}

// GetTunnelsReply is the response of GET /tunnel.
type GetTunnelsReply struct {
	AccountTunnels []TunnelConf `json:"account_tunnels"`
}

// ProxyConf is a Minecraft proxy's configuration, from
// GET /minecraft/proxy/{uuid}.
type ProxyConf struct {
	DstIP                 string `json:"dstIp"`
	DstPort               int    `json:"dstPort"`
	DontSendProxyProtocol bool   `json:"dontSendProxyProtocol"`
	DialTimeoutMessage    string `json:"dialTimeoutMessage"`
}

// ProxyPortConf is the response of GET /minecraft/proxy/{proxyID}/port.
type ProxyPortConf struct {
	BedrockPort int `json:"bedrockPort"`
	JavaPort    int `json:"javaPort"`
}

// TrafficMetricPoint is one timestamped sample within a TrafficMetricSeries.
type TrafficMetricPoint struct {
	Timestamp float64 `json:"timestamp"`
	Value     float64 `json:"value"`
}

// TrafficMetricSeries is one named traffic category (e.g. "passed",
// "tcp_generic_drop", "udp_amplification_drop") with its samples over the
// requested time window.
type TrafficMetricSeries struct {
	MetricName string               `json:"metric_name"`
	Data       []TrafficMetricPoint `json:"data"`
}

// Latest returns the sample judged most recent: the one with the highest
// Timestamp, or - if no sample carries a nonzero timestamp - the last
// element, on the assumption the series is chronologically ordered.
func (s TrafficMetricSeries) Latest() (TrafficMetricPoint, bool) {
	if len(s.Data) == 0 {
		return TrafficMetricPoint{}, false
	}
	hasTimestamp := false
	for _, p := range s.Data {
		if p.Timestamp != 0 {
			hasTimestamp = true
			break
		}
	}
	if !hasTimestamp {
		return s.Data[len(s.Data)-1], true
	}
	best := s.Data[0]
	for _, p := range s.Data[1:] {
		if p.Timestamp > best.Timestamp {
			best = p
		}
	}
	return best, true
}

// TrafficMetricsResponse is IPMetrics: the believed response shape of
// GET /ddos/metrics/{IP} and GET /ddos/metrics/{IP}/{HOURS}.
type TrafficMetricsResponse struct {
	GraphData []TrafficMetricSeries `json:"graph_data"`
}

// TrafficMetricStats summarizes a TrafficMetricSeries: the most recent
// value, plus the min/max/average across every sample in the response
// window (the last 6 hours, for the no-HOURS metrics endpoint this
// exporter polls). The window is decoupled from how often the exporter
// polls, so Max/Min surface short-lived spikes a single "latest value"
// sample could land on either side of and miss entirely.
type TrafficMetricStats struct {
	Latest float64
	Min    float64
	Max    float64
	Avg    float64
}

// Stats summarizes every sample in the series. ok is false for an empty
// series.
func (s TrafficMetricSeries) Stats() (TrafficMetricStats, bool) {
	if len(s.Data) == 0 {
		return TrafficMetricStats{}, false
	}
	latest, _ := s.Latest()
	min, max, sum := s.Data[0].Value, s.Data[0].Value, 0.0
	for _, p := range s.Data {
		if p.Value < min {
			min = p.Value
		}
		if p.Value > max {
			max = p.Value
		}
		sum += p.Value
	}
	return TrafficMetricStats{
		Latest: latest.Value,
		Min:    min,
		Max:    max,
		Avg:    sum / float64(len(s.Data)),
	}, true
}

// AttackSummary is one entry of AttacksForIP, the believed response shape
// of GET /ddos/attacks/{IP}. The dashboard treats the first element of the
// list as the most recent attack, and treats a zero/absent AttackEndTime
// as "attack still ongoing" (verbatim: `s.attack_end_time ? ... :
// "Ongoing"` in its own UI code).
type AttackSummary struct {
	AttackUUID     string  `json:"attack_uuid"`
	AttackTargetIP string  `json:"attack_target_ip"`
	AttackType     string  `json:"attack_type"`
	AttackStart    float64 `json:"attack_start_time"`
	AttackEnd      float64 `json:"attack_end_time"`
	PeakBps        float64 `json:"attack_peakbps"`
	PeakPps        float64 `json:"attack_peakpps"`
}

// AttacksForIPResponse wraps the attack list.
type AttacksForIPResponse struct {
	Attacks []AttackSummary `json:"attacks"`
}

// FirewallRulesResponse is the believed response shape of
// GET /ddos/firewall/{IP} (FWForIP). Individual rule fields aren't decoded
// since the exporter only reports a rule count today; each element is kept
// as raw JSON so a future caller can add fields without another round of
// reverse-engineering.
type FirewallRulesResponse struct {
	Rules []json.RawMessage `json:"rules"`
}
