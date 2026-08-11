// Package poller runs the background polling loops that keep the metric
// store up to date. Two loops run independently: a "slow" one that
// re-discovers account-level resources (authorized IPs, Minecraft
// proxies, account limits), and a "fast" one that refreshes per-resource
// data (DDoS config/metrics/attacks/firewall per IP, tunnel counters).
// Splitting them avoids re-fetching slow-changing discovery data on every
// fast tick, while still refreshing traffic-sensitive data frequently.
package poller

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/elitestarhosting/servcityexporter/internal/flatten"
	"github.com/elitestarhosting/servcityexporter/internal/servcity"
	"github.com/elitestarhosting/servcityexporter/internal/store"
)

// maxFlattenDepth bounds how many nested JSON object levels the generic
// flattener will follow for endpoints whose response schema isn't
// documented upstream (see internal/flatten).
const maxFlattenDepth = 3

// maxConcurrency bounds how many per-resource requests (one IP, one
// Minecraft proxy) are in flight at once during a poll cycle.
const maxConcurrency = 4

// requestStagger spaces out successive per-resource fan-out launches. A
// live account with 36 authorized IPs tripped the ServCity API's own
// proof-of-work anti-bot challenge (HTTP 403 with a "pow" field in the
// response body) when polled at full concurrency with no stagger - this
// keeps the burst rate low enough to avoid it without serializing the
// whole poll cycle.
const requestStagger = 150 * time.Millisecond

// Poller owns the ServCity API client and metric store and drives both
// poll loops.
type Poller struct {
	client *servcity.Client
	store  *store.Store
	log    *slog.Logger

	fastInterval time.Duration
	slowInterval time.Duration

	mu            sync.RWMutex
	discoveredIPs []string

	errCounters sync.Map // endpoint (string) -> *uint64
}

// New builds a Poller.
func New(client *servcity.Client, st *store.Store, log *slog.Logger, fastInterval, slowInterval time.Duration) *Poller {
	return &Poller{
		client:       client,
		store:        st,
		log:          log,
		fastInterval: fastInterval,
		slowInterval: slowInterval,
	}
}

// Run starts both poll loops and blocks until ctx is cancelled. Each loop
// runs once immediately on start rather than waiting for its first tick,
// so /metrics has data as soon as possible after startup.
func (p *Poller) Run(ctx context.Context) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		p.loop(ctx, "slow", p.slowInterval, p.pollSlow)
	}()
	go func() {
		defer wg.Done()
		p.loop(ctx, "fast", p.fastInterval, p.pollFast)
	}()
	wg.Wait()
}

func (p *Poller) loop(ctx context.Context, name string, interval time.Duration, fn func(context.Context)) {
	run := func() {
		start := time.Now()
		fn(ctx)
		p.store.Set(gaugePoint(
			"servcity_exporter_scrape_duration_seconds",
			"Duration in seconds of the last poll cycle, by loop.",
			map[string]string{"loop": name},
			time.Since(start).Seconds(),
		))
	}
	run()
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			run()
		}
	}
}

func (p *Poller) pollSlow(ctx context.Context) {
	p.pollAccountLimits(ctx)
	p.pollAllowedIPs(ctx)
	p.pollMinecraftProxies(ctx)
}

func (p *Poller) pollFast(ctx context.Context) {
	p.pollTunnels(ctx)

	p.fanOut(p.currentIPs(), func(ip string) {
		p.pollIPConfig(ctx, ip)
		p.pollIPMetrics(ctx, ip)
		p.pollIPAttacks(ctx, ip)
		p.pollIPFirewall(ctx, ip)
	})
}

// fanOut runs worker(item) once per item, bounded to maxConcurrency
// in-flight at a time and staggered by requestStagger between launches, to
// keep the API request burst rate low enough to avoid ServCity's anti-bot
// challenge (see requestStagger).
func (p *Poller) fanOut(items []string, worker func(item string)) {
	sem := make(chan struct{}, maxConcurrency)
	var wg sync.WaitGroup
	for i, item := range items {
		item := item
		if i > 0 {
			time.Sleep(requestStagger)
		}
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			worker(item)
		}()
	}
	wg.Wait()
}

func (p *Poller) currentIPs() []string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	out := make([]string, len(p.discoveredIPs))
	copy(out, p.discoveredIPs)
	return out
}

// --- account / discovery -----------------------------------------------

func (p *Poller) pollAccountLimits(ctx context.Context) {
	limits, err := p.client.GetAccountLimits(ctx)
	if err != nil {
		p.handleErr("account_limits", err, true)
		return
	}
	p.setUp(true)
	p.store.SetAll([]store.Point{
		gaugePoint("servcity_account_remaining_proxies", "Remaining Minecraft proxy slots available on this account.", nil, float64(limits.AllowedRemainingProxies)),
		gaugePoint("servcity_account_authorized_subnets", "Number of target subnets authorized on this account.", nil, float64(len(limits.AuthorizedTargetSubnets))),
	})
}

func (p *Poller) pollAllowedIPs(ctx context.Context) {
	ips, err := p.client.GetAllowedIPs(ctx)
	if err != nil {
		p.handleErr("ddos_allowed_ips", err, true)
		return
	}
	p.setUp(true)

	p.mu.Lock()
	p.discoveredIPs = ips
	p.mu.Unlock()

	p.store.Set(gaugePoint("servcity_ddos_authorized_ips", "Number of IPs authorized for DDoS protection on this account.", nil, float64(len(ips))))

	current := make(map[string]bool, len(ips))
	for _, ip := range ips {
		current[ip] = true
	}
	p.store.DeleteWhere(func(pt store.Point) bool {
		ip, ok := pt.Labels["ip"]
		return ok && !current[ip]
	})
}

// --- per-IP DDoS data ----------------------------------------------------

func (p *Poller) pollIPConfig(ctx context.Context, ip string) {
	cfg, err := p.client.GetConfig(ctx, ip)
	if err != nil {
		p.handleErr("ddos_config", err, false)
		return
	}
	labels := map[string]string{"ip": ip}
	fields := cfg.BoolFields()
	points := make([]store.Point, 0, len(fields))
	for field, val := range fields {
		v := 0.0
		if val {
			v = 1
		}
		points = append(points, gaugePoint(
			"servcity_ddos_config_"+field,
			"DDoS protection config toggle '"+field+"' for this IP (1=enabled, 0=disabled).",
			labels, v,
		))
	}
	p.store.SetAll(points)
}

// pollIPMetrics handles GET /ddos/metrics/{IP}. It first tries the shape
// reverse-engineered from the ServCity dashboard's own frontend (see
// servcity.TrafficMetricsResponse): a set of named traffic categories
// (e.g. "passed", "tcp_generic_drop", "udp_amplification_drop"), each with
// a time series. If a live account's response doesn't decode into that
// shape, falls back to generic field flattening so data isn't dropped
// outright. See internal/flatten for the fallback's discovery logic.
func (p *Poller) pollIPMetrics(ctx context.Context, ip string) {
	raw, err := p.client.GetMetricsRaw(ctx, ip)
	if err != nil {
		p.handleErr("ddos_metrics", err, false)
		return
	}
	labels := map[string]string{"ip": ip}

	var tm servcity.TrafficMetricsResponse
	if jsonErr := json.Unmarshal(raw, &tm); jsonErr == nil && len(tm.GraphData) > 0 {
		points := make([]store.Point, 0, len(tm.GraphData)*5)
		for _, series := range tm.GraphData {
			category := flatten.SanitizeMetricName(series.MetricName)
			categoryLabels := map[string]string{"ip": ip, "category": category}
			points = append(points, gaugePoint(
				"servcity_ddos_traffic_samples",
				"Number of samples returned for a traffic category by the last ddos/metrics call.",
				categoryLabels, float64(len(series.Data)),
			))
			if stats, ok := series.Stats(); ok {
				points = append(points,
					gaugePoint(
						"servcity_ddos_traffic_"+category,
						"Latest observed value for the '"+category+"' DDoS traffic category on this IP (units unconfirmed against a live account - see README).",
						labels, stats.Latest,
					),
					gaugePoint(
						"servcity_ddos_traffic_"+category+"_max",
						"Highest value for the '"+category+"' DDoS traffic category across the whole response window (last 6h by default) - catches spikes a single latest-value sample could miss.",
						labels, stats.Max,
					),
					gaugePoint(
						"servcity_ddos_traffic_"+category+"_min",
						"Lowest value for the '"+category+"' DDoS traffic category across the whole response window.",
						labels, stats.Min,
					),
					gaugePoint(
						"servcity_ddos_traffic_"+category+"_avg",
						"Average value for the '"+category+"' DDoS traffic category across the whole response window.",
						labels, stats.Avg,
					),
				)
			}
		}
		p.replaceGroup("servcity_ddos_traffic_", labels, points)
		return
	}

	var generic interface{}
	_ = json.Unmarshal(raw, &generic)
	sample := generic
	if arr, ok := generic.([]interface{}); ok {
		p.store.Set(gaugePoint("servcity_ddos_metrics_samples", "Number of samples returned by the last ddos/metrics call for this IP.", labels, float64(len(arr))))
		sample = flatten.LatestByTime(arr)
	}
	if sample == nil {
		return
	}

	fields := flatten.Numeric(sample, maxFlattenDepth)
	points := make([]store.Point, 0, len(fields))
	for name, val := range fields {
		points = append(points, gaugePoint(
			"servcity_ddos_metric_"+name,
			"DDoS traffic metric '"+name+"' for this IP. Field discovered at runtime because the response didn't match the expected traffic-category shape; verify against a live account.",
			labels, val,
		))
	}
	p.replaceGroup("servcity_ddos_metric_", labels, points)
}

// pollIPAttacks handles GET /ddos/attacks/{IP}. It first tries the shape
// reverse-engineered from the dashboard (servcity.AttacksForIPResponse: an
// "attacks" list, newest first), falling back to generic flattening
// otherwise. Only a count and the most recent record's fields are exposed
// - per-attack traffic detail requires GET /ddos/attacks/{IP}/{ID}, which
// isn't polled here to avoid an unbounded number of series as attack
// history grows.
func (p *Poller) pollIPAttacks(ctx context.Context, ip string) {
	raw, err := p.client.GetAttacksRaw(ctx, ip)
	if err != nil {
		p.handleErr("ddos_attacks", err, false)
		return
	}
	labels := map[string]string{"ip": ip}

	var af servcity.AttacksForIPResponse
	if jsonErr := json.Unmarshal(raw, &af); jsonErr == nil && af.Attacks != nil {
		p.store.Set(gaugePoint("servcity_ddos_attacks_total", "Number of attack records returned for this IP by the last ddos/attacks call.", labels, float64(len(af.Attacks))))

		var points []store.Point
		if len(af.Attacks) > 0 {
			latest := af.Attacks[0]
			active := 0.0
			if latest.AttackEnd == 0 {
				active = 1
			}
			points = []store.Point{
				gaugePoint("servcity_ddos_attack_latest_peak_bps", "Peak bits/sec of the most recent attack on this IP.", labels, latest.PeakBps),
				gaugePoint("servcity_ddos_attack_latest_peak_pps", "Peak packets/sec of the most recent attack on this IP.", labels, latest.PeakPps),
				gaugePoint("servcity_ddos_attack_latest_start_timestamp_seconds", "Unix start time of the most recent attack on this IP.", labels, latest.AttackStart),
				gaugePoint("servcity_ddos_attack_latest_active", "1 if the most recent attack on this IP has no recorded end time yet (still ongoing).", labels, active),
			}
			if latest.AttackEnd != 0 {
				points = append(points, gaugePoint("servcity_ddos_attack_latest_end_timestamp_seconds", "Unix end time of the most recent attack on this IP.", labels, latest.AttackEnd))
			}
		}
		p.replaceGroup("servcity_ddos_attack_latest_", labels, points)
		return
	}

	var generic interface{}
	_ = json.Unmarshal(raw, &generic)
	if arr, ok := generic.([]interface{}); ok {
		p.store.Set(gaugePoint("servcity_ddos_attacks_total", "Number of attack records returned for this IP by the last ddos/attacks call.", labels, float64(len(arr))))

		var points []store.Point
		if latest := flatten.LatestByTime(arr); latest != nil {
			fields := flatten.Numeric(latest, maxFlattenDepth)
			points = make([]store.Point, 0, len(fields))
			for name, val := range fields {
				points = append(points, gaugePoint(
					"servcity_ddos_attack_latest_"+name,
					"Field '"+name+"' of the most recent attack record for this IP. Discovered at runtime because the response didn't match the expected attacks-list shape.",
					labels, val,
				))
			}
		}
		p.replaceGroup("servcity_ddos_attack_latest_", labels, points)
		return
	}

	fields := flatten.Numeric(generic, maxFlattenDepth)
	points := make([]store.Point, 0, len(fields))
	for name, val := range fields {
		points = append(points, gaugePoint(
			"servcity_ddos_attacks_"+name,
			"Field '"+name+"' from the ddos/attacks response for this IP. Discovered at runtime because the response didn't match any expected shape.",
			labels, val,
		))
	}
	p.replaceGroup("servcity_ddos_attacks_", labels, points)
}

// pollIPFirewall handles GET /ddos/firewall/{IP}. It first tries the shape
// reverse-engineered from the dashboard (servcity.FirewallRulesResponse: a
// "rules" list), falling back to generic field flattening otherwise.
func (p *Poller) pollIPFirewall(ctx context.Context, ip string) {
	raw, err := p.client.GetFirewallRaw(ctx, ip)
	if err != nil {
		p.handleErr("ddos_firewall", err, false)
		return
	}
	labels := map[string]string{"ip": ip}

	var fw servcity.FirewallRulesResponse
	if jsonErr := json.Unmarshal(raw, &fw); jsonErr == nil && fw.Rules != nil {
		p.store.Set(gaugePoint("servcity_ddos_firewall_rules", "Number of firewall rules returned for this IP.", labels, float64(len(fw.Rules))))
		return
	}

	var generic interface{}
	_ = json.Unmarshal(raw, &generic)
	if arr, ok := generic.([]interface{}); ok {
		p.store.Set(gaugePoint("servcity_ddos_firewall_rules", "Number of firewall rules returned for this IP.", labels, float64(len(arr))))
		return
	}

	if obj, ok := generic.(map[string]interface{}); ok {
		for _, v := range obj {
			if arr, ok := v.([]interface{}); ok {
				p.store.Set(gaugePoint("servcity_ddos_firewall_rules", "Number of firewall rules returned for this IP.", labels, float64(len(arr))))
				return
			}
		}
		fields := flatten.Numeric(obj, 2)
		points := make([]store.Point, 0, len(fields))
		for name, val := range fields {
			points = append(points, gaugePoint(
				"servcity_ddos_firewall_"+name,
				"Field '"+name+"' from the ddos/firewall response for this IP. Discovered at runtime because the response didn't match any expected shape.",
				labels, val,
			))
		}
		p.replaceGroup("servcity_ddos_firewall_", labels, points)
	}
}

// --- tunnels --------------------------------------------------------------

func (p *Poller) pollTunnels(ctx context.Context) {
	tunnels, err := p.client.GetTunnels(ctx)
	if err != nil {
		p.handleErr("tunnels", err, true)
		return
	}
	p.setUp(true)
	p.store.Set(gaugePoint("servcity_tunnels_total", "Number of WireGuard tunnels on this account.", nil, float64(len(tunnels))))

	current := make(map[string]bool, len(tunnels))
	points := make([]store.Point, 0, len(tunnels)*3)
	for _, t := range tunnels {
		if t.UUID == "" {
			continue
		}
		current[t.UUID] = true
		labels := map[string]string{"tunnel_id": t.UUID}

		points = append(points, store.Point{
			Name:   "servcity_tunnel_info",
			Help:   "Static info about a tunnel; value is always 1.",
			Type:   prometheus.GaugeValue,
			Labels: map[string]string{"tunnel_id": t.UUID, "public_key": t.PublicKey},
			Value:  1,
		})

		if t.ReceiveBytes != nil {
			points = append(points, store.Point{
				Name: "servcity_tunnel_receive_bytes_total", Help: "Total bytes received on this tunnel.",
				Type: prometheus.CounterValue, Labels: labels, Value: float64(*t.ReceiveBytes),
			})
		}
		if t.TransmitBytes != nil {
			points = append(points, store.Point{
				Name: "servcity_tunnel_transmit_bytes_total", Help: "Total bytes transmitted on this tunnel.",
				Type: prometheus.CounterValue, Labels: labels, Value: float64(*t.TransmitBytes),
			})
		}
		if ts, ok := flatten.ParseTimestamp(t.LastHandshakeTime); ok {
			points = append(points, gaugePoint("servcity_tunnel_last_handshake_timestamp_seconds", "Unix timestamp of the last WireGuard handshake on this tunnel.", labels, ts))
		}
	}
	p.store.SetAll(points)

	p.store.DeleteWhere(func(pt store.Point) bool {
		id, ok := pt.Labels["tunnel_id"]
		return ok && !current[id]
	})
}

// --- minecraft proxies -----------------------------------------------------

func (p *Poller) pollMinecraftProxies(ctx context.Context) {
	ids, err := p.client.GetAllowedProxies(ctx)
	if err != nil {
		p.handleErr("minecraft_allowed_proxies", err, true)
		return
	}
	p.setUp(true)
	p.store.Set(gaugePoint("servcity_minecraft_proxies_total", "Number of Minecraft proxies authorized on this account.", nil, float64(len(ids))))

	current := make(map[string]bool, len(ids))
	for _, id := range ids {
		current[id] = true
	}
	p.fanOut(ids, func(id string) {
		p.pollProxy(ctx, id)
	})

	p.store.DeleteWhere(func(pt store.Point) bool {
		id, ok := pt.Labels["proxy_id"]
		return ok && !current[id]
	})
}

func (p *Poller) pollProxy(ctx context.Context, id string) {
	labels := map[string]string{"proxy_id": id}
	points := make([]store.Point, 0, 4)

	if conf, err := p.client.GetProxy(ctx, id); err != nil {
		p.handleErr("minecraft_proxy", err, false)
	} else {
		points = append(points, store.Point{
			Name: "servcity_minecraft_proxy_info", Help: "Static info about a Minecraft proxy; value is always 1.",
			Type: prometheus.GaugeValue, Labels: map[string]string{"proxy_id": id, "dst_ip": conf.DstIP}, Value: 1,
		})
		points = append(points, gaugePoint("servcity_minecraft_proxy_dst_port", "Configured destination port for this proxy.", labels, float64(conf.DstPort)))
	}

	if ports, err := p.client.GetProxyPorts(ctx, id); err != nil {
		p.handleErr("minecraft_proxy_ports", err, false)
	} else {
		points = append(points, gaugePoint("servcity_minecraft_proxy_java_port", "Java Edition listen port for this proxy.", labels, float64(ports.JavaPort)))
		points = append(points, gaugePoint("servcity_minecraft_proxy_bedrock_port", "Bedrock Edition listen port for this proxy.", labels, float64(ports.BedrockPort)))
	}

	p.store.SetAll(points)
}

// --- shared helpers ---------------------------------------------------

func (p *Poller) setUp(v bool) {
	f := 0.0
	if v {
		f = 1
	}
	p.store.Set(gaugePoint("servcity_up", "1 if the last call to the ServCity API succeeded, 0 if authentication or connectivity failed.", nil, f))
}

// handleErr records a failed poll. authCritical should be true only for
// account-wide identity calls (account limits, allowed-IP list, tunnels,
// Minecraft proxy list) - the ones that call setUp(true) on success. A 401
// from those genuinely means the credentials are bad. Per-resource calls
// (one IP's config/metrics/attacks/firewall, one proxy's detail) pass
// false: a live account has been observed getting a real HTTP 401 from
// GET /ddos/attacks/{IP} with credentials that work fine on every other
// endpoint (apparently a backend quirk, likely for IPs with no attack
// history yet) - letting that flip the global servcity_up gauge would make
// it flap misleadingly for accounts that are actually fine.
func (p *Poller) handleErr(endpoint string, err error, authCritical bool) {
	var authErr *servcity.AuthError
	if authCritical && errors.As(err, &authErr) {
		p.setUp(false)
	}
	n := p.incError(endpoint)
	p.store.Set(store.Point{
		Name:   "servcity_exporter_scrape_errors_total",
		Help:   "Count of failed ServCity API calls, by endpoint.",
		Type:   prometheus.CounterValue,
		Labels: map[string]string{"endpoint": endpoint},
		Value:  float64(n),
	})
	p.log.Warn("poll failed", "endpoint", endpoint, "error", err)
}

func (p *Poller) incError(endpoint string) uint64 {
	v, _ := p.errCounters.LoadOrStore(endpoint, new(uint64))
	return atomic.AddUint64(v.(*uint64), 1)
}

// replaceGroup swaps out every existing series whose metric name starts
// with prefix and whose labels match, for the freshly-polled set of
// points. Used for the dynamically-named metric groups (whatever fields
// the undocumented endpoints happen to return this cycle) so a field that
// disappears from the API response doesn't linger in /metrics forever with
// a stale value.
func (p *Poller) replaceGroup(prefix string, matchLabels map[string]string, points []store.Point) {
	p.store.DeleteWhere(func(pt store.Point) bool {
		if !strings.HasPrefix(pt.Name, prefix) {
			return false
		}
		for k, v := range matchLabels {
			if pt.Labels[k] != v {
				return false
			}
		}
		return true
	})
	p.store.SetAll(points)
}

func gaugePoint(name, help string, labels map[string]string, value float64) store.Point {
	return store.Point{Name: name, Help: help, Type: prometheus.GaugeValue, Labels: labels, Value: value}
}
