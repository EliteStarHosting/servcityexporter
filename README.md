# servcityexporter

A [Prometheus](https://prometheus.io/) exporter for the [ServCity](https://servcity.org)
User API (DDoS protection, WireGuard tunnels, and Minecraft proxies).

It polls your ServCity account on an interval and exposes the results on
`/metrics` in Prometheus text format.

## Quick start

Get an API key/secret pair — run this yourself with your own ServCity
login (email/password), it returns credentials this exporter uses, not
your account password itself:

```bash
curl -X POST "https://servcity.org/uapi/user/loginapikey" \
  -H "Content-Type: application/json" \
  -d '{"email":"you@example.com","password":"your-servcity-password"}'
# => {"id": "...", "secret": "...", "success": true}
```

(`loginapikey` creates an independent key without disturbing one already
linked to your account; use `/user/login` instead only if you specifically
want to reset an existing linked key.)

```bash
docker run -d \
  --name servcityexporter \
  --restart unless-stopped \
  -p 9420:9420 \
  -e SERVCITY_API_KEY_ID='the "id" value' \
  -e SERVCITY_API_KEY_SECRET='the "secret" value' \
  ghcr.io/elitestarhosting/servcityexporter:latest
```

Then point Prometheus at it:

```yaml
scrape_configs:
  - job_name: servcity
    static_configs:
      - targets: ["localhost:9420"]
```

A ready-to-run exporter + Prometheus + Grafana stack is in
[`deploy/`](deploy/):

```bash
cd deploy
cp .env.example .env   # fill in SERVCITY_API_KEY_ID / SERVCITY_API_KEY_SECRET
docker compose up -d
```

Grafana (`http://localhost:3000`, default login `admin` / whatever you set
`GRAFANA_ADMIN_PASSWORD` to) comes up with the Prometheus datasource and
the [ServCity dashboard](deploy/grafana/dashboards/servcity-dashboard.json)
already provisioned — no manual setup. Prefer to add it to an existing
Grafana yourself instead: **Dashboards → Import**, upload
`deploy/grafana/dashboards/servcity-dashboard.json`, point it at your
Prometheus datasource.

The dashboard has an `$ip` picker and covers: the traffic-category
breakdown (the same graph as ServCity's own "Traffic Analysis" widget),
a drop-rate gauge, per-category 6h peaks, attack status/history, DDoS
config toggles, firewall rule count, tunnel throughput, and exporter
health (scrape duration/errors, `servcity_up`).

## Configuration

All configuration is via environment variables.

| Variable                      | Default                     | Description                                                              |
| ------------------------------ | ---------------------------- | -------------------------------------------------------------------------- |
| `SERVCITY_API_KEY_ID`          | *(required)*                 | The `id` from `POST /user/loginapikey`. Used as the Basic-auth username.   |
| `SERVCITY_API_KEY_SECRET`      | *(required)*                 | The `secret` from `POST /user/loginapikey`. Used as the Basic-auth password. |
| `SERVCITY_API_BASE_URL`        | `https://servcity.org/uapi`  | API base URL.                                                              |
| `SERVCITY_LISTEN_ADDR`         | `:9420`                      | Address the `/metrics` HTTP server binds to.                               |
| `SERVCITY_POLL_INTERVAL`       | `30s`                        | How often per-IP DDoS data and tunnel counters are refreshed.              |
| `SERVCITY_DISCOVERY_INTERVAL`  | `5m`                         | How often account limits, the authorized-IP list, and the Minecraft proxy list are refreshed. |
| `SERVCITY_REQUEST_TIMEOUT`     | `10s`                        | Timeout for a single ServCity API call.                                    |

`/metrics` always serves the last successfully polled value for each
series — a slow or failing upstream call never blanks the page or blocks a
scrape.

Other endpoints: `/healthz` (liveness) and `/` (index page).

## A note on the upstream API

The [ServCity OpenAPI spec](https://servcity.org/uapi/swagger.yml) has a
few gaps. Everything below was confirmed by running this exporter against
a real account, not guessed:

- **Auth.** The spec declares `type: basic` for its `apiKey` security
  scheme but doesn't say what goes in the username/password slots.
  Confirmed: `POST /user/loginapikey` returns `{"id": ..., "secret": ...}`,
  and the API expects `id` as the Basic-auth username and `secret` as the
  password — not the secret alone in either slot.
- **`IPMetrics`, `AttacksForIP`, `FWForIP` — undocumented in the spec,
  reverse-engineered, then confirmed live.** These three are `$ref`'d in
  the spec but never defined — the live Swagger UI's own "Example Value"
  for them is the literal placeholder `"string"`. Their shapes were
  recovered from ServCity's own DDoS Protection dashboard
  (`prot.servcity.org`): its Next.js frontend is public and
  unauthenticated even though its data isn't, so its JS bundle — which
  calls `/api/traffic-metrics?ip=&hours=`, `/api/attacks?ip=`, and
  `/api/firewall?ip=`, a backend-for-frontend proxying the corresponding
  `/ddos/*` endpoints — was fetched and read directly (no login needed for
  static assets) to recover the real field names. Then verified against
  the actual `/ddos/*` endpoints with a live account: `graph_data`/
  `metric_name`/`data`/`timestamp`/`value` for metrics, `attacks`/
  `attack_uuid`/`attack_start_time`/`attack_end_time`/`attack_peakbps`/
  `attack_peakpps` for attacks (newest-first), and `rules` for firewall —
  all matched exactly. `internal/servcity/types.go` documents the
  reasoning in full.

  The traffic-category names (`passed`, `tcp_generic_drop`,
  `udp_amplification_drop`, etc. — see the Metrics section below) are the
  real values a live account returns, confirmed against the exact same
  "Traffic Analysis" graph ServCity's own dashboard renders. The exporter
  still tries the confirmed shape first and falls back to generic runtime
  field-discovery (`servcity_ddos_metric_*` / `servcity_ddos_attacks_*` /
  `servcity_ddos_firewall_*`, see `internal/flatten`) if a response ever
  doesn't match it — defensive, since ServCity could change this
  undocumented shape without notice.
- **`GET /ddos/attacks/{IP}` returns HTTP 401 for IPs with no attack
  history**, with the same credentials that work fine on every other
  endpoint (and other IPs on the same account). Confirmed against a live
  36-IP account: exactly the IPs with zero recorded attacks got a 401
  `{"message":"Unauthorized/Server Error"}`; every IP with real attack
  history returned normally. The exporter treats this as a per-IP,
  non-fatal error (counted in `servcity_exporter_scrape_errors_total`) and
  does **not** let it flip the account-wide `servcity_up` gauge, since it's
  not actually a credentials problem.
- **Rate limiting / anti-bot challenge on bursts.** Polling many IPs at
  once (confirmed with 36) can trigger ServCity's own proof-of-work
  anti-bot layer — an HTTP 403 with a `"pow"` field in the body — on
  `/ddos/config`, `/ddos/metrics`, and `/ddos/firewall`. The exporter
  staggers per-IP requests (`requestStagger` in `internal/poller`) and
  caps concurrency at 4 in-flight requests specifically to stay under
  this; confirmed clean (zero errors besides the expected
  no-attack-history 401s above) against the same 36-IP account. If you
  have a much larger number of IPs and still see `servcity_ddos_config_*`
  etc. missing along with `ddos_config`/`ddos_metrics`/`ddos_firewall`
  errors in `servcity_exporter_scrape_errors_total`, raise
  `SERVCITY_POLL_INTERVAL`.

## Metrics

### Account

| Metric | Type | Labels | Description |
| --- | --- | --- | --- |
| `servcity_account_remaining_proxies` | gauge | | Remaining Minecraft proxy slots. |
| `servcity_account_authorized_subnets` | gauge | | Number of authorized target subnets. |

### DDoS

| Metric | Type | Labels | Description |
| --- | --- | --- | --- |
| `servcity_ddos_authorized_ips` | gauge | | Number of IPs authorized for DDoS protection. |
| `servcity_ddos_config_<toggle>` | gauge | `ip` | One series per config boolean (e.g. `firewall_enable`, `learning_mode`, `strict`); 1=enabled. |
| `servcity_ddos_traffic_<category>` | gauge | `ip` | Latest value for a DDoS traffic category, e.g. `passed`, `tcp_generic_drop`, `tcp_banned_drop`, `tcp_out_of_state_drop`, `udp_generic_drop`, `udp_banned_drop`, `udp_fragment_drop`, `udp_amplification_drop`, `l7_invalid_drop`, `other_drop` — the exact category set is whatever your account's API returns. Units unconfirmed. |
| `servcity_ddos_traffic_<category>_max` / `_min` / `_avg` | gauge | `ip` | Min/max/average for that category across the *entire* response window (last 6h by default) — not just whatever value landed on a poll tick, so a spike between polls still shows up. |
| `servcity_ddos_traffic_samples` | gauge | `ip`, `category` | Number of samples returned for a traffic category by the last `ddos/metrics` call. |
| `servcity_ddos_attacks_total` | gauge | `ip` | Number of attack records in the last `ddos/attacks` response. |
| `servcity_ddos_attack_latest_peak_bps` | gauge | `ip` | Peak bits/sec of the most recent attack. |
| `servcity_ddos_attack_latest_peak_pps` | gauge | `ip` | Peak packets/sec of the most recent attack. |
| `servcity_ddos_attack_latest_start_timestamp_seconds` | gauge | `ip` | Unix start time of the most recent attack. |
| `servcity_ddos_attack_latest_end_timestamp_seconds` | gauge | `ip` | Unix end time of the most recent attack; absent if still ongoing. |
| `servcity_ddos_attack_latest_active` | gauge | `ip` | 1 if the most recent attack has no recorded end time yet. |
| `servcity_ddos_firewall_rules` | gauge | `ip` | Number of firewall rules for this IP. |
| `servcity_ddos_metric_<field>` / `servcity_ddos_attacks_<field>` / `servcity_ddos_firewall_<field>` | gauge | `ip` | Fallback series, only present if a response didn't match the typed shapes above — runtime-discovered field names (see "A note on the upstream API"). |

### Tunnels

| Metric | Type | Labels | Description |
| --- | --- | --- | --- |
| `servcity_tunnels_total` | gauge | | Number of WireGuard tunnels on the account. |
| `servcity_tunnel_info` | gauge | `tunnel_id`, `public_key` | Always 1; join key for labeling. |
| `servcity_tunnel_receive_bytes_total` | counter | `tunnel_id` | Bytes received. |
| `servcity_tunnel_transmit_bytes_total` | counter | `tunnel_id` | Bytes transmitted. |
| `servcity_tunnel_last_handshake_timestamp_seconds` | gauge | `tunnel_id` | Unix time of the last WireGuard handshake. |

### Minecraft

| Metric | Type | Labels | Description |
| --- | --- | --- | --- |
| `servcity_minecraft_proxies_total` | gauge | | Number of authorized Minecraft proxies. |
| `servcity_minecraft_proxy_info` | gauge | `proxy_id`, `dst_ip` | Always 1. |
| `servcity_minecraft_proxy_dst_port` | gauge | `proxy_id` | Configured destination port. |
| `servcity_minecraft_proxy_java_port` | gauge | `proxy_id` | Java Edition listen port. |
| `servcity_minecraft_proxy_bedrock_port` | gauge | `proxy_id` | Bedrock Edition listen port. |

### Exporter self-metrics

| Metric | Type | Labels | Description |
| --- | --- | --- | --- |
| `servcity_up` | gauge | | 1 if the last ServCity API call succeeded, 0 on auth/connectivity failure. |
| `servcity_exporter_scrape_duration_seconds` | gauge | `loop` (`fast`/`slow`) | Duration of the last poll cycle. |
| `servcity_exporter_scrape_errors_total` | counter | `endpoint` | Failed API calls by endpoint. |
| `servcity_exporter_build_info` | gauge | `version` | Always 1. |

## Building from source

```bash
go build ./...
go test ./...
```

## Docker image

Published to GHCR on every push to `main` and on version tags:

```
ghcr.io/elitestarhosting/servcityexporter:latest
ghcr.io/elitestarhosting/servcityexporter:vX.Y.Z
```

Multi-arch: `linux/amd64` and `linux/arm64`.

## License

[MIT](LICENSE)
