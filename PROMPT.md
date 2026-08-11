# Build a Prometheus Exporter for the ServCity User API

## Context

ServCity (servcity.org) offers DDoS-protected IP hosting, WireGuard GRE-style
tunnels, and Minecraft proxies. Their "User API" (v2.0, Swagger 2.0) lets
customers manage and inspect their own account's resources.

- Spec source: `https://servcity.org/uapi/swagger.yml` (rendered docs at
  `https://servcity.org/uapi/docs`)
- Base URL: `https://servcity.org/uapi/`
- Auth: HTTP **Basic** auth (`securityDefinitions.apiKey.type: basic`). Every
  endpoint except `/ddos/availablefilters` requires it. Obtain a key via
  `POST /user/login` (email+password, **resets** any existing linked key) or
  `POST /user/loginapikey` (creates an independent key without resetting the
  linked one). Manage keys via `GET/POST /user/apikey` and
  `DELETE /user/apikey/{token}`.
  - **Verify empirically before writing the HTTP client**: confirm whether
    the key goes in the Basic-auth username slot with an empty password, or
    as the password with a fixed/blank username. The spec's `type: basic`
    is unusual for what's conceptually an API key — don't assume, test it
    against a real account first.

## Known spec gaps — resolve these before writing parsers

The spec has several `$ref`s to schemas that are **never defined** in the
`definitions` block (some are literally marked `# Placeholder` in the source
YAML). Do not guess these shapes — call the live endpoints with a real
account and API key, capture a sample response, and derive the struct/model
from that:

- `IPMetrics` — response of `GET /ddos/metrics/{IP}` and
  `GET /ddos/metrics/{IP}/{HOURS}`. This is the primary traffic/metrics
  payload the exporter cares about (packet/byte rates, attack state, etc.)
  and it's completely undocumented. Sample it first.
- `AttacksForIP` — response of `GET /ddos/attacks/{IP}` (list of attacks).
- `AttackDetails` — response of `GET /ddos/attacks/{IP}/{ID}`.
- `FWForIP` — response of `GET /ddos/firewall/{IP}` (firewall rule list).
- `Config.blacklist_conf` (`$ref: BlackListSelector`) — nested field on the
  otherwise-documented `Config` object.
- `proxyConf.offlineMotd` (`$ref: MOTD`) — nested field on `proxyConf`.
- `FlowMapEntry`, `FWKeyValue`, `FwValue` — request bodies for firewall
  mutation endpoints (not needed for a read-only exporter, ignore unless
  you add write support).

If any of these can't be reached without a paid/active account, build the
exporter defensively: log the raw JSON on parse failure instead of crashing,
and expose only the fields you've actually confirmed exist.

## Goal

A standalone Prometheus exporter binary/service that:

1. Polls the ServCity API on an interval.
2. Discovers the account's monitorable resources automatically (don't
   hardcode IPs/tunnel IDs/proxy UUIDs — enumerate them):
   - `GET /ddos/getAllowedIps` → IPs to poll for DDoS metrics/config/firewall
   - `GET /tunnel` → this account's WireGuard tunnels
   - `GET /minecraft/getAllowedProxies` → this account's Minecraft proxies
   - `GET /user/limits` → account-level limits/usage
3. Exposes everything on `GET /metrics` in Prometheus text format.
4. Runs continuously (systemd service / Docker container), independent of
   any scrape — cache the last-good value per series so a slow or failing
   upstream call doesn't blank out the whole `/metrics` page.

## Proposed metrics

Prefix everything `servcity_`. Use `ip` as a label on all DDoS metrics,
`tunnel_id` on tunnel metrics, `proxy_id`/`proxy_uuid` on Minecraft metrics.

### Account (`GET /user/limits`)
- `servcity_account_remaining_proxies` (gauge) — `allowedRemainingProxies`
- `servcity_account_authorized_subnets` (gauge) — count of
  `authorizedTargetSubnets`

### DDoS config (`GET /ddos/config/{IP}`)
- `servcity_ddos_protection_enabled{ip}` (gauge, 0/1) — from `firewall_enable`
- One gauge per other boolean toggle worth tracking as a 0/1 state, e.g.
  `servcity_ddos_learning_mode{ip}`, `servcity_ddos_strict_mode{ip}`,
  `servcity_ddos_symmetric{ip}`, `servcity_ddos_synflood_filter{ip}`,
  `servcity_ddos_dynamic_filter{ip}`, `servcity_ddos_whitelisted{ip}` — derive
  the full list from the actual `Config` schema fields already in the spec
  (17 booleans are listed; expose the ones that are operationally useful,
  don't blindly dump all 17 unless the user wants a full state mirror).

### DDoS metrics (`GET /ddos/metrics/{IP}` or `/ddos/metrics/{IP}/{HOURS}`)
- Shape TBD (see gaps above). Expect something like packets/bytes per
  second, dropped vs. passed traffic, and possibly an under-attack flag.
  Map each numeric field to a `servcity_ddos_<field>{ip}` gauge or counter
  (counter if monotonic/cumulative, gauge if a point-in-time rate).
  Use the `/{HOURS}` variant only if you need backfill on startup —
  otherwise poll the default (last 6h) endpoint and track only the latest
  sample per scrape.

### DDoS attacks (`GET /ddos/attacks/{IP}`, `GET /ddos/attacks/{IP}/{ID}`)
- `servcity_ddos_attacks_total{ip}` (gauge or counter, TBD from schema) —
  count of attacks returned
- `servcity_ddos_under_attack{ip}` (gauge, 0/1) — derive from whether an
  attack is currently active, if the schema exposes a status/end-time field
- Consider a per-attack `Info`-style metric
  (`servcity_ddos_attack_info{ip,attack_id,...}` = 1) if attacks carry
  useful categorical detail (attack type, source count, etc.) — decide once
  the real schema is known.

### Firewall (`GET /ddos/firewall/{IP}`)
- `servcity_ddos_firewall_rules{ip}` (gauge) — count of rules returned
  (exact structure TBD, see gaps above)

### Tunnels (`GET /tunnel` → array of `tunnelConf`)
This one IS fully documented — build it first, it's the easy win:
- `servcity_tunnel_receive_bytes_total{tunnel_id}` (counter) —
  `receive_bytes`
- `servcity_tunnel_transmit_bytes_total{tunnel_id}` (counter) —
  `transmit_bytes`
- `servcity_tunnel_last_handshake_timestamp_seconds{tunnel_id}` (gauge) —
  parse `last_handshake_time`
- `servcity_tunnel_info{tunnel_id, public_key}` (gauge, always 1) — for
  joining/labeling in Grafana

### Minecraft proxies (`GET /minecraft/getAllowedProxies`, then per-proxy
`GET /minecraft/proxy/{uuid}` and `GET /minecraft/proxy/{proxyID}/port`)
- `servcity_minecraft_proxies_total` (gauge) — count of allowed proxies
- `servcity_minecraft_proxy_info{proxy_uuid, dst_ip, dst_port}` (gauge,
  always 1)
- `servcity_minecraft_proxy_java_port{proxy_id}` /
  `servcity_minecraft_proxy_bedrock_port{proxy_id}` (gauge)

### Exporter self-metrics (standard practice, don't skip)
- `servcity_exporter_scrape_duration_seconds` (histogram or gauge, per
  endpoint group)
- `servcity_exporter_scrape_errors_total{endpoint}` (counter)
- `servcity_exporter_up` (gauge, 0/1) — whether the last poll of the
  ServCity API succeeded at all
- `servcity_exporter_build_info{version}` (gauge, always 1)

## Architecture requirements

- **Language**: Go, using `prometheus/client_golang` — the idiomatic choice
  for exporters, produces a single static binary, easy to containerize. (If
  the user prefers Python + `prometheus_client`, that's a fine substitute —
  flag it as an open choice, don't silently assume.)
- **Polling model**: background goroutine(s)/thread(s) polling on a
  configurable interval (default e.g. 30s for DDoS/config data, maybe
  longer for slow-changing data like account limits and Minecraft proxy
  list — split into separate poll loops with separate intervals rather than
  one big interval for everything). Cache last-good values in memory;
  `/metrics` always serves from cache, never blocks on a live upstream call.
- **Config**: environment variables (12-factor) with a YAML file as an
  optional override, at minimum:
  - `SERVCITY_API_BASE_URL` (default `https://servcity.org/uapi`)
  - `SERVCITY_API_KEY` (required, never logged)
  - `SERVCITY_POLL_INTERVAL` (default `30s`)
  - `SERVCITY_LISTEN_ADDR` (default `:9200`, or whatever's free in the
    Prometheus exporter default-port list — check
    https://github.com/prometheus/prometheus/wiki/Default-port-allocations
    for a genuinely unused port before picking one)
- **HTTP client**: sane timeout (e.g. 10s), retry with backoff on 5xx/
  network errors, treat 401 as a hard config error (log loudly, keep
  `servcity_exporter_up` at 0, don't tight-loop retry credentials).
- **Concurrency**: fan out per-IP / per-tunnel / per-proxy requests
  concurrently (bounded worker pool) rather than serially, since account
  limits could mean dozens of IPs/tunnels.
- **Logging**: structured (e.g. `slog`), API key redacted, one line per
  poll cycle summarizing success/failure counts.
- **Deliverables**:
  - `main.go` (or equivalent) + package structure
  - `Dockerfile` (multi-stage, scratch/distroless final image)
  - `docker-compose.yml` or systemd unit example for local run
  - `README.md`: config reference, example `docker run`, example Prometheus
    scrape config, example Grafana panel list
  - Unit tests for the metric-mapping logic using recorded fixture JSON
    (capture real sample responses during the schema-discovery step above
    and check them into `testdata/`)

## Suggested build order

1. Get a real API key; hit `/user/limits`, `/tunnel`,
   `/ddos/getAllowedIps`, `/ddos/metrics/{IP}` and `/ddos/attacks/{IP}`
   manually (curl/Postman) against a live account and save the raw JSON —
   this resolves every "TBD" above.
2. Scaffold the exporter with just the fully-documented tunnel metrics
   (no schema guesswork) to get the collector/registry/HTTP-server
   plumbing working end-to-end.
3. Add account limits and DDoS config (also fully documented).
4. Add DDoS metrics/attacks/firewall using the real schemas captured in
   step 1.
5. Add Minecraft proxy metrics.
6. Add self-metrics, Dockerfile, README, tests.
