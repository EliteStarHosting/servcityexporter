# servcityexporter

A [Prometheus](https://prometheus.io/) exporter for the [ServCity](https://servcity.org)
User API (DDoS protection, WireGuard tunnels, and Minecraft proxies).

It polls your ServCity account on an interval and exposes the results on
`/metrics` in Prometheus text format.

## Quick start

```bash
docker run -d \
  --name servcityexporter \
  -p 9420:9420 \
  -e SERVCITY_API_KEY=your-api-key \
  ghcr.io/elitestarhosting/servcityexporter:latest
```

Then point Prometheus at it:

```yaml
scrape_configs:
  - job_name: servcity
    static_configs:
      - targets: ["localhost:9420"]
```

Get an API key from your ServCity account via `POST /user/loginapikey`
(creates an independent key) or `POST /user/login` (**resets** any
already-linked key) — see the
[API docs](https://servcity.org/uapi/docs#/user).

## Configuration

All configuration is via environment variables.

| Variable                      | Default                     | Description                                                              |
| ------------------------------ | ---------------------------- | -------------------------------------------------------------------------- |
| `SERVCITY_API_KEY`             | *(required)*                 | Your ServCity API key.                                                     |
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
few gaps that shape how this exporter behaves:

- **Auth.** The spec declares `type: basic` for its `apiKey` security
  scheme. This exporter sends your key as the HTTP Basic-auth *username*
  with an empty password. That hasn't been confirmed against ServCity's
  actual behavior — if every request 401s, that's the first thing to
  check (see `internal/servcity/client.go`).
- **Undocumented response shapes.** `IPMetrics` (`GET /ddos/metrics/{IP}`),
  `AttacksForIP` (`GET /ddos/attacks/{IP}`), and `FWForIP`
  (`GET /ddos/firewall/{IP}`) are referenced in the spec but never
  defined. Rather than guess field names, the exporter decodes these
  responses generically at runtime: every numeric or boolean leaf becomes
  its own metric, named from its JSON key path (see
  `internal/flatten`). This means metric names under `servcity_ddos_metric_*`,
  `servcity_ddos_attack_latest_*`, and `servcity_ddos_firewall_*` are
  discovered from your account's actual API responses rather than
  hard-coded — inspect a live `/metrics` output to see exactly what your
  account returns, and treat units/semantics as unverified until you've
  cross-checked them against the ServCity dashboard.

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
| `servcity_ddos_metrics_samples` | gauge | `ip` | Number of samples in the last `ddos/metrics` response. |
| `servcity_ddos_metric_<field>` | gauge | `ip` | Numeric field from the most recent metrics sample (runtime-discovered, see above). |
| `servcity_ddos_attacks_total` | gauge | `ip` | Number of attack records in the last `ddos/attacks` response. |
| `servcity_ddos_attack_latest_<field>` | gauge | `ip` | Numeric field from the most recent attack record (runtime-discovered). |
| `servcity_ddos_firewall_rules` | gauge | `ip` | Number of firewall rules for this IP. |

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
