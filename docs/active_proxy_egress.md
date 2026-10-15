# Active Proxy Egress — Operator Guide (Hypermass)

The engine has two egress profiles:

- **Passive / default** — OSINT and data sources, registry lookups (RDAP,
  WHOIS, GLEIF, BGP.Tools), and **all DNS** (forward and reverse). This traffic
  never touches a target asset directly and always uses the engine's default
  network.
- **Active** — anything that connects to a target asset and so is detectable by
  it, in or out of scope: port connect scans, HTTP/HTTPS probes, raw TLS and
  JARM handshakes, and TLS certificate harvesting.

`active_proxy` routes **all** active traffic through an operator-specified
proxy. DNS is never proxied, by design: DNS is detectable but not treated as a
reconnaissance signal.

## The guarantee

When an `active_proxy` is configured, active traffic goes through it or not at
all. There is no fallback to the default network.

- **At start-up** the engine checks the proxy before dispatching any work. If
  the proxy cannot be reached or will not relay, the session is refused with an
  error.
- **Mid-run** the engine does not watch the proxy. If it fails, active
  operations fail with it: port scans see every port as closed, and HTTP, TLS
  and JARM probes return nothing. No traffic goes out directly. Results from a
  run that lost its proxy are incomplete, so the proxy must be monitored
  externally and affected enumerations stopped and rerun (see below).

## Configuration

| Setting | CLI flag | YAML (`options:`) | JSON field | Default |
|---|---|---|---|---|
| Enable active mode | `-active` | `active: true` | `"active": true` | false |
| Active proxy URL | `-active-proxy <url>` | `active_proxy: <url>` | `"active_proxy"` | `""` |
| Fail-closed policy | `-active-strict=<bool>` | `active_strict: <bool>` | `"active_strict"` | **true** |

Supported proxy schemes: `socks5://`, `socks5h://`, `http://`, `https://`.
SOCKS5 and HTTP CONNECT both tunnel raw TCP, which the TLS/JARM/banner probes
need. A bare `host:port` is rejected — include the scheme.

### How the three cases behave

- **`-active` with `-active-proxy`** → all active traffic goes through the
  proxy, whatever `-active-strict` says.
- **`-active`, no proxy, strict (the default)** → refused. The engine will not
  start the run rather than send active traffic over the default network. You
  must pass a proxy or opt out.
- **`-active`, no proxy, `-active-strict=false`** → active traffic uses the
  default network, exactly as a run with no proxy did before this feature. Use
  this for local testing, or for a target you are cleared to probe directly.

`active_strict` defaults to `true` even for engine API payloads that omit it,
so a minimal JSON body cannot silently weaken the policy.

## Usage

Docker compose CLI (the enum container passes the config to the engine, which
dials the proxy):

```bash
docker compose run --rm enum \
  -d example.com -active -p 80,443,8080,8443 \
  -active-proxy socks5h://proxy.internal:1080
```

With proxy authentication: `socks5h://user:pass@proxy.internal:1080`.

Opt out of the proxy for a direct active run (testing):

```bash
docker compose run --rm enum -d example.com -active -active-strict=false
```

Engine REST API (`POST /api/v1/sessions`): include `"active": true` and
`"active_proxy": "..."`. A payload with `"active": true` and no proxy, without
`"active_strict": false`, is rejected with HTTP 400.

## What goes where

| Traffic | Through `active_proxy`? |
|---|---|
| Port connect scans (Port-Prefilter, FQDN-pipeline scans) | Yes |
| HTTP/HTTPS service probes | Yes |
| Raw TLS / JARM fingerprinting | Yes |
| TLS certificate harvesting (Protocol-Probes) | Yes |
| OSINT and data sources | No — default network |
| RDAP, WHOIS, GLEIF, BGP.Tools | No — default network |
| Forward and reverse DNS | No — default network |

## When the proxy fails

At start-up, a dead proxy is reported and the session is not created:

- The engine log records `failed to create session` with
  `error="active proxy <url> is not usable: ..."`.
- `POST /api/v1/sessions` returns HTTP 500, `"error": "failed to create
  session"`, with the reason in `"details"`.
- `oam_enum` prints `Failed to create a session with the Amass engine:
  createSession: status=500 ... error=failed to create session: active proxy
  <url> is not usable: ...` and exits non-zero.

Mid-run, nothing is reported by the engine. Detecting the failure is the job
of an external monitor, which should stop the affected engines and prevent new
enumerations until the proxy is restored (the start-up check also refuses
them). A run that lost its proxy has recorded ports as closed and marked its
probes as done, so rerun it once the relevant TTLs have expired.

## Network setup

The **engine** container dials the proxy (not the enum container), so the
engine's network must have a route to the proxy host:port. The proxy must be
able to reach the targets. For defence in depth, block direct
engine-to-target connections at the firewall: even a bug could then not leak
active traffic.
