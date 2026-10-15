# Hypermass Engine API Reference (v1)

This is the reference for driving Hypermass engines directly over their API, as
an orchestrator does: creating enumeration sessions, feeding them seed assets,
monitoring them to completion, and shutting them down. It covers every endpoint
the engine serves, the session configuration they take, and the behaviour an
orchestrator has to account for.

It describes the `hypermass-1.1` branch. The machine-readable OpenAPI 2.0
(Swagger) spec generated from the same code is in
[`swagger.yaml`](swagger.yaml). Where the two differ in detail, this document
is the one checked against a running engine.

## Contents

1. [Overview](#1-overview)
2. [Running an engine](#2-running-an-engine)
3. [Conventions](#3-conventions)
4. [Running an enumeration end to end](#4-running-an-enumeration-end-to-end)
5. [Session configuration](#5-session-configuration)
6. [Endpoint reference](#6-endpoint-reference)
7. [Asset formats](#7-asset-formats)
8. [The log stream](#8-the-log-stream)
9. [Running a fleet](#9-running-a-fleet)
10. [Known issues](#10-known-issues)
- [Appendix A: default transformations](#appendix-a-default-transformations)
- [Appendix B: complete example session](#appendix-b-complete-example-session)

## 1. Overview

- **One process, one port.** An engine serves HTTP and WebSocket on TCP port
  **4000**, all endpoints under the base path **`/api/v1`**. The port is fixed
  in the code.
- **No authentication, no TLS.** Anyone who can reach port 4000 can create,
  read and stop sessions, and session configurations carry database passwords
  and data-source API keys in plain text. Keep engines on a private network
  that only the orchestrator can reach. Never expose port 4000.
- **Control plane only.** The API starts and monitors work. Enumeration
  results (names, addresses, services, certificates, relationships) are written
  to the asset database named in the session configuration, and are read from
  there, not through this API.
- **One session per engine.** An engine can host several sessions at once, but
  they share and split its connection limits, and some counters are global to
  the process. Hypermass is designed to run one session per engine container,
  with the container replaced between enumerations. See
  [Running a fleet](#9-running-a-fleet).

## 2. Running an engine

### Image and process

The repository's `Dockerfile` builds an image with the engine at `/bin/engine`
(alongside `enum`, `ae_isready` and the other tools). Inside the container:

| Item | Value |
|---|---|
| Home directory | `/` (`HOME=/`) |
| Output directory | `/.config/amass` (session temporary directories and, if used, the SQLite database) |
| Working directory | `/data` |
| Stop signal | `SIGINT` (the engine also shuts down cleanly on `SIGTERM`) |

Engine flags:

| Flag | Meaning |
|---|---|
| `-log-dir <path>` | Directory for the engine log file |
| `-silent` | No console output |
| `-nocolor` | No colour in console output |

### Start-up requirements

- **Outbound DNS to public resolvers.** At start-up the BGP.Tools plugin
  resolves `bgp.tools` through the engine's public resolver list. If that
  fails, the engine exits with
  `Failed to start the engine: failed to obtain the BGPTools IP address`.
  Engines need UDP/TCP 53 to public resolvers (8.8.8.8, 1.1.1.1, 9.9.9.9 and
  others) from the moment they start.
- **The output directory must exist** if any session uses the default SQLite
  database. The image creates it. Outside the image, create it first, or
  session creation fails with
  `failed to initialize database store: unable to open database file`.

### Readiness

The engine is ready when `GET /api/v1/health` returns 200. From inside the
image, `ae_isready --host <engine-host>` does the same check with a 2-second
timeout and exits 0 when ready, 1 when not. In local testing the API was ready
about 2 seconds after start; allow longer under load.

### The engine log

The engine writes its own log to the first of these that works (as one JSON
object per line in a file; as plain text on standard output):

1. `amass_engine_<YYYY-MM-DDTHH:MM:SS>.log` in `-log-dir`, if given;
2. syslog, if `SYSLOG_HOST` is set (with `SYSLOG_PORT` and `SYSLOG_TRANSPORT`);
3. `amass_engine_<...>.log` in the output directory;
4. standard output.

This log holds engine-level events: every API request (method, path,
duration), session-creation failures with their reason, plugin start-up, and
the plugins' own messages. Messages tied to a session, such as discoveries,
go to that session's [log stream](#8-the-log-stream) instead. Collect both.

### Environment variables read by the engine

| Variable | Used for |
|---|---|
| `SYSLOG_HOST`, `SYSLOG_PORT`, `SYSLOG_TRANSPORT` | Sending the engine log to syslog |
| `POSTAL_SERVER_HOST`, `POSTAL_SERVER_PORT` | The libpostal address-parsing service |
| `INFLUX_*` (the InfluxDB v3 client's standard variables, e.g. `INFLUX_HOST`, `INFLUX_TOKEN`, `INFLUX_DATABASE`) | Handler timing telemetry and [`GET /handler-stats`](#get-handler-stats) |
| `HTTP_PROXY`, `HTTPS_PROXY`, `NO_PROXY` | Honoured by the engine's normal HTTP clients (OSINT and registry lookups). Ignored by active traffic when the session has an `active_proxy`. In a session with `active_strict: false` and no proxy, the HTTP/HTTPS probes do honour them (raw connections do not), so leave them unset on engines that run such sessions. |

The `AMASS_DB_*` and `AMASS_ENGINE_*` variables are read by the `enum` CLI
only. The engine takes its database from each session's configuration.

### Request timeouts

The engine's HTTP server allows **15 seconds** to read a request and
15 seconds to write its response, and closes idle keep-alive connections after
60 seconds. A request that takes longer is cut off without a response.

## 3. Conventions

- **Content type.** Request and response bodies are JSON. Clients should send
  `Content-Type: application/json`; the engine does not require it.
- **Errors.** Every error response has this body:

  ```json
  {"error": "session not found", "details": "not found", "code": 404}
  ```

  `error` is a short fixed message, `details` (optional) gives the underlying
  reason, and `code` repeats the HTTP status.
- **Unknown routes and wrong methods** both return
  `404 {"error":"route not found","code":404}`. The engine does not return 405.
- **Session tokens** are UUIDs. A token that is not in UUID form does not match
  any route, so it also returns 404 `route not found`, not 400. A well-formed
  token for a session that does not exist (or has been terminated) returns
  404 `session not found`.
- **Asset type names in paths** are the Open Asset Model type names in
  lowercase with no separators: `fqdn`, `ipaddress`, `netblock`,
  `autonomoussystem`, `organization` and so on (full list in
  [Asset formats](#7-asset-formats)). Forms such as `autonomous_system` are
  rejected.

## 4. Running an enumeration end to end

This is the sequence the `enum` CLI performs, which an orchestrator should
reproduce. The intervals and counts are the CLI's.

### Step 1: wait for the engine

Poll `GET /api/v1/health` until it returns 200.

### Step 2: create the session

`POST /api/v1/sessions` with the [session configuration](#5-session-configuration).
On 201 the body holds the session token:

```json
{"sessionToken": "77947b4a-4d6b-4d1a-886e-3ae0fa95a546"}
```

How to treat failures:

| Response | Meaning | What to do |
|---|---|---|
| 400 `invalid JSON` / `invalid JSON object` / `invalid configuration` | The configuration is malformed, has no `scope`, or breaks the active-egress policy; `details` says which | Fix the configuration. Do not retry as is. |
| 500 `failed to create session`, `details` contains `active proxy ... is not usable` | Active proxy down or refusing to relay | Treat the proxy as down. Do not start enumerations until it is restored. |
| 500 `failed to create session`, anything else | Engine-side problem (database unreachable, output directory missing, etc.) | Investigate the engine; `details` and the engine log give the reason. |

### Step 3: connect to the log stream

Open the WebSocket `GET /api/v1/sessions/{token}/ws/logs` straight away and
store everything it sends. Session log records are only delivered to clients
connected at the time; anything logged while nobody is connected is lost. If
the connection drops, reconnect; the engine stops sending to a client as soon
as it disconnects.

### Step 4: submit the seed assets

The session does no work until assets are submitted. Submit:

- every domain in `scope.domains` as an `fqdn` asset;
- every address in `scope.ips` as an `ipaddress` asset;
- every CIDR in `scope.cidrs` as a `netblock` asset;
- every ASN in `scope.asns` as an `autonomoussystem` asset;
- any additional known host names as `fqdn` assets, in bulk batches of at most
  1,000.

Seeds and scope are separate. Scope (in the configuration) decides what the
engine treats as in scope; seeds start the work. A seed that is not also in
`scope` is processed but is not in scope: for example, an IP posted as an asset
but missing from `scope.ips` does not appear in `GET /scope/ipaddress`.
Submit each seed with [`POST /assets/{type}`](#post-sessionstokenassetstype)
or [`POST /assets/{type}:bulk`](#post-sessionstokenassetstypebulk), and check
each response: a bulk request reports how many items it stored.

### Step 5: monitor until the first pass is idle

Poll [`GET /sessions/{token}/stats`](#get-sessionstokenstats) every 2 seconds.
The session is **idle** when `workItemsCompleted == workItemsTotal`. The
first pass is finished when the session has been idle for **5 consecutive
polls** (about 10 seconds); any poll that is not idle resets the count.

Also keep a no-progress timeout: if `workItemsCompleted` has not changed for a
long time, treat the first pass as finished anyway. The CLI's default is
24 hours (its `-timeout` flag, in minutes). Choose a value that suits your
targets.

`workItemsTotal` keeps growing as the enumeration discovers new assets, so
neither number is a progress percentage until the session settles.

### Step 6: run the session-end work

`POST /sessions/{token}/end-work` (202). This starts the owned-netblock fill
and the Protocol-Probes sweep of missed IPs, which only do anything when the
session has `active: true`. Then poll every 2 seconds:

- `GET /sessions/{token}/end-work` until `done` is `true`;
- `GET /sessions/{token}/stats` as before.

The enumeration is **complete** when `done` is `true` **and** the stats have
been idle for 5 consecutive polls. If `done` has been `true` for 2 minutes but
the stats never go idle (a few work items can stay leased), treat it as
complete anyway. If a `GET /end-work` request fails, send the `POST` again; a
repeated `POST` is harmless.

In a passive session (`active: false`) the end-work finishes at once, with
`done: true` and `phase: "none"`.

### Step 7: terminate

`DELETE /sessions/{token}` (204). The session stops at once and its token
becomes invalid; the engine finishes cleaning up about 10 seconds later. Then
stop and replace the engine container.

Results are in the asset database from the moment they are discovered, so
nothing needs saving through the API before terminating. `GET /scope/{type}`
lists the session's scope (not its findings) if you want a record of it.

### Stopping a run early

To abandon an enumeration, either `DELETE` the session or kill the engine
container outright. Both stop all of its traffic immediately and are safe for
the database: statements in flight are rolled back. A forced kill leaves the
session's temporary directory behind in the output directory; delete old
`session-*` directories on a schedule (see [Running a fleet](#9-running-a-fleet)).

### If the active proxy fails mid-run

The engine checks the active proxy only when a session is created. If the
proxy fails during a run, active traffic fails with it (nothing is sent
directly) and the run's results are incomplete: ports are recorded as closed
and probes marked done. Detecting that is the orchestrator's job: monitor the
proxy, stop the affected engines, start nothing until it is restored, and rerun
the affected enumerations once their TTLs have expired. See
[`active_proxy_egress.md`](active_proxy_egress.md).

## 5. Session configuration

The body of `POST /api/v1/sessions` is a JSON object. These are the fields the
engine reads; anything else is ignored.

| Field | Type | Default | Meaning |
|---|---|---|---|
| `scope` | object | none | What is in scope. **Required**: a request without it is refused with 400 (`scope is required`). See [scope](#scope). |
| `transformations` | object | none | Which handlers run, and for how long their results are reused. **Required in practice**: with no transformations nothing runs. See [transformations](#transformations). |
| `database` | array | SQLite in the engine's output directory | Where results are stored. See [database](#database). |
| `datasource_config` | object | none | Data-source credentials and settings. See [data sources](#data-sources). |
| `active` | boolean | `false` | Enables active probing of targets: port scans, HTTP/HTTPS probes, banner and TLS certificate probes, JARM. |
| `active_proxy` | string | `""` | Proxy for all active traffic: `socks5://`, `socks5h://`, `http://` or `https://`, optionally with `user:pass@`. A bare `host:port` is rejected. |
| `active_strict` | boolean | **`true`** when the field is omitted | With `active: true` and no `active_proxy`, refuse the session. Send `false` to allow active traffic over the engine's own network. |
| `rigid_boundaries` | boolean | `false` | When `true`, the scope never grows during the run: newly associated domains, netblocks and organizations are not added to it, and the horizontal-expansion plugins do not run. |
| `brute_force` | boolean | `false` | Together with `alterations`, enables name alterations. There is no separate brute-force plugin in this version. |
| `alterations` | boolean | `false` | Generate alterations of discovered names; needs `brute_force` too. |
| `wordlist` | array of strings | none | Brute-force wordlist (not used in this version). |
| `alt_worldlist` | array of strings | none | Alterations wordlist. The field name really is misspelled. |
| `resolvers`, `trusted_resolvers` | array of strings | none | Accepted but not used: DNS always goes to the engine's built-in public resolver list. |
| `seed` | object | none | Read by the `enum` CLI only; the engine ignores it. |

### Active-egress rules at creation

| `active` | `active_proxy` | `active_strict` | Result |
|---|---|---|---|
| `false` | any | any | Created. No active traffic. |
| `true` | set, valid, reachable | any | Created. All active traffic goes through the proxy. |
| `true` | set, not a valid URL | any | **400** `invalid configuration` |
| `true` | set, unreachable or refusing to relay | any | **500** `failed to create session`, `details: "active proxy <url> is not usable: ..."` |
| `true` | not set | omitted or `true` | **400** `invalid configuration` (`active mode is enabled but no active_proxy is configured...`) |
| `true` | not set | `false` | Created. Active traffic uses the engine's own network. |

The reachability check asks the proxy to relay a connection to `1.1.1.1:443`
and allows up to about 12 seconds for it.

### scope

| Field | JSON form | Example |
|---|---|---|
| `domains` | array of strings | `["example.com"]` |
| `ips` | array of strings | `["192.0.2.10", "2001:db8::1"]` |
| `cidrs` | array of **objects** (see below) | `[{"IP": "198.51.100.0", "Mask": "////AA=="}]` |
| `asns` | array of integers | `[64500]` |
| `ports` | array of integers; ranges are not accepted in JSON | `[80, 443, 8000, 8080, 8443, 8888]` |
| `blacklist` | array of strings: names never to investigate | `["skip.example.com"]` |

`ports` are the ports scanned and probed when `active` is `true`. **Always
send them for an active session:** if `ports` is missing or empty, nothing is
scanned and so nothing is probed. (The CLI fills in `80, 443` when its YAML
configuration has no ports; the engine does not.) The shipped
`config.yaml` uses `80, 443, 8000, 8080, 8443, 8888`.

**`cidrs` format.** Each CIDR is written in Go's `net.IPNet` JSON form: an
object with the network address as `IP`, and the network mask's bytes
base64-encoded as `Mask`. A plain `"198.51.100.0/24"` string makes the request
fail with 400 (`cannot unmarshal string into ... scope.cidrs of type net.IPNet`).

| CIDR | `IP` | `Mask` |
|---|---|---|
| `/8` IPv4 | `10.0.0.0` | `/wAAAA==` |
| `/12` IPv4 | `172.16.0.0` | `//AAAA==` |
| `/16` IPv4 | `192.0.0.0` | `//8AAA==` |
| `/24` IPv4 | `198.51.100.0` | `////AA==` |
| `/28` IPv4 | `192.0.2.0` | `////8A==` |
| `/32` IPv4 | `192.0.2.10` | `/////w==` |
| `/32` IPv6 | `2001:db8::` | `/////wAAAAAAAAAAAAAAAA==` |
| `/48` IPv6 | `2001:db8::` | `////////AAAAAAAAAAAAAA==` |
| `/64` IPv6 | `2001:db8::` | `//////////8AAAAAAAAAAA==` |

To compute it: an IPv4 mask is 4 bytes and an IPv6 mask 16 bytes, with the
first *prefix-length* bits set; base64-encode those bytes. In Python:
`base64.b64encode(ipaddress.ip_network(cidr).netmask.packed)`.

### transformations

An object whose keys are `"From->To"` rules and whose values hold the rule's
settings. A handler only runs for an asset if a rule allows it.

- **From** is an asset type name (`FQDN`, `IPAddress`, `Netblock` ...).
- **To** is an asset type name, a plugin name (`RDAP`, `GLEIF` ...), `ALL`
  (every handler for that asset type), or `none` (no handlers at all).
- **Values:** `ttl` (minutes: how long a result is reused before the work is
  done again), `confidence` (0 to 100), `priority`, and `exclude` (with `ALL`:
  handlers to leave out).

Use the 27 rules in [Appendix A](#appendix-a-default-transformations), which
are the repository's defaults, unless you have a reason to change them. The
TTLs matter operationally: an asset processed within its TTL is not processed
again, which is why an enumeration that ran against a dead proxy cannot be
rerun until its TTLs expire.

### database

An array of databases; the engine uses the first one with `primary: true`. If
`database` is omitted, the engine uses a SQLite file, `asset.db`, in its own
output directory, which is lost with the container. **Always send a database
for production runs.**

| Field | Type | Used for |
|---|---|---|
| `system` | string | `postgres`; `sqlite` / `sqlite3`; or `neo4j` / `bolt` (also `neo4+s`, `neo4j+sec`, `bolt+s`, `bolt+sec`) |
| `primary` | boolean | Must be `true` on the database to use |
| `host`, `port`, `username`, `password`, `db_name` | strings (`port` too) | Postgres connection details |
| `url` | string | Neo4j connection URL |
| `options` | string | Not used by the engine |

Postgres example (the engine builds
`postgres://<username>:<password>@<host>:<port>/<db_name>` from it):

```json
"database": [
  {"system": "postgres", "primary": true, "host": "assetdb", "port": "5432",
   "username": "amass", "password": "CHANGE-ME", "db_name": "assetdb"}
]
```

### data sources

```json
"datasource_config": {
  "global_options": {"minimum_ttl": 1440},
  "datasources": [
    {"name": "AlienVault", "creds": {"account": {"apikey": "CHANGE-ME"}}},
    {"name": "Prospeo", "ttl": 10080,
     "creds": {"account": {"apikey": "CHANGE-ME"}},
     "options": {"max_emails_per_domain": 25, "min_remaining_credits": 100}}
  ]
}
```

| Field | Meaning |
|---|---|
| `global_options.minimum_ttl` | Minutes; the minimum reuse time for data-source results |
| `datasources[].name` | The data source's name, as in `resources/datasources.yaml` |
| `datasources[].ttl` | Minutes to reuse that source's results |
| `datasources[].creds` | Credential sets by label (`account` in the shipped file), each with any of `username`, `password`, `apikey`, `secret` |
| `datasources[].options` | Source-specific integer settings. Prospeo reads `max_emails_per_domain` and `min_remaining_credits`. |

`resources/datasources.yaml` lists every supported source and its credential
fields. A source with no credentials either runs keyless or is skipped,
depending on the source.

## 6. Endpoint reference

| Method | Path | Purpose |
|---|---|---|
| GET | [`/health`](#get-health) | Engine is up |
| POST | [`/sessions`](#post-sessions) | Create a session |
| GET | [`/sessions/list`](#get-sessionslist) | List sessions |
| DELETE | [`/sessions/{token}`](#delete-sessionstoken) | Terminate a session |
| GET | [`/sessions/{token}/stats`](#get-sessionstokenstats) | Work-item counts |
| POST | [`/sessions/{token}/end-work`](#post-sessionstokenend-work) | Start session-end work |
| GET | [`/sessions/{token}/end-work`](#get-sessionstokenend-work) | Session-end work progress |
| GET | [`/sessions/{token}/backlog`](#get-sessionstokenbacklog) | Per-asset-type backlog |
| GET | [`/sessions/{token}/scope/{type}`](#get-sessionstokenscopetype) | Session scope |
| POST | [`/sessions/{token}/assets/{type}`](#post-sessionstokenassetstype) | Submit one asset |
| POST | [`/sessions/{token}/assets/{type}:bulk`](#post-sessionstokenassetstypebulk) | Submit many assets |
| GET | [`/sessions/{token}/ws/logs`](#get-sessionstokenwslogs) | Session log stream (WebSocket) |
| GET | [`/handler-stats`](#get-handler-stats) | Handler timing (InfluxDB) |

All paths are relative to `/api/v1`. The examples use
`E=http://engine-host:4000/api/v1` and `T=<session token>`.

---

### GET /health

Reports that the API is up.

```
curl -s $E/health
```

**200**

```json
{"result": "Amass Engine OK"}
```

---

### POST /sessions

Creates a session from a [session configuration](#5-session-configuration).

```
curl -s -X POST $E/sessions -H 'Content-Type: application/json' --data @session.json
```

| Status | Body |
|---|---|
| **201** | `{"sessionToken": "77947b4a-4d6b-4d1a-886e-3ae0fa95a546"}` |
| 400 | `invalid JSON` (body is not JSON), `invalid JSON object` (JSON but not an object), or `invalid configuration` (fields of the wrong type, including a plain-string CIDR, or the [active-egress rules](#active-egress-rules-at-creation)); reason in `details` |
| 500 | `failed to create session`; reason in `details`, e.g. an unusable active proxy or an unreachable database |

Examples from a running engine:

```json
{"error":"invalid configuration","details":"active mode is enabled but no active_proxy is configured: set -active-proxy / active_proxy: in the YAML, or pass -active-strict=false to allow active traffic over the default egress (not recommended)","code":400}
```

```json
{"error":"invalid configuration","details":"active_proxy must include a scheme (http, https, socks5, socks5h)","code":400}
```

```json
{"error":"failed to create session","details":"active proxy socks5h://127.0.0.1:1 is not usable: active proxy 127.0.0.1:1 is unreachable (dialing 1.1.1.1:443): socks connect tcp 127.0.0.1:1->1.1.1.1:443: dial tcp 127.0.0.1:1: connect: connection refused","code":500}
```

Both refusals are also written to the engine log at `ERROR` level
(`session refused: invalid configuration` / `failed to create session`).

---

### GET /sessions/list

Lists the tokens of all sessions on this engine.

| Status | Body |
|---|---|
| **200** | `{"sessionTokens": ["77947b4a-4d6b-4d1a-886e-3ae0fa95a546"]}` |
| 404 | `{"error":"zero sessions found","details":"not found","code":404}` when there are none |

Treat the 404 as an empty list.

---

### DELETE /sessions/{token}

Terminates a session. It stops at once: in-flight work is cancelled and no new
work starts. The response is sent immediately; the backlog, temporary directory
and database connection are released in the background about 10 seconds later.
The session-end work is **not** run; call `POST /end-work` first if you want it.

| Status | Body |
|---|---|
| **204** | none |
| 404 | `session not found` (unknown or already terminated), or `route not found` (token not a UUID) |

---

### GET /sessions/{token}/stats

The session's work-item counts, recalculated every 2 seconds from the backlog
across all asset types.

**200**

```json
{"workItemsCompleted": 24, "workItemsTotal": 25}
```

| Field | Meaning |
|---|---|
| `workItemsCompleted` | Work items processed |
| `workItemsTotal` | Processed plus waiting plus in progress |

The session is idle when the two are equal. Right after creation both are 0,
which also counts as idle, so only start the idle check after submitting the
seeds. Errors: 404 as for every per-session endpoint.

---

### POST /sessions/{token}/end-work

Starts the session-end work in the background and returns at once. The work
is, in order:

1. **owned-netblock fill:** admits scoped netblocks whose registration contacts
   now match the target, and waits for their addresses to reach the port
   scanner;
2. **Protocol-Probes sweep:** waits up to 2 minutes for the IP pipeline to go
   quiet, finds in-scope IPs that were never probed, requeues them, and waits
   up to 15 minutes for them to finish.

Both steps only run when the session has `active: true`. The session keeps
running throughout, so `/stats` and `GET /end-work` stay available.

Only the first `POST` for a session starts the work; later ones return 202 and
do nothing.

| Status | Body |
|---|---|
| **202** | none |
| 404 | `session not found` |

---

### GET /sessions/{token}/end-work

Progress of the session-end work.

**200**

```json
{"done": true, "phase": "none", "candidates": 0, "requeued": 0,
 "waiting": 0, "leased": 0, "processed": 1}
```

| Field | Meaning |
|---|---|
| `done` | `true` once the work started by `POST /end-work` has finished. `false` if it is running or was never started. |
| `phase` | `none` (not started, or a passive session), `owned-fill`, `idle-wait`, `listing`, `requeue`, `drain`, `done` |
| `candidates` | IPs the sweep considered |
| `requeued` | IPs the sweep sent back for probing |
| `waiting`, `leased`, `processed` | The **IPAddress** backlog's counts: waiting, in progress, processed |

Wait for `done`, not for `phase: "done"`: in a passive session, or when the
sweep stops early, the phase never reaches `done`.

---

### GET /sessions/{token}/backlog

A breakdown of the session's backlog by asset type, plus connection usage.
Useful for dashboards and for diagnosing a session that is slow or stuck.

**200**

```json
{
  "buckets": [
    {"asset_type": "FQDN", "waiting": 0, "leased": 1, "queue": 0, "processed": 5},
    {"asset_type": "IPAddress", "waiting": 0, "leased": 0, "queue": 0, "processed": 1}
  ],
  "active_connections": 1, "max_connections": 500,
  "active_scan_conns": 0, "max_scan_conns": 3200,
  "prefilter_scanned": 0, "prefilter_open": 0
}
```

| Field | Meaning |
|---|---|
| `buckets[]` | One per asset type with any activity |
| `buckets[].waiting` | Not yet picked up |
| `buckets[].leased` | Being processed now |
| `buckets[].queue` | In the asset type's in-memory pipeline queue |
| `buckets[].processed` | Done |
| `active_connections`, `max_connections` | The session's general network connections in use, and its limit (500, divided between sessions on the engine) |
| `active_scan_conns`, `max_scan_conns` | Port-scan connections in use, and the limit (3,200) |
| `prefilter_scanned`, `prefilter_open` | Ports scanned and found open so far. These counters are per engine process, not per session. |

How to read it: `waiting` high with `queue` near its ceiling means handlers
cannot keep up; `waiting` high with `queue` near zero means work is being
handed out too slowly; `active_connections` at `max_connections` means the
connection limit is the bottleneck.

---

### GET /sessions/{token}/scope/{type}

The session's scope for one asset type, as Open Asset Model JSON objects. This
is the scope (what the session treats as in scope, which grows during the run
as the engine associates new assets with the target), not the enumeration's
findings.

`{type}` is one of `fqdn`, `ipaddress`, `netblock`, `autonomoussystem`,
`organization`, `location`.

**200**

```json
{"data": [{"name": "example.com"}]}
```

| Status | Body |
|---|---|
| 404 | `session scope not found for the selected asset type` when the scope has none of that type, including for any other `{type}`; or `session not found` |

---

### POST /sessions/{token}/assets/{type}

Submits one asset to the session; it is stored and work on it starts. The body
is the asset's Open Asset Model JSON, without a `type` field; the type comes
from the path. See [Asset formats](#7-asset-formats).

```
curl -s -X POST $E/sessions/$T/assets/fqdn -H 'Content-Type: application/json' -d '{"name":"example.com"}'
```

**200**

```json
{"entityID": "1"}
```

`entityID` is the asset's database ID. Submitting an asset that is already in
the database reuses it and returns the same ID (submitting `example.com` twice
returned `"1"` both times), so retries are safe.

| Status | Body |
|---|---|
| 400 | `invalid JSON`, `invalid JSON object`, or `invalid asset object`: an unknown type (`unknown asset type: autonomous_system`) or an asset with no identifying value, such as an `fqdn` without a `name` (`the fqdn asset has no identifying value`) |
| 404 | `session not found` |
| 500 | `failed to submit the asset`, with the database's reason in `details` |

---

### POST /sessions/{token}/assets/{type}:bulk

Submits several assets of one type in one request.

```
curl -s -X POST "$E/sessions/$T/assets/fqdn:bulk" -H 'Content-Type: application/json' \
  -d '{"items":[{"name":"a.example.com"},{"name":"b.example.com"}]}'
```

**200**

```json
{"ingested": 2, "stored": 2, "failed": 0}
```

| Field | Meaning |
|---|---|
| `ingested` | Items that parsed as the path's asset type |
| `stored` | Items stored and started |
| `failed` | `ingested` minus `stored`: items the database refused |

Items that do not parse (for example a string instead of an object), and items
with no identifying value (an `fqdn` without a `name`), are skipped silently
and are not counted anywhere. Check that `ingested` equals the number of items
you sent, and that `failed` is 0.

| Status | Body |
|---|---|
| 400 | `invalid JSON`; `items must be non-empty`; `no valid JSON objects in items` (nothing parsed) |
| 404 | `session not found` |
| 413 | `too many items in bulk request` (more than 5,000) |
| 500 | Same body shape, with `stored: 0` and `failed` equal to `ingested` |

Keep batches to **1,000 items** (the CLI's limit) so each request completes
well inside the 15-second response timeout. The engine answers only after
every item is stored. A request cut off by the timeout may still have stored
some or all of its items; resending is safe because existing assets are
reused.

---

### GET /sessions/{token}/ws/logs

Upgrades to a WebSocket and streams the session's log records, one JSON
object per text frame (format in [The log stream](#8-the-log-stream)).

```
ws://engine-host:4000/api/v1/sessions/<token>/ws/logs
```

- Before the upgrade, the usual 404 errors apply.
- Records are delivered in order, and only while the client is connected;
  nothing is buffered for a later connection.
- The server sends a ping every 30 seconds and drops a client that has not
  answered within 60 seconds. Keep reading the connection; standard WebSocket
  clients answer pings while reading. Anything the client sends is ignored.
- A client that disconnects, or is dropped, is unsubscribed at once, so
  reconnecting is safe. Several clients can watch the same session.
- When the session is terminated, the server sends a normal close frame
  (`session ended`), about 10 seconds after the `DELETE`.

---

### GET /handler-stats

Average execution time and call count per handler over the last 15 minutes,
slowest first, read from InfluxDB. The engine writes these timings only when
the `INFLUX_*` variables are set. The data covers the whole engine process,
not one session.

**200** (illustrative values; `handler` is the asset type and the handler's
pipeline position)

```json
{"window_minutes": 15,
 "handlers": [{"handler": "FQDN-10", "avg_duration_ns": 1834000.5, "call_count": 412}]}
```

| Status | Body |
|---|---|
| 503 | `influxdb not configured` (`details: "empty host"` when `INFLUX_HOST` is unset) or `influxdb query failed` |
| 500 | `error reading query results` |

## 7. Asset formats

Submitted assets use the Open Asset Model's JSON, without a `type` field. The
seed types:

| Path `{type}` | JSON | Notes |
|---|---|---|
| `fqdn` | `{"name": "www.example.com"}` | `name` must be non-empty |
| `ipaddress` | `{"address": "192.0.2.10", "type": "IPv4"}` | `type` is `IPv4` or `IPv6` |
| `netblock` | `{"cidr": "198.51.100.0/24", "type": "IPv4"}` | Here the CIDR **is** a plain string, unlike in `scope.cidrs` |
| `autonomoussystem` | `{"number": 64500}` | |
| `organization` | `{"unique_id": "...", "name": "Example Corp"}` | Also `legal_name`, `jurisdiction`, `registration_id`, `industry` and others |

All accepted `{type}` values: `account`, `autnumrecord`, `autonomoussystem`,
`contactrecord`, `domainrecord`, `file`, `fqdn`, `fundstransfer`, `identifier`,
`ipaddress`, `ipnetrecord`, `location`, `netblock`, `organization`, `person`,
`phone`, `product`, `productrelease`, `service`, `tlscertificate`, `url`. The
field names for each are in the Open Asset Model
(`github.com/owasp-amass/open-asset-model`).

## 8. The log stream

Each frame is one JSON log record. Real examples:

```json
{"time":"2026-10-15T19:28:10.699170564Z","level":"INFO","msg":"successfully acquired the RDAP record for example.com","session":"77947b4a-4d6b-4d1a-886e-3ae0fa95a546","plugin":{"name":"WHOIS","handler":"WHOIS-FQDN-Handler"}}
{"time":"2026-10-15T19:28:10.710322789Z","level":"INFO","msg":"relationship discovered","session":"77947b4a-4d6b-4d1a-886e-3ae0fa95a546","from":"DomainRecord: example.com","relation":{"label":"name_server"},"to":"elliott.ns.cloudflare.com","plugin":{"name":"WHOIS","handler":"WHOIS-Domain-Record-Handler"}}
```

| Field | Present | Meaning |
|---|---|---|
| `time` | always | RFC 3339 timestamp, UTC |
| `level` | always | `DEBUG`, `INFO`, `WARN` or `ERROR` |
| `msg` | always | The message |
| `session` | always | The session token |
| `plugin` | most records | `{"name": ..., "handler": ...}`: which plugin and handler logged it |
| `from`, `relation`, `to` | discoveries | What was found linked to what (`relation` can be a string or an object) |
| others | varies | Extra context such as `ip`, `fqdn`, `error` |

The stream is for monitoring and troubleshooting. Do not parse it for
results, which are in the database.

## 9. Running a fleet

- **One session per engine container.** Concurrent sessions on one engine
  split its 500-connection limit between them, and the port-scan counters are
  shared. Start an engine, run one enumeration, then replace the container.
- **Proxy health.** The engine refuses to create an active session while the
  proxy is down, but it does not watch the proxy afterwards. Your monitor must
  stop the affected engines when the proxy fails. Killing an engine container
  outright is safe.
- **Housekeeping.** A forced kill leaves `session-<uuid>...` directories in the
  output directory, and the engine log grows without rotation. Prune
  `session-*` directories older than your longest possible enumeration (for
  example 7 days) and rotate the engine logs daily. If you use SQLite, do not
  touch `asset.db` and its `-wal` / `-shm` files.
- **Retries.** Asset submission is safe to retry (existing assets are reused).
  `POST /end-work` is safe to repeat. `DELETE` on a session that is already
  gone returns 404, which can be treated as success.
- **Network.** Engines need: outbound DNS to public resolvers; outbound HTTPS
  for OSINT sources and registry lookups (RDAP, WHOIS, GLEIF, BGP.Tools on TCP
  43); the asset database; and, for active sessions, the active proxy. Block
  direct engine-to-target traffic at the firewall as a backstop.
- **Secrets.** Session configurations carry database passwords and API keys.
  Keep them out of orchestrator logs, and keep port 4000 private.

## 10. Known issues

1. **Wrong methods and malformed tokens return 404**, not 405 or 400 (see
   [Conventions](#3-conventions)).
2. **Skipped bulk items are not counted**: items that do not parse, or have no
   identifying value, are missing from `ingested` and `failed` alike (see the
   [bulk endpoint](#post-sessionstokenassetstypebulk)).

Fixed in this version: a bad item in a bulk request no longer crashes the
engine, a bad single asset gets an error response instead of a dropped
connection, a configuration without `scope` gets a 400 instead of no
response, and disconnected log-stream clients no longer leak memory.

## Appendix A: default transformations

The repository's default rules (`resources/config.yaml`), as the engine
expects them in JSON. TTLs are in minutes: 1440 = 1 day, 10800 = 7 days,
43200 = 30 days.

```json
"transformations": {
  "Account->ALL":           {"confidence": 50, "ttl": 10800},
  "AutnumRecord->ALL":      {"confidence": 50, "ttl": 1440},
  "AutonomousSystem->ALL":  {"confidence": 50, "ttl": 1440},
  "AutonomousSystem->RDAP": {"confidence": 50, "ttl": 43200},
  "ContactRecord->ALL":     {"confidence": 50, "ttl": 1440},
  "DomainRecord->ALL":      {"confidence": 50, "ttl": 1440},
  "FQDN->ALL":              {"confidence": 50, "ttl": 1440},
  "FQDN->DomainRecord":     {"confidence": 50, "ttl": 43200},
  "File->ALL":              {"confidence": 50, "ttl": 1440},
  "FundsTransfer->ALL":     {"confidence": 50, "ttl": 10800},
  "IPAddress->ALL":         {"confidence": 50, "ttl": 1440},
  "IPNetRecord->ALL":       {"confidence": 50, "ttl": 1440},
  "Identifier->ALL":        {"confidence": 50, "ttl": 1440},
  "Identifier->GLEIF":      {"confidence": 50, "ttl": 43200},
  "Identifier->RDAP":       {"confidence": 50, "ttl": 43200},
  "Location->ALL":          {"confidence": 50, "ttl": 1440},
  "Netblock->ALL":          {"confidence": 50, "ttl": 1440},
  "Netblock->RDAP":         {"confidence": 50, "ttl": 43200},
  "Organization->ALL":      {"confidence": 50, "ttl": 1440},
  "Organization->GLEIF":    {"confidence": 50, "ttl": 43200},
  "Person->ALL":            {"confidence": 50, "ttl": 43200},
  "Phone->ALL":             {"confidence": 50, "ttl": 10800},
  "Product->ALL":           {"confidence": 50, "ttl": 10800},
  "ProductRelease->ALL":    {"confidence": 50, "ttl": 1440},
  "Service->ALL":           {"confidence": 50, "ttl": 1440},
  "TLSCertificate->ALL":    {"confidence": 50, "ttl": 10800},
  "URL->ALL":               {"confidence": 50, "ttl": 1440}
}
```

## Appendix B: complete example session

An active enumeration of `example.com` and one netblock through a SOCKS5
proxy, storing results in Postgres. Replace the `CHANGE-ME` values; the rest
can be sent as it is.

`session.json`:

```json
{
  "scope": {
    "domains": ["example.com"],
    "ips": ["192.0.2.10"],
    "cidrs": [{"IP": "198.51.100.0", "Mask": "////AA=="}],
    "asns": [64500],
    "ports": [80, 443, 8000, 8080, 8443, 8888],
    "blacklist": ["skip.example.com"]
  },
  "active": true,
  "active_proxy": "socks5h://proxy.internal:1080",
  "active_strict": true,
  "rigid_boundaries": false,
  "database": [
    {"system": "postgres", "primary": true, "host": "assetdb", "port": "5432",
     "username": "amass", "password": "CHANGE-ME", "db_name": "assetdb"}
  ],
  "datasource_config": {
    "global_options": {"minimum_ttl": 1440},
    "datasources": [
      {"name": "AlienVault", "creds": {"account": {"apikey": "CHANGE-ME"}}}
    ]
  },
  "transformations": {
    "Account->ALL":           {"confidence": 50, "ttl": 10800},
    "AutnumRecord->ALL":      {"confidence": 50, "ttl": 1440},
    "AutonomousSystem->ALL":  {"confidence": 50, "ttl": 1440},
    "AutonomousSystem->RDAP": {"confidence": 50, "ttl": 43200},
    "ContactRecord->ALL":     {"confidence": 50, "ttl": 1440},
    "DomainRecord->ALL":      {"confidence": 50, "ttl": 1440},
    "FQDN->ALL":              {"confidence": 50, "ttl": 1440},
    "FQDN->DomainRecord":     {"confidence": 50, "ttl": 43200},
    "File->ALL":              {"confidence": 50, "ttl": 1440},
    "FundsTransfer->ALL":     {"confidence": 50, "ttl": 10800},
    "IPAddress->ALL":         {"confidence": 50, "ttl": 1440},
    "IPNetRecord->ALL":       {"confidence": 50, "ttl": 1440},
    "Identifier->ALL":        {"confidence": 50, "ttl": 1440},
    "Identifier->GLEIF":      {"confidence": 50, "ttl": 43200},
    "Identifier->RDAP":       {"confidence": 50, "ttl": 43200},
    "Location->ALL":          {"confidence": 50, "ttl": 1440},
    "Netblock->ALL":          {"confidence": 50, "ttl": 1440},
    "Netblock->RDAP":         {"confidence": 50, "ttl": 43200},
    "Organization->ALL":      {"confidence": 50, "ttl": 1440},
    "Organization->GLEIF":    {"confidence": 50, "ttl": 43200},
    "Person->ALL":            {"confidence": 50, "ttl": 43200},
    "Phone->ALL":             {"confidence": 50, "ttl": 10800},
    "Product->ALL":           {"confidence": 50, "ttl": 10800},
    "ProductRelease->ALL":    {"confidence": 50, "ttl": 1440},
    "Service->ALL":           {"confidence": 50, "ttl": 1440},
    "TLSCertificate->ALL":    {"confidence": 50, "ttl": 10800},
    "URL->ALL":               {"confidence": 50, "ttl": 1440}
  }
}
```

The run, in shell form:

```bash
E=http://engine-host:4000/api/v1

# 1. wait for the engine
until curl -sf $E/health >/dev/null; do sleep 1; done

# 2. create the session
T=$(curl -sf -X POST $E/sessions -H 'Content-Type: application/json' \
      --data @session.json | jq -r .sessionToken)

# 3. connect to the log stream (any WebSocket client), e.g.
#    websocat "ws://engine-host:4000/api/v1/sessions/$T/ws/logs" >> "logs/$T.jsonl" &

# 4. seeds: everything in scope, plus any extra names in bulk
curl -sf -X POST $E/sessions/$T/assets/fqdn             -d '{"name":"example.com"}'
curl -sf -X POST $E/sessions/$T/assets/ipaddress        -d '{"address":"192.0.2.10","type":"IPv4"}'
curl -sf -X POST $E/sessions/$T/assets/netblock         -d '{"cidr":"198.51.100.0/24","type":"IPv4"}'
curl -sf -X POST $E/sessions/$T/assets/autonomoussystem -d '{"number":64500}'
curl -sf -X POST "$E/sessions/$T/assets/fqdn:bulk" \
     -d '{"items":[{"name":"www.example.com"},{"name":"mail.example.com"}]}'

# 5. first pass: idle for 5 consecutive 2-second polls
idle=0
while [ $idle -lt 5 ]; do
  sleep 2
  s=$(curl -sf $E/sessions/$T/stats) || continue
  [ "$(jq '.workItemsCompleted == .workItemsTotal' <<<"$s")" = true ] && idle=$((idle+1)) || idle=0
done

# 6. session-end work: done, and idle again for 5 polls
curl -sf -X POST $E/sessions/$T/end-work
idle=0
while [ $idle -lt 5 ]; do
  sleep 2
  d=$(curl -sf $E/sessions/$T/end-work | jq .done)
  s=$(curl -sf $E/sessions/$T/stats) || continue
  if [ "$d" = true ] && [ "$(jq '.workItemsCompleted == .workItemsTotal' <<<"$s")" = true ]; then
    idle=$((idle+1)); else idle=0; fi
done

# 7. terminate, then replace the container
curl -sf -X DELETE $E/sessions/$T
```

This sketch leaves out the no-progress timeout (step 5) and the 2-minute
fallback for stranded work items (step 6), both of which a real orchestrator
needs.
