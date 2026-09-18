# 🔌 HyperDNS Developer REST API v1 — Official Specification & Guide

HyperDNS provides a high-performance, developer-first **REST API v1** designed for bot developers, subscription managers, automated billing systems, Discord/Telegram bots, and enterprise monitoring platforms.

---

## 📑 Table of Contents

- [🔐 Authentication & Security](#-authentication--security)
- [🌐 Base URL & Interactive Docs](#-base-url--interactive-docs)
- [📦 1. Build Version & Metadata (`/version`)](#-1-build-version--metadata-version)
- [📊 2. System Health & Telemetry (`/status`)](#-2-system-health--telemetry-status)
- [👥 3. Client Management & Accounting (`/clients`)](#-3-client-management--accounting-clients)
  - [Create Client](#post-apiv1clients---create-new-client)
  - [List Clients](#get-apiv1clients---list-clients)
  - [Get Client Details](#get-apiv1clientsid---get-client-by-id)
  - [Update Client Details](#put-apiv1clientsid---update-client)
  - [Reset Consumed Traffic](#post-apiv1clientsidreset-traffic---reset-traffic)
  - [Regenerate Client UUID](#post-apiv1clientsidregenerate-uuid---regenerate-uuid)
  - [Delete Client](#delete-apiv1clientsid---delete-client)
- [🔑 4. Master API Key Management (`/api-key`)](#-4-master-api-key-management-api-key)
- [🎮 5. SmartDNS Rules & Presets (`/policies`)](#-5-smartdns-rules--presets-policies)
- [🧹 6. Cache Management (`/cache/flush`)](#-6-cache-management-cacheflush)
- [🔗 7. Subscriber Portal Links (`/sub/`, `/ip/`)](#-7-subscriber-portal-links-sub-ip)
- [🤖 8. Practical Implementation Samples](#-8-practical-implementation-samples)
  - [Python Telegram Bot Integration](#-sample-a-python-telegram-bot-integration)
  - [Node.js / Express Client Provisioner](#-sample-b-nodejs--express-client-provisioner)
  - [cURL Fast Scripts](#-sample-c-curl-cli-one-liners)

---

## 🔐 Authentication & Security

All requests to `/api/v1/*` (except `/api/v1/version` and `/api/v1/docs`) require authentication via either a Master **API Key** or a **Bearer Admin Session Token**.

### Method 1: Master API Key (Recommended for Bots & Scripts)
Pass the API Key in the `X-API-Key` HTTP header:
```http
GET /api/v1/status HTTP/1.1
Host: YOUR_SERVER_IP:8080
X-API-Key: hdns_live_your_secret_api_key_here
```

### Method 2: Bearer Token (For Web Panels)
Pass the admin session token in the `Authorization` header:
```http
GET /api/v1/status HTTP/1.1
Host: YOUR_SERVER_IP:8080
Authorization: Bearer hdns_session_your_token_here
```

### Status Codes You Should Handle

| Code | Meaning | What to do |
| :--- | :--- | :--- |
| `400` | Malformed JSON, a missing required field, or a request body larger than 1 MB. | Fix the payload — the response body names the problem. |
| `401` | Missing or invalid API key / session token. | Re-read the key from Settings; it may have been regenerated. |
| `403` | The REST API is bound to `127.0.0.1` and your request did not come from the server itself. | Turn on **Public API** in Settings, or call the API locally / through an SSH tunnel. |
| `404` | No subscriber exists with that id. | Re-list `/clients`; the id may have been deleted. |
| `405` | Wrong HTTP method for that endpoint. The response carries an `Allow` header naming the verbs the endpoint does accept. | Read `Allow` and resend. A wrong verb is never quietly treated as the right one, so a `405` means nothing happened. |

> **On the `403` gate:** it is decided by the address of the machine that actually opened the connection, never by `X-Forwarded-For` — a forwarding header must not be able to carry a request past a listener the operator deliberately bound to localhost. A reverse proxy running **on the same host** therefore passes the gate on its own; a proxy on a different host needs **Public API** enabled.

> **On the `405` and `HEAD`:** every endpoint that answers `GET` also answers `HEAD` — `/version`, `/status`, `/docs`, `/clients`, `/clients/{id}`, `/policies` and `/api-key` — because that is what uptime probes send, and `HEAD` costs the server nothing beyond the work `GET` already does. The two sub-actions (`/clients/{id}/regenerate-uuid`, `/clients/{id}/reset-traffic`) and `/cache/flush` are `POST` only. You do not have to keep this list: a `405` tells you, per RFC 9110 §15.5.6.
>
> ```http
> HTTP/1.1 405 Method Not Allowed
> Allow: GET, HEAD, PUT, DELETE
> Content-Type: application/json
>
> {"error":"Method not allowed"}
> ```

---

## 🌐 Base URL & Interactive Docs

- **Base URL (v2, current):** `http://<SERVER_IP>:<panel-port>/<admin-path>/api/v2` (or `https://<YOUR_DOMAIN>:<panel-port>/<admin-path>/api/v2` when TLS is active)
- **Base URL (v1, deprecated):** the same with `/api/v1`. Every v1 route answers with `Deprecation: true`, a `Sunset` header and a `Link` to its v2 successor. v1 keeps working — with the same security fixes — until its sunset; new integrations should start on v2.
- **Admin path:** since v2.1 the panel and its API live below a random 16-hex-character path generated once at first install (printed to the log on first run). It is a locator, not a credential — every URL below shows the un-prefixed form, and you must insert your own `<admin-path>` before it.
- **Panel port:** fresh installs draw a random management port (20000–60000) instead of the old fixed 8080; the installer prints and opens it. Read it from the install banner or the service log.
- **Interactive Swagger Documentation:** Open `http://<SERVER_IP>:<panel-port>/<admin-path>/api/v1/docs` in your browser. Press **Authorize**, paste the Master API Key from Settings, and every endpoint on the page becomes runnable from the browser — `Try it out` sends the key with each request.

---

## ⚡ API v2 — the current contract

v2 exists because v1's field names grew asymmetric (`ip` on create, `allowed_ip` on update; `days` that silently meant "lifetime" when typo'd). The v2 rules, applied uniformly:

- **Symmetric DTO.** One client shape everywhere: `display_name`, `allowed_ips`, `validity_days` (create) / `expires_at` (read), `quota_limit_gb`, `quota_reset_cycle`, `policy_ids`, `note`, `token`.
- **Strict decoding.** An unknown field is a `400` naming the field — v1 dropped it silently, which is how a typo'd `expires_days` produced a lifetime account.
- **Cursor pagination.** Lists answer `{"items": [...], "next_cursor": "N"}`; `?limit=` bounds a page (1–200, default 50); the last page has no `next_cursor`.
- **RFC 9457 errors.** Errors are `application/problem+json` with `type`, `title`, `status`, `detail`.
- **Actions are explicit.** `POST /api/v2/clients/{id}/actions/reset-traffic` and `.../actions/regenerate-uuid`.
- **PATCH for partial updates.** Only the fields you send change; absent and empty stay distinguishable.
- **The master key is a REST credential.** It authorizes `/api/v2` (and `/api/v1`) — it no longer opens dashboard admin routes (settings, credentials, 2FA, LDAP). Those take a dashboard session.

### `GET /api/v2/clients?limit=50&cursor=0`
```json
{
  "items": [
    {
      "id": "12340abcde",
      "display_name": "Gamer-VIP",
      "token": "6f2b…",
      "allowed_ips": ["198.51.100.7"],
      "expires_at": "2026-10-14T00:00:00Z",
      "quota_limit_gb": 50,
      "quota_reset_cycle": "monthly",
      "policy_ids": ["enable_riot"],
      "note": "",
      "enabled": true
    }
  ],
  "next_cursor": "50"
}
```

### `POST /api/v2/clients` → `201 Created`
```bash
curl -s -X POST "https://dns.example.com/<admin-path>/api/v2/clients" \
  -H "X-API-Key: hdns_live_…" \
  -H "Content-Type: application/json" \
  -d '{"display_name":"Gamer-VIP","validity_days":30,"quota_limit_gb":50,"quota_reset_cycle":"monthly"}'
```
The response is the created client (the `token` builds the register link). Unknown fields — including v1's `days`/`ip`/`traffic_limit_gb` names — are refused with a 400 naming the field.

### `PATCH /api/v2/clients/{id}`
Send only what changes: `{"allowed_ips":["203.0.113.9"]}` moves the binding; `{"enabled":false}` suspends; `{"validity_days_add":30}` extends.

### `DELETE /api/v2/clients/{id}` → `204 No Content`

---


## 📦 1. Build Version & Metadata (`/version`)

> **Deprecated surface.** Sections 1–8 below document the v1 contract, kept
> for integrations already built on it. New integrations: use [API v2](#-api-v2--the-current-contract) above.

Returns the build version, channel, release codename, and semantic sync hash.

### `GET /api/v1/version`
*(Unauthenticated)*

#### Request
```bash
curl -s http://127.0.0.1:8080/api/v1/version
```

#### Response (`200 OK`)
```json
{
  "version": "1.5.0",
  "channel": "beta",
  "codename": "HyperRAIN",
  "display": "v1.5.0-beta",
  "hash": "3585f9bf",
  "go": "go1.26"
}
```

---

## 📊 2. System Health & Telemetry (`/status`)

Returns real-time server health, QPS rate, CPU/Memory telemetry, cache performance, and active client statistics.

### `GET /api/v1/status`

#### Request
```bash
curl -s http://127.0.0.1:8080/api/v1/status \
  -H "X-API-Key: hdns_live_your_key_here"
```

#### Response (`200 OK`)

The `telemetry` object is the complete `LiveStatsResponse`, serialized as-is — the
same payload the dashboard polls. Every field below is present on every response.

```json
{
  "status": "healthy",
  "version": {
    "version": "1.5.0",
    "channel": "beta",
    "codename": "HyperRAIN",
    "display": "v1.5.0-beta",
    "hash": "3585f9bf",
    "go": "go1.26"
  },
  "timestamp": "2026-09-01T19:30:00Z",
  "public_ip": "95.179.140.241",
  "api_bind": "127.0.0.1",
  "telemetry": {
    "total_queries": 163240,
    "qps": 42.5,
    "active_relays": 12,
    "total_relays": 5402,
    "bytes_sent": 84210920,
    "bytes_recv": 124902100,
    "cache_items": 1240,
    "cache_hits": 128900,
    "cache_misses": 34340,
    "cache_hit_rate": 78.96,
    "cpu_usage": 0.5,
    "ram_usage_mb": 14.8,
    "alloc_memory_mb": 14.8,
    "sys_memory_mb": 27.3,
    "cpu_usage_percent": 0.5,
    "num_cpu": 4,
    "num_goroutines": 38,
    "speed_in_kbps": 118.4,
    "speed_out_kbps": 76.2,
    "uptime_sec": 3840,
    "rate_limited": 0,
    "rate_limit_qps": 200,
    "stale_served": 84,
    "refresh_started": 1902,
    "refresh_failed": 3,
    "refresh_dropped": 0,
    "relays_refused": 41,
    "relays_unreadable": 216,
    "latency": {
      "count": 163240,
      "avg_ms": 2.94,
      "p50_ms": 0.03,
      "p95_ms": 27.5,
      "p99_ms": 41.2,
      "max_ms": 812.4
    },
    "latency_uncached": {
      "count": 34340,
      "avg_ms": 13.6,
      "p50_ms": 11.8,
      "p95_ms": 33.5,
      "p99_ms": 68.7,
      "max_ms": 812.4
    }
  }
}
```

#### Telemetry fields

| Field | Type | Meaning |
|---|---|---|
| `total_queries` | uint | DNS queries answered since start, all transports. |
| `qps` | float | Queries per second, averaged over a rolling 10-second window. |
| `active_relays` | int | SNI proxy connections open right now. |
| `total_relays` | uint | SNI proxy connections accepted since start. |
| `bytes_sent` / `bytes_recv` | uint | Bytes relayed by the SNI proxy, from the server's point of view. |
| `cache_items` | int | Entries currently held in the DNS cache. |
| `cache_hits` / `cache_misses` | uint | Cache lookups since start. |
| `cache_hit_rate` | float | Hit percentage, `0` when no lookups have happened yet. |
| `cpu_usage` | float | Process CPU percentage, capped at `100 × num_cpu`. |
| `ram_usage_mb` | float | Go heap in use, MiB. |
| `sys_memory_mb` | float | Memory obtained from the OS, MiB — always higher than the heap. |
| `num_cpu` | int | Hardware threads visible to the process. |
| `num_goroutines` | int | Live goroutines; a steadily climbing value means a leak. |
| `speed_in_kbps` / `speed_out_kbps` | float | Proxy throughput over the last sampling interval. |
| `uptime_sec` | int | Seconds since the daemon started. |
| `rate_limited` | uint | Queries **dropped or refused** by the per-source rate limiter since start. |
| `rate_limit_qps` | int | The limit in force, per source. `0` means limiting is **disabled**. |
| `stale_served` | uint | Answers served from an **expired** cache entry while a refresh ran in the background. |
| `refresh_started` | uint | Background cache refreshes started since start. |
| `refresh_failed` | uint | Background refreshes that could not reach an upstream. |
| `refresh_dropped` | uint | Refreshes skipped because the background worker pool was saturated. |
| `relays_refused` | uint | SNI proxy connections **declined** after their destination was read — quota spent, relay table full, or a blocked/malformed target. |
| `relays_unreadable` | uint | SNI proxy connections whose opening bytes named **no destination at all**, so there was nothing to dial. |
| `latency` | object | Service-time distribution of **every** answered query. See below. |
| `latency_uncached` | object | The same, restricted to queries the cache did **not** answer. |

Each latency object carries `count`, `avg_ms`, `p50_ms`, `p95_ms`, `p99_ms` and
`max_ms`. All six are cumulative since the daemon started — polling does not reset
them — and every figure is in milliseconds.

`alloc_memory_mb` is an alias of `ram_usage_mb`, and `cpu_usage_percent` an alias
of `cpu_usage`; both pairs carry identical values and exist because the dashboard
and the REST clients grew different names for the same number. Read the shorter
name in new integrations.

**On `rate_limited`.** The limiter answers a UDP flood with silence — no `REFUSED`,
no truncated reply, nothing — because any answer would make the daemon an
amplifier. Over TCP, DoT and DoH it returns `REFUSED` instead, since there the
peer has already completed a handshake and cannot be a spoofed source. This
counter is therefore the *only* evidence available that the limiter fired at all:
without it, an attack in progress and a quiet network both look like a QPS graph
that stopped rising. Read the two fields together — `rate_limited: 4217` means one
thing at `rate_limit_qps: 200` and something quite different at `20`.

**On the two latency objects.** Read `latency_uncached` first. A resolver with a
healthy hit rate answers most queries from RAM in tens of microseconds, so those
hits dominate `latency` and drag its median to a number that describes the cache
rather than the service: at an 85% hit rate the overall `p50_ms` *is* a cache hit,
and a badly degraded upstream can double the real resolution time without moving
it at all. `latency_uncached` excludes the hits, which makes it the figure that
responds to upstream trouble. `avg_ms` is published for completeness and is the
least useful of the six — one 800 ms timeout in ten thousand queries moves the
average by 0.08 ms and the p99 by a great deal more.

The percentiles come from a fixed-bucket histogram, so a reported value is only as
precise as the bucket it falls in; the bucket edges are dense below 1 ms and
through the tens of milliseconds, where cache hits and upstream round trips
respectively live. Two consequences are worth knowing before you alert on these:
a query slower than the last edge (2000 ms) is reported *as* 2000 ms, and a high
percentile can read slightly above `max_ms`, because interpolation assumes a
bucket's observations are spread evenly across it. `max_ms` is exact — it is the
real worst case, tracked separately.

**On `stale_served` and `refresh_failed`.** Serve-stale answers an expired entry
instantly while renewing it in the background, which is also how it conceals a dead
upstream: clients keep getting fast replies from a cache nothing is refilling.
`stale_served` rising on its own is the feature working as intended. `stale_served`
rising *together with* `refresh_failed` is the one failure this design hides on
purpose, and it is the pair to alert on — otherwise the first symptom an operator
sees is names going dark once the stale window closes. `refresh_dropped` rising
means the background worker pool is saturated and renewals are being skipped.

**On `relays_refused` and `relays_unreadable`.** These are the two ways a connection
reaches the SNI proxy and leaves again without ever becoming a relay, so neither
appears in `active_relays`, `total_relays` or the byte counters. They are disjoint —
a connection is counted in exactly one — which makes their sum every
accepted-but-not-relayed connection.

`relays_refused` is mostly reassuring: the proxy read a destination and declined it
because the client's quota was spent, the relay table was already full, or the
target was blocked, malformed, or resolved back to this host. It is evidence the
guards are working.

`relays_unreadable` is the diagnostic one. The proxy needs a destination out of the
opening bytes — a TLS SNI extension or an HTTP `Host` header — and these connections
carried neither. A port scanner and a TCP health check look exactly like this, so a
handful on a public IP is background noise. A count that climbs *with real traffic*
is not: it means a name is being answered with this server's address and the client
then speaks something the relay cannot read a destination out of — traffic that is
UDP, or TCP on a port the proxy does not listen on, or TCP that is neither TLS nor
HTTP. That name is not being slowed down, it is being **removed**, and the client
cannot diagnose it either, because the substitution happened in DNS. The server log
carries a sampled line (one in 64) naming the port, the source and the first four
bytes, which is what separates a scanner from a mis-proxied service.

---

## 👥 3. Client Management & Accounting (`/clients`)

### `POST /api/v1/clients` — Create New Client
Creates a new subscriber account, generates an RFC 4122 v4 UUID, and creates their 1-click dynamic registration URL.

#### Request
```bash
curl -s -X POST http://127.0.0.1:8080/api/v1/clients \
  -H "X-API-Key: hdns_live_your_key_here" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Reza (PS5 & PC)",
    "days": 30,
    "ip": "2.189.86.32",
    "traffic_limit_gb": 50,
    "traffic_reset_cycle": "monthly",
    "custom_policies": ["enable_riot", "enable_discord"],
    "note": "Purchased 50GB VIP Plan"
  }'
```

`name` is the only required field.

**`days` has no server-side default, and omitting it does not mean "short trial" — it means the account never expires.** A zero or absent `days` stores no expiry date at all, which is how the *Lifetime* plan is created and also how a billing integration with a missing field silently gives away a permanent account. Always send it explicitly, even when your product's default is 30.

`traffic_reset_cycle` is optional and must be `""`, `"daily"`, `"weekly"` or `"monthly"`; anything else is a `400`. It makes the quota come back on its own every period instead of staying spent until an operator resets it. The cycle is anchored at the moment of this request, so a monthly plan sold on the 31st renews on the 31st — or on the last day of a shorter month. **It resets the volume only; `expires_at` is never extended**, because a subscriber who stopped paying should not keep the service.

Omit it and the account behaves exactly as it did before v1.5.0: one quota, spent once.

#### Response (`201 Created`)
```json
{
  "id": "c4b8e219",
  "uuid": "ded3329d-e208-4e00-9d6b-3b1567bdc501",
  "token": "c4b8e219",
  "name": "Reza (PS5 & PC)",
  "allowed_ips": ["2.189.86.32"],
  "traffic_limit_gb": 50,
  "traffic_used_bytes": 0,
  "traffic_reset_cycle": "monthly",
  "next_traffic_reset": "2026-10-01T19:30:00Z",
  "quota_exceeded": false,
  "custom_policies": ["enable_riot", "enable_discord"],
  "note": "Purchased 50GB VIP Plan",
  "created_at": "2026-09-01T19:30:00Z",
  "expires_at": "2026-10-01T19:30:00Z",
  "enabled": true
}
```

#### Accounting fields, and which number to trust

| Field | Meaning |
|---|---|
| `traffic_used_bytes` | Bytes consumed in the **current** cycle, including the bytes still buffered in the in-memory ledger. This is the number to show a customer; do not add anything to it. |
| `traffic_limit_gb` | `0` means unlimited. Any other value is the cap for one cycle. |
| `traffic_reset_cycle` | `""`, `"daily"`, `"weekly"` or `"monthly"`. `""` means the quota never comes back on its own. |
| `next_traffic_reset` | When the volume next returns, RFC 3339. **Absent** from the object when there is no cycle — do not treat a missing key as "now". Computed by the daemon; do not recompute it from the cycle name, because a monthly cycle anchored past the 28th is clamped per month. |
| `quota_exceeded` | The resolver's own verdict on whether this account is out of volume, and the same test it refuses queries with. Always present. **Compare against this, not against your own percentage** — a rounded 100% is not the cut-off. |

An account is answered as *itself* only when `enabled` is true, `expires_at` is in the future **and** `quota_exceeded` is false. All three are independent; a panel that shows only the first two will badge a spent account as active.

⚠️ Those three fields decide whether the resolver serves **this account** — not whether it serves the request. With `access.allow_all` left at its default of `true` the daemon is an open resolver: disabling or expiring an account only stops it from being *recognised*, and the address behind it is then served as anonymous `Public`, which has no plan and no quota. So revocation does nothing until `allow_all` is off, and expiring an account that is already over its limit gives its service back. Set `access.allow_all` to `false` on any server you sell access to.

---

### `GET /api/v1/clients` — List Clients
Returns all registered clients.

#### Request
```bash
curl -s http://127.0.0.1:8080/api/v1/clients \
  -H "X-API-Key: hdns_live_your_key_here"
```

#### Response (`200 OK`)
```json
{
  "clients": [
    { "id": "c4b8e219", "name": "Reza (PS5 & PC)", "quota_exceeded": false }
  ]
}
```

**The list is wrapped in an object; the single-client route is not.** `GET /clients` answers `{"clients": [...]}` while `GET /clients/{id}` answers the bare account object, so a client library cannot share one unwrapping step between them. Each entry is the same shape `POST /clients` returned, and each carries the same live `traffic_used_bytes`, `quota_exceeded` and `next_traffic_reset` as the single-client route — the accounting is computed per request, not read from the last flush, so listing a thousand accounts needs no follow-up call to price them.

---

### `GET /api/v1/clients/{id}` — Get Client by ID
Returns details of a single subscriber.

#### Request
```bash
curl -s http://127.0.0.1:8080/api/v1/clients/c4b8e219 \
  -H "X-API-Key: hdns_live_your_key_here"
```

#### Response (`200 OK`)

The **bare account object** — not wrapped, unlike the list above — in exactly the shape `POST /clients` returned, with the accounting fields recomputed for this request. An unknown id is a `404` with a JSON error body, so a billing job can tell "this subscriber is gone" from "the API is down" by the status code alone.

---

### `PUT /api/v1/clients/{id}` — Update Client
Update client name, UUID, IP address, traffic limit, reset cycle, duration, policies, enabled status, or note.

**Every field is optional and omitting one leaves it alone.** This is a patch, not a replacement: a body carrying only `{"enabled": false}` suspends the account and touches nothing else.

#### Request
```bash
curl -s -X PUT http://127.0.0.1:8080/api/v1/clients/c4b8e219 \
  -H "X-API-Key: hdns_live_your_key_here" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Reza (VIP-Pro)",
    "allowed_ip": "2.189.86.32",
    "traffic_limit_gb": 100,
    "traffic_reset_cycle": "monthly",
    "custom_policies": ["enable_riot", "enable_discord", "enable_steam"],
    "enabled": true,
    "note": "Upgraded to 100GB plan"
  }'
```

On `traffic_reset_cycle` specifically: send `""` to turn a cycle **off**, and omit the key to leave it as it is. Re-sending the cycle an account already has is a no-op — the period is re-anchored only when the value actually *changes*, so editing a note every month cannot keep pushing a rollover out of reach. Switching daily → monthly today does re-anchor, so the plan renews on today's day-of-month from then on.

#### Renewal, expiry and unbinding

Two mutually compatible ways to move the expiry date, plus the field that releases a bound address. None of the three appear in the example above and all three are what a billing bot actually calls:

| Field | Type | Effect |
|---|---|---|
| `days_to_add` | int | **The renewal field.** Extends from the account's current `expires_at`, or from **now** if that date has already passed — so renewing a customer who lapsed last week sells them a full period rather than a retroactive one. Negative values shorten a plan. `0` is ignored, so a bot may send the key unconditionally. |
| `expires_at` | RFC 3339 | Sets the date **absolutely**, ignoring what was there. Use it to correct a mistake, not to renew. If both keys are sent, this one lands first and `days_to_add` then counts from it. |
| `allowed_ip` | string | Rebinds the account to one address. Sending `""` **unbinds** it: the account keeps its plan and its remaining volume but resolves for nobody until the subscriber opens their `/sub/{token}` link again. That is the correct way to move a subscription to a new household without deleting the account. |

```bash
# Renew for another 30 days, whether or not the account already lapsed.
curl -s -X PUT http://127.0.0.1:8080/api/v1/clients/c4b8e219 \
  -H "X-API-Key: hdns_live_your_key_here" \
  -H "Content-Type: application/json" \
  -d '{"days_to_add": 30}'
```

Renewal does **not** return spent volume, and resetting volume does not extend a date — the two ledgers are deliberately independent. A renewal on a plan with a `traffic_reset_cycle` gets its allowance back at the next rollover; a renewal on a plan without one needs `POST /clients/{id}/reset-traffic` as well, or the subscriber will pay and still be refused.

Two fields ignore an empty string instead of clearing it: `name` and `uuid`. An account cannot be left nameless, and `""` is not a UUID — send `POST /clients/{id}/regenerate-uuid` if you want a new one. And remember from the table above that `traffic_limit_gb: 0` means **unlimited**, not *zero allowance*, so it is not the way to cut someone off; `{"enabled": false}` is.

---

### `POST /api/v1/clients/{id}/reset-traffic` — Reset Traffic
Resets the subscriber consumed bandwidth counter to `0` bytes.

It clears the in-memory ledger too, so bytes counted but not yet written cannot land on top of the zero. It deliberately does **not** move a recurring cycle: `next_traffic_reset` stays where it was, so a courtesy top-up on the 20th of a monthly plan does not move that subscriber's renewal day to the 20th.

#### Request
```bash
curl -s -X POST http://127.0.0.1:8080/api/v1/clients/c4b8e219/reset-traffic \
  -H "X-API-Key: hdns_live_your_key_here"
```

#### Response (`200 OK`)
```json
{
  "reset": true
}
```

---

### `POST /api/v1/clients/{id}/regenerate-uuid` — Regenerate UUID
Generates a new RFC 4122 v4 UUID for the specified client.

#### Request
```bash
curl -s -X POST http://127.0.0.1:8080/api/v1/clients/c4b8e219/regenerate-uuid \
  -H "X-API-Key: hdns_live_your_key_here"
```

#### Response (`200 OK`)
```json
{
  "uuid": "8a32b904-f521-4822-a7f4-d02167de1812"
}
```

---

### `DELETE /api/v1/clients/{id}` — Delete Client
Deletes the client account immediately from BoltDB and memory.

#### Request
```bash
curl -s -X DELETE http://127.0.0.1:8080/api/v1/clients/c4b8e219 \
  -H "X-API-Key: hdns_live_your_key_here"
```

#### Response (`200 OK`)
```json
{ "deleted": true }
```

There is no undo and no soft-delete: the record, its token, its UUID and its usage history are gone, and the subscriber's `/sub/{token}` link answers the portal's "invalid or unknown token" page from that moment. (That page is HTML for a human and answers `200`; the JSON twin at `/api/sub/{token}` answers `404`, which is the one to probe from a script.) To stop serving someone while keeping the ability to bring them back — and while keeping their remaining volume — send `{"enabled": false}` to the `PUT` route instead. Deleting is also the wrong tool for moving a subscription to a new household; `{"allowed_ip": ""}` unbinds the address and keeps the plan.

---

## 🔑 4. Master API Key Management (`/api-key`)

### `GET /api/v1/api-key` — Get Master API Key
```bash
curl -s http://127.0.0.1:8080/api/v1/api-key \
  -H "X-API-Key: hdns_live_your_key_here"
```

#### Response (`200 OK`)
```json
{
  "success": true,
  "api_key": "hdns_live_2f8c41a90b7d4e63",
  "api_bind": "127.0.0.1",
  "data": {
    "api_key": "hdns_live_2f8c41a90b7d4e63",
    "api_bind": "127.0.0.1"
  }
}
```

`data` is a duplicate of the two fields beside it and exists only because an older dashboard build read them from there. Read the top-level names in new code; the nested copy is kept so nothing already shipped breaks.

`api_bind` is the operational half of this response: `127.0.0.1` means the REST API answers **only** the server itself, and a call from anywhere else gets the `403` described above however valid the key is. `0.0.0.0` means **Public API** is on and the key is the only thing standing in front of an admin surface.

### `POST /api/v1/api-key` — Regenerate Master API Key
Generates a new administrative Master API Key.

```bash
curl -s -X POST http://127.0.0.1:8080/api/v1/api-key \
  -H "X-API-Key: hdns_live_your_key_here"
```

#### Response (`200 OK`)
```json
{
  "success": true,
  "api_key": "hdns_live_9d1e77b4c2a05f38",
  "data": { "api_key": "hdns_live_9d1e77b4c2a05f38" }
}
```

⚠️ **The old key stops working the moment this returns**, and it is the only copy — nothing keeps a previous key alive for a grace period. Every bot, billing hook and monitoring probe holding it starts getting `401` immediately, including the one that made this call. Regenerate when you have somewhere to write the new value, not while debugging something else. If the write to disk fails the response is a `500` and the *old* key stays in force, so a failed rotation is never a locked-out daemon.

---

## 🎮 5. SmartDNS Rules & Presets (`/policies`)

### `GET /api/v1/policies` — List All Policies
Returns two lists: the full catalogue of selectable presets, and the ones whose global state has been changed from the default.

```bash
curl -s http://127.0.0.1:8080/api/v1/policies \
  -H "X-API-Key: hdns_live_your_key_here"
```

#### Response (`200 OK`)
```json
{
  "catalog": [
    { "key": "enable_riot",       "label": "Riot Games & Valorant",  "blocking": false },
    { "key": "enable_downloads",  "label": "Game & App Downloads",   "blocking": false },
    { "key": "enable_familysafe", "label": "FamilySafe Protection",  "blocking": true }
  ],
  "policies": [
    {
      "key": "enable_adblock",
      "name": "AdBlock & Tracker Sinkhole",
      "category": "security",
      "enabled": true,
      "custom_domains": []
    }
  ]
}
```

| Field | Meaning |
|---|---|
| `catalog` | Every preset that can be toggled globally or attached to one client, in display order. `label` is the same text the resolver and the dashboard use; `blocking: true` marks a category that **sinkholes** what it matches instead of routing it, which is the opposite kind of decision from attaching a game. Build policy pickers from this — do not hardcode the list, and do not sort it. |
| `policies` | Only the presets whose state was **explicitly changed and persisted**. A preset missing from this array is at its built-in default, not absent from the product. On a fresh install this array is empty. Three categories default to **off** — `enable_adblock`, `enable_familysafe` and `enable_downloads` — and every other key defaults to on. Do not infer that from `blocking`: the first two are blocking and the third is not. |

`custom_policies` on a client accepts any `key` from `catalog`. An **empty** list means the account gets every preset that is globally on — it is not a lockout — and a non-empty list **narrows** that account to the intersection of its own selection and the global state. It cannot widen it, so a key listed here for a preset that is globally off does nothing.

### `POST /api/v1/policies` — Toggle Policy Rule
Enables or disables a specific gaming policy rule globally.

```bash
curl -s -X POST http://127.0.0.1:8080/api/v1/policies \
  -H "X-API-Key: hdns_live_your_key_here" \
  -H "Content-Type: application/json" \
  -d '{"key": "enable_riot", "enabled": true}'
```

The response echoes the stored policy record. `key` is required; anything else is a `400`. The change takes effect on the resolver immediately — it is not deferred to a restart — but **already-cached answers are not re-decided**, so a name resolved a minute ago keeps its old routing until its TTL runs out. Follow a toggle with `POST /cache/flush` when you need the switch to be visible at once.

A globally disabled preset also overrides every per-client selection: `custom_policies` **narrows** what an account gets from the presets that are on, it cannot switch one back on for that account. So disabling a preset here revokes it for everyone, whatever their plan says.

#### `enable_downloads` behaves backwards from the rest

Every other key in the catalogue *adds* routing: on means those domains are proxied, off means they are not matched at all. `enable_downloads` **subtracts**. Its domains are the depot and CDN hosts already covered by the game presets, and the key decides which side of the proxy they land on:

| `enable_downloads` | What a depot host resolves to |
|---|---|
| `false` (default) | Its real address — `action: "DIRECT"`, `rule: "Game & App Downloads"` in the query log. The install runs on the subscriber's own line. |
| `true` | Whatever the owning game preset says, normally `action: "PROXY"` with that preset's own label. |

Three consequences for anything automated:

- **`GET /stats` proxied/blocked/direct rule counts do not move** when this key is toggled. The category is not an action index of its own; it only vetoes. A monitor that watches those numbers to confirm a write landed will see nothing — read the value back from `/policies` instead.
- **It cannot proxy a game whose own preset is off.** With `enable_steam` off, a Steam depot is direct in both states, because there is nothing to subtract from.
- **A single host can be excused** without switching the whole category on: add it to `custom_proxied`, which outranks the veto. `custom_blocked` outranks both.

Read the bandwidth warnings in the README before turning this on for a paying subscriber base — the traffic meter counts these bytes and has no per-domain accounting.

---

## 🧹 6. Cache Management (`/cache/flush`)

### `POST /api/v1/cache/flush` — Flush In-Memory DNS Cache
Immediately purges all entries from the 64-shard LRU DNS cache.

```bash
curl -s -X POST http://127.0.0.1:8080/api/v1/cache/flush \
  -H "X-API-Key: hdns_live_your_key_here"
```

#### Response (`200 OK`)
```json
{
  "flushed": true
}
```

Every subscriber's next query for every name then goes upstream, so on a busy resolver this is a deliberate latency spike for all of them at once. Use it after changing routing, not on a schedule.

---

## 🔗 7. Subscriber Portal Links (`/sub/`, `/ip/`)

These three routes are **unauthenticated by design** — the token in the path *is* the credential — and they are the only ones a subscriber ever touches. They take `GET` and nothing else (not even `HEAD`), because opening one is a write.

| Route | What it does |
| :--- | :--- |
| `GET /sub/{token}` | Binds the caller's current IP to the subscription and renders the Persian portal page (quota, expiry countdown, setup guide). `GET /ip/{token}` is the same handler under the older path. |
| `GET /api/sub/{token}/sync` | The JSON half, called by the portal's *«بروزرسانی آی‌پی من»* button. Registers the caller's IP and returns the account's live figures. |

**A subscription link is a write, and that is the point.** A registration *replaces* the account's single allowed IP with the caller's address, which is what makes the link a one-click fix for a subscriber whose home IP just changed. It also means anything that fetches the link on their behalf would take the subscription:

- **Link previews and prefetches are detected and suppressed.** A fetch that identifies itself as speculative (`Sec-Purpose`, `Purpose`, `X-Purpose`, `X-Moz`) or carries a known crawler / unfurler `User-Agent` (Telegram, WhatsApp, Discord, Slack, search engines, …) resolves the token **read-only**: the real page is rendered, no address is bound, and the page says so and points at the sync button. So a bot may post the link into a chat safely.
- **`curl` and `wget` are not treated as crawlers.** A router script or cron job on the subscriber's network hitting this URL after a reconnect is asking for exactly that registration.
- **`/api/sub/{token}/sync` always registers**, whatever the `User-Agent` claims. It is reached only from an already-open page, and it is the recovery path when the detection above guesses wrong — so it is never suppressed.

The detection is advisory: a crawler presenting a browser's `User-Agent` cannot be told apart from a subscriber. If you distribute these links at scale and want a guarantee, send the subscriber to the page and let them press the button, or bind the address yourself with `PUT /api/v1/clients/{id}` from your own backend.

**An unknown, deleted or expired token does not answer an error status on the HTML route.** `GET /sub/{token}` renders a bilingual "the link is invalid" or "your plan has expired" page with `200 OK`, because the recipient is a person and a browser error page would tell them nothing. The JSON route is the one to probe from a script: `GET /api/sub/{token}` answers `404` with `{"success": false, "error": "..."}`. So a monitor that checks a subscriber's link is alive must call the JSON path — the HTML one is `200` either way.

---

## 🔐 7b. Admin-Panel Authentication & Settings (v2.1)

All of these live **inside the admin namespace** (`/<admin-path>/api/...` below the hidden 16-hex path generated at first install) and require an authenticated session unless noted. Where two-factor is enabled, credential-mutating endpoints additionally require a current TOTP `code` and answer `401` with the same `"Invalid credentials"` body any other failure produces.

| Route | What it does |
| :--- | :--- |
| `POST /api/auth/login` | Session login. Body: `username`, `password`, and `code` (required when 2FA is enabled). Directory logins follow the configured LDAP mode (`local`, `ldap`, `both`). |
| `GET /api/auth/2fa/status` | Display-safe 2FA state: `totp_enabled`, `totp_enrolling`, `otpauth_uri` (present **only** while an enrollment is open). Never carries the secret. |
| `POST /api/auth/2fa/setup` | Opens an enrollment. Body: `username`, `current_password`. Returns `secret` + `otpauth_uri` **once**. Refused while 2FA is already active. |
| `POST /api/auth/2fa/enable` | Confirms the enrollment. Body: `username`, `current_password`, `code`. On success every session is invalidated. |
| `POST /api/auth/2fa/disable` | Turns 2FA off. Body: `username`, `current_password`, `code` — both factors are required one last time. |
| `GET /api/auth/ldap` | LDAP settings snapshot. The bind password is structurally absent from the response. |
| `POST /api/auth/ldap` | Saves the directory settings (`enabled`, `ldap_server_url` — must start with `ldap://`/`ldaps://` — `ldap_bind_dn`, `ldap_bind_password` (empty keeps the stored one), `ldap_base_dn`, `ldap_user_attr`, `ldap_login_mode`). Invalidates sessions. |
| `POST /api/settings/regenerate-admin-path` | Replaces the hidden namespace. Body **must** be `{"confirm":true}`; every session and bookmark under the old path dies immediately. |
| `GET/POST /api/settings/subscription` | The subscriber-surface record (enabled, domain, port, title, certificate paths, `use_panel_certificate`). A different domain is refused without a valid certificate naming it; `restart_required` is always stated. |

The password-change endpoint (`POST /api/config/server`) accepts a `code` field and enforces the same second-factor gate. Session invalidation after 2FA, LDAP-mode, admin-path and credential changes is deliberate and documented in the v2.1 plan.

---

## 🤖 8. Practical Implementation Samples

### 🐍 Sample A: Python Telegram Bot Integration
```python
import requests

HYPERDNS_API = "http://127.0.0.1:8080/api/v1"
API_KEY = "hdns_live_your_key_here"
HEADERS = {"X-API-Key": API_KEY, "Content-Type": "application/json"}

def create_gamer_account(telegram_user_id: str, days: int = 30, traffic_gb: float = 50.0,
                         cycle: str = "monthly"):
    payload = {
        "name": f"tg_{telegram_user_id}",
        "days": days,
        "traffic_limit_gb": traffic_gb,
        # "" | "daily" | "weekly" | "monthly". With a cycle the allowance comes back on
        # its own; without one, a spent account stays dead until you reset it by hand.
        "traffic_reset_cycle": cycle,
        "custom_policies": ["enable_riot", "enable_discord", "enable_steam"]
    }
    res = requests.post(f"{HYPERDNS_API}/clients", json=payload, headers=HEADERS)
    res.raise_for_status()
    client = res.json()

    # Return 1-click registration URL for user
    return f"http://YOUR_SERVER_IP:8080/ip/{client['token']}"
```

That URL binds whoever opens it, so posting it as a clickable message is safe only because unfurlers are detected and served read-only — see [Subscriber Portal Links](#-7-subscriber-portal-links-sub-ip) for what is and is not guaranteed.

To tell a subscriber where they stand, read the account back and use the daemon's own numbers rather than deriving them:

```python
def account_status(client_id: str) -> str:
    c = requests.get(f"{HYPERDNS_API}/clients/{client_id}", headers=HEADERS).json()
    if not c["enabled"]:
        return "suspended"
    if c["quota_exceeded"]:                      # the resolver's verdict, not a percentage
        renews = c.get("next_traffic_reset")     # absent when the plan has no cycle
        return f"out of volume, back on {renews}" if renews else "out of volume"
    return f"{c['traffic_used_bytes'] / 1e9:.2f} GB used of {c['traffic_limit_gb']} GB"
```

---

### 🟩 Sample B: Node.js / Express Client Provisioner

The shape a checkout page or a payment webhook wants. No dependencies beyond Express itself — Node 18+ has `fetch` built in.

```js
import express from "express";

const API = "http://127.0.0.1:8080/api/v1";
const KEY = process.env.HYPERDNS_API_KEY;          // never hardcode it
const HOOK_SECRET = process.env.PROVISION_SECRET;  // your own shared secret
const PORTAL = process.env.PORTAL_BASE ?? "http://YOUR_SERVER_IP:8080";

async function hdns(path, method = "GET", body) {
  const res = await fetch(`${API}${path}`, {
    method,
    headers: { "X-API-Key": KEY, ...(body && { "Content-Type": "application/json" }) },
    body: body && JSON.stringify(body),
  });
  const text = await res.text();
  if (!res.ok) throw new Error(`${method} ${path} → ${res.status}: ${text}`);
  return text ? JSON.parse(text) : null;
}

const app = express();
app.use(express.json());

// This service mints paid accounts, so it authenticates callers in its own right.
// The HyperDNS key stays on this side and never reaches a browser.
app.use((req, res, next) =>
  req.get("X-Provision-Secret") === HOOK_SECRET ? next() : res.sendStatus(401));

app.post("/provision", async (req, res) => {
  const { orderId, days = 30, gb = 50 } = req.body;
  try {
    const c = await hdns("/clients", "POST", {
      name: `order_${orderId}`,
      days,
      traffic_limit_gb: gb,
      traffic_reset_cycle: "monthly",
      note: `order ${orderId}`,
    });
    // No `ip` was sent, so the account is unbound and the subscriber's first visit
    // to this link binds whatever address they are on. That is the point of it.
    res.json({ id: c.id, portal: `${PORTAL}/sub/${c.token}` });
  } catch (e) {
    res.status(502).json({ error: e.message });
  }
});

app.post("/renew/:id", async (req, res) => {
  // enabled:true as well as the extension — an account suspended for non-payment
  // stays suspended, and a renewal that only moves the date leaves it dead.
  const c = await hdns(`/clients/${req.params.id}`, "PUT",
    { days_to_add: 30, enabled: true });
  res.json({ expires_at: c.expires_at, quota_exceeded: c.quota_exceeded });
});

app.listen(3000);
```

This service runs **on the HyperDNS host**, which is what lets it reach `127.0.0.1:8080` with nothing exposed: the `403` gate is decided by the address that opened the connection, so a same-host caller passes it without **Public API** ever being turned on. Keep it that way if you can — a provisioning key is an admin key.

The renewal route returns `quota_exceeded` because the two ledgers are independent, and on a plan with no `traffic_reset_cycle` a paid renewal can come back with it still `true`. If that is your product, call `reset-traffic` in the same handler.

### 🧪 Sample C: cURL CLI One-Liners

Run these on the server itself. Each assumes `KEY=hdns_live_your_key_here` is exported and `jq` is installed.

```bash
# Is it alive, and is it actually resolving? (`/version` needs no key at all.)
curl -s "http://127.0.0.1:8080/api/v1/status" -H "X-API-Key: $KEY" \
  | jq '{status, qps: .telemetry.qps, hit_rate: .telemetry.cache_hit_rate,
         uncached_p95: .telemetry.latency_uncached.p95_ms}'
```

```bash
# Who is out of volume right now — the resolver's own verdict, not a percentage.
curl -s "http://127.0.0.1:8080/api/v1/clients" -H "X-API-Key: $KEY" \
  | jq -r '.clients[] | select(.quota_exceeded) | "\(.id)\t\(.name)"'
```

```bash
# The ten accounts closest to expiring, soonest first.
curl -s "http://127.0.0.1:8080/api/v1/clients" -H "X-API-Key: $KEY" \
  | jq -r '.clients | sort_by(.expires_at) | .[:10][] | "\(.expires_at)\t\(.id)\t\(.name)"'
```

```bash
# Sell 30 days / 50 GB and print the link to hand over.
curl -s -X POST "http://127.0.0.1:8080/api/v1/clients" -H "X-API-Key: $KEY" \
  -H "Content-Type: application/json" \
  -d '{"name":"Reza","days":30,"traffic_limit_gb":50,"traffic_reset_cycle":"monthly"}' \
  | jq -r '"http://YOUR_SERVER_IP:8080/sub/" + .token'
```

```bash
# Renew and un-suspend in one call.
curl -s -X PUT "http://127.0.0.1:8080/api/v1/clients/c4b8e219" -H "X-API-Key: $KEY" \
  -H "Content-Type: application/json" -d '{"days_to_add":30,"enabled":true}' \
  | jq '{name, expires_at, quota_exceeded}'
```

```bash
# Suspend without deleting; the plan and the remaining volume are kept.
curl -s -X PUT "http://127.0.0.1:8080/api/v1/clients/c4b8e219" -H "X-API-Key: $KEY" \
  -H "Content-Type: application/json" -d '{"enabled":false}' | jq '.enabled'
```

```bash
# Turn a preset on globally, then drop the cache so the change is visible at once.
curl -s -X POST "http://127.0.0.1:8080/api/v1/policies" -H "X-API-Key: $KEY" \
  -H "Content-Type: application/json" -d '{"key":"enable_riot","enabled":true}'
curl -s -X POST "http://127.0.0.1:8080/api/v1/cache/flush" -H "X-API-Key: $KEY"
```

Sorting on `expires_at` as text is exact while the server's clock is UTC, which a VPS almost always is; the field is serialized with whatever offset the host runs in, so on a machine set to a local zone treat that ordering as approximate and compare the parsed dates instead. Do not try to spot a spent account by dividing `traffic_used_bytes` by `traffic_limit_gb` — `quota_exceeded` is the same test the resolver refuses queries with, and a rounded 100% is not the cut-off.

### `POST /api/auth/unlock` — Clear Login Lockouts (v2.1.0-beta3+)

Clears the per-address login lockouts the panel's brute-force guard recorded. The
tracker lives in the daemon's memory, so this endpoint is the only way to lift a
lockout (for example an office NAT that got locked out) without restarting the
service. The TUI's **[12] Clear Login Lockouts** entry calls exactly this
endpoint over loopback.

- **Method:** `POST` — body `{"code": "123456"}` (the current TOTP code; required
  only when 2FA is enabled) and optional `"ip": "203.0.113.9"` to clear one
  address. An empty body clears every tracked address.
- **Auth:** a live dashboard session or the master API key — the same gate as
  every other admin call, **plus** the second factor when 2FA is on. An endpoint
  that undoes a security control must not be cheaper to reach than the control
  it undoes.
- **Responses:** `200 {"success":true,"cleared":N}` (or `"cleared":1` with the
  `ip` echo), `401` wrong credentials/second factor, `405` non-POST.

**Lockout policy:** 3 failed logins inside 10 minutes → the address answers
`429` until the window slides past the failures, an operator unlocks it, or a
successful login from another address... no: a successful login clears only its
own address. The lock applies to the source address (trusted-proxy aware), and
the login response says so: *"Too many failed login attempts. This address is
locked for 10 minutes (the operator can unlock it sooner: Settings → Login
Lockouts)."*

---

### `POST /ip/<token>` — Subscriber IP Registration API (v2.1.0-beta3+)

The subscriber's one write. Phase B moved binding off the portal page: **no GET
anywhere can move an account's address any more** — opening `/sub/<token>`
renders a read-only overview, and a chat unfurler or browser prefetch that used
to steal the binding cannot.

- **Method:** `POST` — body `{"secret": "<registration secret>",
  "ip": "203.0.113.9" (optional)}`. With no `ip` the address the request was
  seen from is bound (the 1-click flow the portal page drives); with one, an
  explicit address is bound for subscribers whose gaming device sits behind a
  different NAT than the device holding the page.
- **Credential:** the **registration secret**, a 24-hex-character value minted
  at account creation and shown in the operator's client modal (with a
  regenerate button that invalidates the old value immediately). The secret
  travels out-of-band — handed to the subscriber separately from the portal
  link — which is what makes a leaked `/sub/` link read-only (Mantis C-03).
- **Gates, in order:** token+secret first (a wrong secret answers exactly like
  an unknown token, so a prober learns nothing), then suspension, expiry and
  quota — each a distinct 403 with an actionable message — then address
  validation, then a cross-account duplicate check: an address already bound to
  a **different** subscription answers **409 and disables neither account**
  (CGNAT makes shared addresses ordinary).
- **Responses:** `200 {"success":true,"bound_ip":...,"client":{...}}` on a bind
  (or a repeat bind of the same address), `401` unknown token or wrong secret,
  `403` suspended/expired/quota-exhausted (the body names which), `409` address
  belongs to another subscription, `400` malformed body or bad address.
- **`GET /ip/<token>`** serves a bilingual explainer page (no script) for old
  bookmarks and chat unfurls — it performs no write and returns no account
  data beyond the explanation.

**Portal page (`GET /sub/<token>`):** read-only overview — identity, the
address this visit was seen from, quota figures, expiry countdown, endpoints
and device guides. The register card posts the secret to the API above.

**Login (`POST /<admin-path>/api/auth/login`):** when the password verifies but
the TOTP code fails, the 401 body carries `"twofactor_required": true` — the
login form reveals its code field for exactly this case and never for a plain
wrong password (Mantis fix, Hotfix 2/3).
