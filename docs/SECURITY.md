# 🔐 Security Policy

HyperDNS is a **DNS resolver and TLS relay** — by design it answers queries from
the public internet on port 53 and can relay TLS sessions on ports 80/443. That
places it in a different risk class from an ordinary web application, and this
document states what the project does about it, what it deliberately does not,
and how to report a problem.

---

## 📑 Table of Contents

- [Supported Versions](#-supported-versions)
- [Reporting a Vulnerability](#-reporting-a-vulnerability)
- [Security Model](#-security-model)
- [What Is Encrypted, Precisely](#-what-is-encrypted-precisely)
- [Built-In Controls](#-built-in-controls)
- [Deployment Hardening Checklist](#-deployment-hardening-checklist)
- [Known Non-Goals](#-known-non-goals)
- [Verification You Can Run Yourself](#-verification-you-can-run-yourself)
- [Standards & RFC Compliance](#-standards--rfc-compliance)

---

## ✅ Supported Versions

| Version | Status | Security fixes |
| :--- | :--- | :--- |
| `v2.6.0-beta` (HyperFORGE) | Current beta | ✅ Yes |
| `v2.5.0-beta` (HyperFORGE) | Superseded | ❌ Upgrade first |
| `v2.4.0-beta` (HyperFORGE) | Superseded | ❌ Upgrade first |
| `v2.3.0-beta` (HyperFORGE) | Superseded | ❌ Upgrade first |
| `v2.2.0-beta` (HyperSHIELD) | Superseded | ❌ Upgrade first |
| `v2.0.x`–`v2.1.x` beta | Superseded | ❌ Upgrade first |
| `v1.x` | End of life | ❌ No |

Only the current beta line receives fixes. The project does not backport to
earlier betas — the release cadence is fast enough that upgrading is the
supported path.

---

## 📮 Reporting a Vulnerability

**Do not open a public issue for a security problem.** A public report is a
working exploit for every install that has not yet upgraded, and this software
runs on the public internet by design.

Report privately through **GitHub's private vulnerability reporting** (Security →
*Report a vulnerability* on the repository). If that is unavailable to you,
contact the maintainer through the address on the repository profile.

**What to include.** The more of this you have, the faster the fix:

- The affected version (`hdns -version`).
- Whether the panel is on a domain (HTTPS) or loopback-only, and whether
  `access.allow_all` is on or off — several issues are only reachable in one of
  those states.
- A **reproduction**: the request, the config, or a test that fails. A PoC
  against a local install is worth more than a description.
- Impact as you understand it: what an attacker gains, and what they must
  already hold to get it.

**What to expect.**

| Stage | Target |
| :--- | :--- |
| Acknowledgement of your report | 72 hours |
| Initial assessment (confirmed / not reproduced / by design) | 7 days |
| Fix or documented mitigation for a confirmed high-severity issue | 30 days |

Please **do not** test against infrastructure you do not own. Every issue this
project has found can be reproduced against a local install — the test suite and
the container recipe in [Verification](#-verification-you-can-run-yourself) are
there for exactly that.

**Credit.** Reporters are credited in the changelog entry and the release notes
unless they ask not to be.

---

## 🧭 Security Model

Stating the trust boundaries first makes the rest of this document readable.

| Principal | Reaches | Trusted for |
| :--- | :--- | :--- |
| **Anonymous internet** | Port 53 (UDP/TCP), the landing page at `/`, the subscriber routes `/sub/` and `/ip/`, DoT 853, the DoH port (restricted surface: `/dns-query` plus the public portal routes only — v2.2.0 removed the dashboard from it), and the relay on 80/443 | Nothing. Every input is validated; the subscriber token in the path is a credential, not an identity. |
| **Subscriber** (holds a `/sub/` link) | Read-only account overview. **Cannot** move the IP binding — that needs the out-of-band registration secret. | Only the ability to *read* the account the link names. |
| **Subscriber with registration secret** | `POST /ip/<token>` — rebinds one address. | Nothing else: no account creation, no quota change, no policy access. |
| **Operator** (authenticated session) | The dashboard below `/<admin-path>/dash/` and every `/api/...` route. | Full control of this daemon, including generating credentials. |
| **API client** (holds `X-API-Key`) | `/api/v1/...` and `/api/v2/...` and nothing else — the master key is **refused on every dashboard route** (v2.2.0 scoping) except the lockout-recovery unlock. | Provisioning and read access, bounded by the `api_bind` gate. |
| **Local OS user on the box** | `master.key` and `data.db` if file permissions allow. | Treated as **compromised-equivalent** for confidentiality — see below. |

Two boundaries are load-bearing and worth naming explicitly:

- **The admin path is a locator, not a credential.** `/<admin-path>/` keeps the
  dashboard out of blind scans, but anyone who learns the path still faces the
  login. It is defence in depth, never the control. Treat a leaked path as a
  reason to rotate it (Settings → *Hidden Admin Path*), not as a breach.
- **Field encryption protects the confidentiality of sealed fields when the
  database is obtained without its `master.key`.** That is the boundary: a
  stolen database file alone (a backup, a snapshot, a mis-sent archive) gives
  up nothing. An attacker who already reads the install directory holds both,
  and is compromised-equivalent for confidentiality. The daemon warns at
  startup if it finds a `master.key.bak` or `data.db.bak` beside the live
  files for exactly this reason.

---

## 🔏 What Is Encrypted, Precisely

`data.db` is a BoltDB file. Secret **fields** inside it are individually sealed
with **AES-256-GCM** under the 32-byte key in `master.key`:

| Sealed | In the clear (deliberately) |
| :--- | :--- |
| Subscriber name | Policy presets and their domain lists |
| Subscriber bound-IP list | The BoltDB structure itself |
| Subscription token | Traffic counters, timestamps |
| Registration secret | |
| REST API key | |
| TLS certificate paths | |
| TOTP secret and LDAP bind password | |

**The admin password is never stored.** Only a PBKDF2-HMAC-SHA256 verifier
(600,000 iterations) is kept, so the password cannot be recovered by reversing
the verifier — even with `master.key` in hand. A sufficiently strong policy is
what stands between an attacker holding the verifier and an offline guessing
attack, which is why new passwords are held to the strength policy; and a lost
admin password is a *reset*, not a recovery.

Subscription tokens additionally carry a **keyed blind index** alongside the
ciphertext, so `/ip/<token>` remains a single constant-time lookup without the
token ever being stored in the clear for indexing.

The reason presets are in the clear is that they are not secrets: the same list
is published in [`PRESET_CATALOG.md`](PRESET_CATALOG.md) and embedded in the
binary. Sealing them would cost a decrypt per query on the hot path and protect
nothing.

**Query logs are never written to disk in any form.** DNS telemetry lives in
memory and on the SSE stream only. This is a design constraint, not a setting.

---

## 🛡 Built-In Controls

The controls below ship enabled (where noted, they need one setting changed).
They are the reason several classes of issue are "by design" rather than bugs.

### Authentication and authorization

- **PBKDF2-HMAC-SHA256, 600,000 iterations** for the admin password, with a
  minimum-strength policy on new passwords (≥10 chars with two classes, ≥16
  chars, or a non-ASCII script).
- **Server-side sessions** in memory, wiped on restart. Tokens carry 32 bytes of
  `crypto/rand` entropy and are never derived from anything guessable.
- **Login lockout**: 3 failures from one address locks it for 10 minutes. The
  operator can clear it without a restart (`POST /api/auth/unlock`, or TUI entry
  `[12]`), which requires a session or the API key, plus a TOTP code when 2FA is
  on.
- **TOTP (RFC 6238)** with a proper enrollment flow: the secret is shown once,
  and confirmation requires a code. When enabled, password changes and API-key
  rotation also demand a current code — a stolen session plus a stolen password
  is not enough. A validated code is **single-use across every gated endpoint**
  (login included), so one observed code cannot authorise a rotation, an unlock
  and a login inside its validity window, and the enrollment URI never leaves
  the password-gated setup response.
- **The master REST key no longer opens the dashboard** (v2.2.0): one credential
  passing both surfaces meant a leaked REST key was a full panel takeover. It
  keeps its power on `/api/v1|/api/v2` and one dashboard route — the
  lockout-recovery unlock the root-local TUI calls; the key-scoping tests pin
  the refusal on the admin routes and the exception on that one. Key rotation
  re-asks for the **current password** (dashboard) and the same TOTP gate runs
  on both surfaces.
- **LDAP** (`ldaps://` verified against the system trust store, bounded timeouts,
  bind/search/bind). Modes: local, LDAP, or LDAP-with-local-fallback. Saving the
  directory settings re-asks for the current password (the directory IS the
  login path — repointing it from a bare session is the one credential change a
  stolen session must not make), and **only the directory entry naming the admin
  account may authenticate** — the directory validates credentials, the panel
  picks the account.
- **One answer for every credential failure.** Local, LDAP, and second-factor
  failures are indistinguishable, so the API is not an oracle for which path
  exists or which account is real.

### Session and API surface

- **Configurable idle timeout** (5–1440 minutes, default 15) with a separate
  24-hour absolute ceiling that a session cannot extend by being used.
- **The REST API binds `127.0.0.1` by default.** Flipping it to `0.0.0.0` puts an
  admin surface on the internet with the API key as the only thing in front of
  it; the dashboard says so before it saves.
- **The panel fails closed without a trusted certificate.** A configured domain
  means HTTPS-only, and a self-signed fallback is refused rather than served —
  the "Not secure" banner is treated as a defect, not a cosmetic issue. With no
  domain the panel binds loopback only.

### Subscriber surface

- **`/sub/<token>` cannot move the binding.** It is a read-only overview, and it
  does not mutate on a visit, a prefetch, or a chat unfurler's fetch (all of
  which are detected and suppressed).
- **Rebinding requires the 96-bit registration secret**, delivered out-of-band.
  A leaked portal link alone is read-only material.
- **Registration gates**: suspended, expired, and over-quota accounts are
  refused; an address already bound to a *different* subscription answers 409
  **without disabling either account** — shared CGNAT addresses are ordinary on
  mobile networks, and auto-disabling a paying account over one would be worse
  than the conflict.
- **The dedicated subscriber listener serves an allow-list, not a deny-list.**
  When a portal port is configured, that listener answers `/sub/`, `/ip/`,
  `/api/sub/`, and the three portal asset prefixes — and returns a bare 404 for
  the admin namespace, every `/api/...` route, DoH, and the SPA. Adding a route
  to the dashboard cannot silently widen it.
- **Token and secret failures are one answer**, so the endpoint cannot be walked
  to enumerate live subscriptions.
- **Error pages answer with honest status codes**: an unknown token is 404, an
  expired plan is 410 — the friendly body stays, the success code does not
  pretend the resource exists.
- **Certificates are issued per surface** (panel, subscription portal, DoT/DoH),
  each validated against its own name before anything persists; the DoH/DoH
  transports refuse to serve a certificate for the wrong name.

### Input handling

- **html/template everywhere on the subscriber pages**, with the one exception
  (`ServerDNS`) filtered by a dedicated display validator because it is shown as
  an address to type into a console.
- **Operator CSS is sanitised** before it reaches a subscriber: `<style>` and
  `<script>` escaped, `@import` stripped, external `url()` removed. A reseller's
  "branding" cannot become a data-exfiltration surface.
- **Paths are cleaned mux-style before the admin-prefix check**, so a
  dot-segment traversal cannot escape the hidden namespace.
- **Forwarding headers are only believed from a trusted local/private hop**, so
  the registration endpoint cannot be told to bind an attacker-chosen address
  via `X-Forwarded-For`.
- **Bounded request bodies** on every JSON endpoint, bounded connection counts on
  every listener, and timeouts on headers and idle connections.

### DNS-specific

- **Client access whitelist ships on (v2.2.0).** An unknown source is refused
  (`REFUSED`) instead of served for free — an existing install converges through
  a one-time idempotent migration, and an operator who wants public mode back
  flips the dashboard toggle deliberately. Until an install converges, the
  historical open behaviour is what an upgrade temporarily keeps.
- **RFC 8914 Extended DNS Error**: refused queries that carried OPT learn *why*
  — the answer carries EDE code 18 (`Prohibited`, per the IANA registry) with an
  explanatory string, on every transport (UDP, TCP, DoT).
- **Per-source query rate limiting.**
- **Response-size and amplification limits** on the resolver path.
- **The relay cannot be aimed inward**: a relay target that resolves to a
  loopback, link-local, or private address is refused, so the SNI proxy is not
  an SSRF pivot into the server or its subnet.
- **Bulk-download traffic stays off the relay by default** (`enable_downloads`
  ships off) — see the README for the operational reasoning.

---

## 🚀 Deployment Hardening Checklist

The defaults target a personal box on a home network — and since v2.2.0 the
resolver ships **closed** (whitelist by default). Review this list before
exposing the installation to other users: some rows are required changes and
some are checks that the shipped default is already the right one.

| # | Setting | Ships as | Change to | Why |
| :--- | :--- | :--- | :--- | :--- |
| 1 | `access.allow_all` | `false` since v2.2.0 (whitelist by default) | keep it `false` to sell or share; `true` is for a personal all-devices install | While `true` the daemon answers *every* address, so expiring or disabling an account only stops it being **recognised** — the address is then served as anonymous `Public`, with no plan to expire and no quota to exceed. **Revocation does not work at all** until this is off. Fresh installs ship whitelist-on; an existing install converges through a one-time migration on first boot. |
| 2 | `security.api_bind` | `127.0.0.1` | leave it unless a bot runs off-box | `127.0.0.1` means a remote call gets `403` however valid its key is. Changing it to `0.0.0.0` makes the API key the primary remote authentication credential for that surface — prefer an SSH tunnel, VPN, or equivalent network control for off-box administration. |
| 3 | Admin password | random, printed **once** | your own, ≥10 characters | Only a verifier is stored, so a lost password is a reset, not a recovery. Changing it invalidates every session. |
| 4 | `master.key` | generated on first start | back up **off** the server | It decrypts every subscriber record. Losing it makes them unreadable; leaking it makes them readable. `.gitignore` already covers it — keep it that way. |
| 5 | Panel domain | — | set one; the daemon issues the certificate itself | HTTPS-only with a trusted certificate is the supported configuration — the embedded ACME client (RFC 8555) issues at first start and renews daily while the service runs. |
| 6 | Portal port (if set) | — | open it in the host firewall | The daemon binds it, but the panel cannot open a host firewall for you; `ufw allow <port>/tcp`. |
| 7 | Two-factor auth | off | on, for any internet-facing panel | The single highest-value control after `allow_all`. |

Optional but recommended for a public deployment: keep the API on loopback and
reach it over an SSH tunnel; put the dashboard behind a VPN or an IP allow-list at
the firewall; and run the daemon as a user that can only bind port 53 through
`CAP_NET_BIND_SERVICE` rather than as root.

---

## 🚫 Known Non-Goals

These are documented so that a report about them can be answered by pointing here
rather than by a debate.

- **The resolver answers the public internet on port 53.** That is the product.
  An open resolver is a deliberate default for a personal install and a
  documented misconfiguration for a shared one — see checklist item 1.
- **The admin path is not a secret.** It is defence in depth; the login is the
  control.
- **Field encryption does not defend against a local attacker who can read
  `master.key`.** It defends a stolen database file. The two travel together in
  your backups by design; keep that backup encrypted.
- **The SNI relay is not a censorship-resistant transport.** It relays a TLS
  session without terminating it; it does not obscure what the session is.
- **Query logs are not retained.** There is no disk log to hand over, by design,
  and no setting that turns one on.
- **The project does not provide a WAF or DDoS mitigation.** Rate limits and
  connection caps bound resource use; volumetric attacks are the hosting
  provider's layer.

---

## 🧪 Verification You Can Run Yourself

Two recipes, both deterministic, both used by the maintainer before every release.
Neither needs internet access after the modules are cached.

**Full suite with the race detector**, in an isolated container:

```bash
bash build/race-in-docker.sh ./...
```

This copies the working tree out of the platform mount, resolves modules in a
networked phase, then runs `go vet` and `go test -race` with `--network=none` —
so a test cannot reach out and the result depends only on the source. The script
lives in the repository for this purpose; read it before you run it.

**On the host, without a container:**

```bash
go vet ./... && go test ./... -count=1
```

**Regression tests for the controls above.** The security-relevant tests are
named, not scattered — these are the ones to read first:

| Test | Asserts |
| :--- | :--- |
| `TestSubscriberSurfaceServesNoAdminRoutes` | The public subscriber listener exposes no admin route. |
| `TestSubscriberListenerRebindsOnPortChange` | A moved portal port releases the old socket and binds the new one. |
| `TestKeyScoping…` (`key_scoping_test.go`) | The master REST key is refused on dashboard admin routes; only the unlock recovery route accepts it. |
| `TestAPIKeyRotationConsultsTOTPGate` (`router_totp_test.go`) | v1 key rotation faces the same second factor the dashboard enforces. |
| `TestTwoFactorGatesLogins`, `TestSecondFactorGatesCredentialChanges` | Password and API-key changes re-authenticate; codes are single-use. |
| `TestTOTPCodeCannotBeReplayedAcrossGatedEndpoints` | One validated code, used once: a second gated endpoint refuses the same code, and a fresh one passes (the cross-endpoint single-use invariant). |
| `TestDoHAcceptsBothBase64URLSpellings`, `TestDoHRejectsMethodsRFC8484DoesNotDefine` | DoH GET (both base64url spellings) and POST work; non-RFC methods are refused. |
| `TestLDAPLoginPaths` | Only the admin account's directory entry may log in; a non-admin directory user is refused. |
| `TestDotFirstIssuanceConstructsHolderAndRebinds`, `TestDotClearDetachesHolderAndSource` | The first DoT/DoH certificate goes live; clearing detaches the dedicated source. |
| `TestValidatePortRefusesTheRedirectListenerPort` (`portplan_test.go`) | The panel cannot be moved onto the redirect listener's port. |
| `TestPortalUnknownTokenAnswers404` | The friendly error page no longer carries a success code. |
| `TestPoC01…`–`TestPoC05…` | The red-team set for the subscriber surface: no admin exposure, no auth surface, no token oracle, no reason-code leak, operator title escaped. |
| `TestIndexHTMLSectionsAreDivBalanced` | The served dashboard document is structurally balanced (a mis-nested tag reparents the layout). |

A clean `go test` run is the baseline any report is measured against. If you can
add a failing test that demonstrates the issue, that is the fastest possible route
from report to fix.

---

## 📐 Standards & RFC Compliance

HyperDNS implements and honours the following IETF specifications. Compliance
is verified by the test suite and — for the externally observable behaviour —
by an external-attacker pass against a live deployment.

| RFC | Scope in HyperDNS |
| :--- | :--- |
| [RFC 1035](https://www.rfc-editor.org/rfc/rfc1035) / [RFC 2181](https://www.rfc-editor.org/rfc/rfc2181) | Core DNS message format and transport; the label/hostname rules the ACME and domain validators enforce |
| [RFC 7766](https://www.rfc-editor.org/rfc/rfc7766) | DNS over TCP: persistent connections, reuse, pipelining, and connection management |
| [RFC 7858](https://www.rfc-editor.org/rfc/rfc7858) | DNS-over-TLS on port 853, with the correct ALPN (`dot`) so a standards-compliant client is not refused for offering one |
| [RFC 8484](https://www.rfc-editor.org/rfc/rfc8484) | DNS-over-HTTPS using `application/dns-message`; **both methods** — GET with the base64url `dns` parameter (padded and padding-free spellings accepted) and POST |
| [RFC 7828](https://www.rfc-editor.org/rfc/rfc7828) | `edns-tcp-keepalive` on connection-oriented transports, never on UDP, and only when the query asked |
| [RFC 8914](https://www.rfc-editor.org/rfc/rfc8914) | Extended DNS Errors: unauthorized `REFUSED` responses carry EDE 18 (`Prohibited`) with an explanatory string, where the query carried OPT — on UDP, TCP and DoT alike |
| [RFC 8555](https://www.rfc-editor.org/rfc/rfc8555) | ACME certificate issuance and HTTP-01 challenge handling |
| [RFC 6238](https://www.rfc-editor.org/rfc/rfc6238) | TOTP authentication; HyperDNS additionally enforces cross-endpoint single-use of successfully validated codes (see below) |
| [RFC 9110](https://www.rfc-editor.org/rfc/rfc9110) | HTTP semantics and method handling, including the HTTPS URI scheme |
| [RFC 9457](https://www.rfc-editor.org/rfc/rfc9457) | `application/problem+json` problem details on the v2 API surface |
| [RFC 9745](https://www.rfc-editor.org/rfc/rfc9745) | `Deprecation` response header on the v1 API |
| [RFC 8594](https://www.rfc-editor.org/rfc/rfc8594) | `Sunset` response header on the v1 API |
| [RFC 9562](https://www.rfc-editor.org/rfc/rfc9562) | UUID v4 subscriber identifiers (supersedes RFC 4122) |
| [RFC 6066](https://www.rfc-editor.org/rfc/rfc6066) | TLS Server Name Indication, the mechanism the SNI relay parses and dispatches on |

**Implementation behavior — not RFC requirements.** The following are
deliberate product choices, stated here so the table above is about the RFCs
and nothing else: the relay forwards TLS without terminating it and may
fragment ClientHello records as a traffic-handling technique (not something
RFC 6066 standardizes); HyperDNS imposes no fixed per-connection DNS-query
count limit (RFC 7766 leaves resource policy to the implementation — ours are
the connection and rate caps above); the ACME client runs issuance and daily
renewal from the daemon, single-flighted, against Let's Encrypt's production
directory; the fail-closed certificate validation on the panel is a security
policy, not something RFC 9110 specifies.

The v1 API additionally sets `Link: successor-version` headers pointing at
`/api/v2/version`. Deprecation is `Deprecation` (RFC 9745), and the sunset
date is `Sunset` (RFC 8594) — the two mean different things and only v2 is
the successor.

---

<p align="center">
  <a href="../README.md">README</a> •
  <a href="API.md">REST API</a> •
  <a href="CHANGELOG.md">Changelog</a> •
  <a href="PRESET_CATALOG.md">Preset Catalog</a>
</p>
