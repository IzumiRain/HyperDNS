# 📜 HyperDNS Changelog

All notable changes to the **HyperDNS** project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## 🌐 [v2.5.0-beta.1] — Per-Subscriber Device Limit & IPv6 for Proxied Names

Codename **HyperFORGE**. Two networking features that had been on the roadmap since the fork feedback.

### ✨ Added
- **Per-subscriber device limit (1–5).** Each account can now hold more than one bound source IP. Set **Max Devices** on the add/edit client form (or `max_devices` in REST v2); a new address past the limit evicts the oldest, LRU-style. The default is 1, so accounts created before this change behave exactly as before. The cross-account address guard (Mantis C-04) is unchanged: an address already bound to a *different* subscription is still refused, so a device limit is not a way to share one paid account across households.
- **IPv6 answers for proxied names.** When the server has a reachable IPv6, set it as **`public_ipv6`** and proxied names answer `AAAA` with it, so an IPv6 client reaches the SNI proxy over v6 instead of being pushed onto IPv4. With `public_ipv6` empty the previous behaviour stands — `AAAA` on a proxied name is withheld so the client uses the proxied `A` record and cannot leak past the proxy over v6. Direct (non-proxied) names already return their real `AAAA`, and the DNS and SNI listeners already bind dual-stack, so this closes the remaining gap for the proxied path.

### 🧪 Quality gates this release passed
- `go build ./...`, `go vet ./...`, gofmt clean; all packages green with `-count=1`.
- New tests: `MaxDevices` clamp (1..5), multi-device LRU eviction, the default single-device path, and the C-04 conflict still refused under a multi-device account; the client codec and settings round-trip guards updated for the new fields.

### ⚠️ Upgrade notes
- No migration: `max_devices` defaults to 1 and `public_ipv6` to empty, so an upgraded install behaves identically until an operator opts in.

---

## 🎨 [v2.4.0-beta.1] — Custom Portal CSS from a File or URL

Codename **HyperFORGE**. Adds a way to brand the subscriber portal beyond the inline CSS box.

### ✨ Added
- **The subscriber portal's custom CSS can now come from a server-local file or an online URL,** not just the inline textbox — inspired by how panels like 3x-ui let an operator point at a stylesheet. Choose the source under **Settings → Subscription Portal → Portal custom CSS**:
  - **Inline** — paste CSS as before.
  - **Local file** — an absolute path on the server (e.g. `/root/css/sub.css`); the daemon reads it (read-only, capped at 256 KiB), runs it through the same sanitiser as the inline box (`<style>`/`<script>` defanged, `@import` and external `url()` stripped), and inlines it.
  - **URL** — an `http(s)` stylesheet address emitted as a `<link>` the subscriber's browser loads directly. The daemon never fetches the URL itself, so the resolver takes on no SSRF or latency risk.
  Only the field for the selected source is stored; a missing local file or a bad value renders the portal with no custom CSS and logs why, rather than failing the page.

### 🧪 Quality gates this release passed
- `go build ./...`, `go vet ./...`, gofmt clean; all packages green with `-count=1`.
- New tests: source resolution for inline/local/url (including sanitisation of a local file's `@import` and a missing-file no-op) and save-time validation of the source selector, the absolute-path rule and the http(s) URL rule.

### ⚠️ Upgrade notes
- Existing inline CSS keeps working unchanged: a record with no source set resolves as `inline`, exactly as before.

---

## 🔵 [v2.3.0-beta.1] — Auto-Updating Presets, Custom Policy Groups, Installer & Login Fixes

Codename **HyperFORGE**. A feature release (new user-facing surface, so a MINOR bump per the project's tag policy).

### ✨ Added
- **A signed preset-update channel.** The 171+ built-in policy presets moved from hard-coded Go slices to embedded JSON data files (`presets/<id>.json`), and the daemon can now pull newer routing lists from a signed channel served over GitHub Pages. Every update is an ed25519-signed manifest (the public key is baked into the binary; the private half lives only in the release workflow's secrets) with a sha256 for each policy file. The daemon downloads only what changed, swaps it in atomically, health-checks the result (probe queries + a minimum-size floor) and **rolls straight back on any failure**; a stale mirror can never downgrade a running catalog, and only domains of policies the binary already knows are updated. Drive it from **Policy Presets → Policy Catalog Updates** in the dashboard, `hdns update-presets`, or menu item 12 in the console. Auto-apply is opt-in per server, with the same health-check and rollback.
- **Named custom policy groups.** Define a named bundle of domains with one action — proxy, direct, or block — and toggle or edit it as a unit, the structured evolution of the flat Custom Proxied/Blocked/Direct lists. Managed from a new **Custom Policy Groups** card in the dashboard and the `/api/custom-groups` endpoints; stored in their own database bucket and re-applied to the resolver on every edit and at startup.

### 🖼 Fixed
- **The console's Uninstall no longer points at a missing script (GitHub issue #1).** A piped `curl | bash` install had no local `scripts/` directory to copy `uninstall.sh` from, so `/opt/hyperdns/scripts/uninstall.sh` was never written and the console's Uninstall failed with a bare *not found*. The installer now downloads `uninstall.sh` the same way it already fetches `restore.sh`, and the console falls back to the built-in cleanup (which also retires the resolver override and firewall rules) when the script is absent.
- **No more pre-login flash of the dashboard.** The panel is a bearer-token SPA, so a browser navigation to the dashboard carried no credential and the shell HTML rendered for a few hundred milliseconds before the JS noticed there was no token and redirected — a pre-auth flash of panel chrome to anyone who knew the admin path. Login now also sets an HttpOnly, admin-path-scoped, `SameSite=Strict` document cookie, and the SPA document route redirects to the sign-in page server-side when it is missing or dead, so the shell never reaches an unauthenticated browser. The cookie gates only the document; every `/api/*` call still requires the bearer header, so no CSRF surface is added.

### 🧪 Quality gates this release passed
- `go build ./...`, `go vet ./...`, gofmt clean; all packages green with `-count=1`.
- New tests: preset channel (sign/verify/apply/rollback/downgrade/restart), custom-group matcher precedence and catalog-swap survival, custom-group service CRUD + validation + restart reload, the login document gate, and the installer download path.

### ⚠️ Upgrade notes
- Existing presets keep working unchanged — the embedded baseline is the permanent offline fallback, and the channel is opt-in. No data migration is required; the new `custom_groups` bucket is created on first write.

---

## 🔐 [v2.2.0-beta.1] — Whitelist by Default, Built-In ACME, API v2, Google/AI Presets & a Real Console

### ✨ Added
- **Client Access Whitelist is the default.** An unknown source is refused by DNS (`REFUSED`, with an RFC 8914 *Prohibited* Extended DNS Error for OPT-bearing queries so the client learns *why*) instead of being served for free. Fresh installs ship whitelist-on; existing installs converge through a one-time idempotent migration, and an operator who wants public mode back flips the dashboard toggle (their choice then persists over every default).
- **Certificates are issued by the daemon itself.** The certbot/acme.sh shells are gone, replaced by an in-process ACME client (`golang.org/x/crypto/acme`, no new dependencies, ships inside the single binary — an offline install can issue the moment it has internet). The HTTP-01 challenge is served out of the port-80 listener that is already running, so issuance and daily renewal happen **while the service runs** — no more stopping HyperDNS so certbot could borrow port 80. Renewed certificates hot-swap into the live listeners without a restart.
- **Google, AI and Social service presets.** Three new policy categories: *Google Services* (Search, Gmail, Drive, YouTube — with the shared CDN zones deliberately excluded and the update CDNs forced direct), *AI Assistants & Platforms* (Copilot, Perplexity, Grok, DeepSeek, Mistral, OpenRouter, …), and *Social & Messaging* (X, Instagram, Facebook, WhatsApp, Telegram, Reddit). Default on like every other proxy category, independently toggleable, per-client selectable.
- **REST API v2.** A versioned successor contract: symmetric field names (`display_name`, `allowed_ips`, `validity_days` — create and update finally agree), cursor-paginated lists (`{items, next_cursor}`, bounded limit), RFC 9457 `application/problem+json` errors, `POST /clients/{id}/actions/{action}` for mutations, and **strict decoding** — an unknown field is a 400, not a silently dropped typo (v1's decoder turned `expires_days` into a lifetime account). v1 keeps working with `Deprecation`/`Sunset` headers.
- **The created-client credentials popup.** Creating a subscriber now opens a dialog with the register link and the registration secret (masked until revealed, copy buttons on both, focus-managed like every other modal) — the two things the operator needs to hand over at the moment they are minted, instead of hunting through the card's Bot Card afterwards.
- **A console worth opening.** `hdns` now clears and redraws in place (no more menu-copy-per-action scrolling), carries the banner and ANSI colors (auto-disabled for pipes, `NO_COLOR` and dumb terminals), sanitizes untrusted names against ANSI injection, prints the subscriber list as an aligned table, and — the functional gap — can **stop and start the service**, plus stop demands a typed confirmation.
- **Configurable game-relay ports and a random management port.** The four extra listeners (5223/5222/2099/8393) are settings, not literals. Fresh installs draw the panel port randomly from 20000–60000 (8080 is everyone's default and collides with half the internet), open it in the firewall, and print it in the banner; upgrades keep their existing port. Every port change — dashboard, TUI or control socket — runs the same shared validator (listener collision, disabled-service warning, privileged-port warning, live bind probe) before anything persists.
- **DoH URLs tell the truth.** A canonical `doh_url` builder (domain-first, the DoH listener's own port, https) feeds the Connect Guide and `/api/config` — the guide used to print `http://IP:web_port/dns-query`, wrong in scheme, port and host at once. The portal's copy buttons copy the displayed values (they hardcoded 8443/853).

### 🔐 Security
- **The master REST key no longer opens the dashboard.** It used to authorize every admin route — settings, credentials, LDAP mode — so one leaked REST key (the credential that lives in integrations and CI logs) was a full panel takeover. It now authorizes the versioned REST API and exactly one dashboard route: the lockout-recovery unlock the root-local TUI calls. Dashboard routes take real sessions.
- **The public subscription API no longer leaks the registration secret or operator note** (critical v2.1.0 fix carried in this release's baseline: `GET /api/sub/<token>` served the full client record including the write credential; it now serves display data only).
- **The DoH listener no longer serves the admin panel.** The DoH port answered with the complete dashboard handler — login page, admin namespace, every `/api` route — on the wildcard bind, so any network that could reach the DoH port could reach the panel's admin surface too. It now serves `/dns-query` plus the same public portal surface the subscriber links name, and the same bare 404 for everything else.
- **v1 API-key rotation faces the second factor.** `POST /api/v1/api-key` rotated the master key with no TOTP check while the dashboard's rotate endpoint demanded one — with 2FA enabled, a hijacked session could rotate the key through the v1 route unguarded. The same gate now runs on both (injected into the API router; still a no-op while 2FA is off).
- **The port validator covers the HTTP→HTTPS redirect listener.** The shared validator knew the DNS trio and the SNI relays but not the redirect port, so a panel port that collided with it was only discovered as a fatal startup in service mode — the exact failure the validator exists to prevent.
- **The directory can no longer be repointed from a stolen session.** Saving the LDAP settings now re-asks for the current password (and a current code when 2FA is on) — the directory IS the login path, and repointing it was the one credential change a bare session could still make. And the panel now decides who may log in: only the directory entry naming the admin account authenticates, where before every user under the configured BaseDN came in with full panel admin.
- **API-key rotation re-asks for the current password**, on the dashboard — matching the file's own invariant ("look, but not touch"). A validated TOTP code is also **single-use across every gated endpoint** now (login included), so one observed code cannot authorise a rotation, an unlock and a login in its validity window, and the code no longer rides the query string on the v1 route.
- **The pending 2FA enrollment secret is no longer readable through a live session.** `/api/auth/2fa/status` answers with a bare "enrollment open" marker; the URI (which embeds the secret) only leaves the password-gated setup response.
- **The keyless metadata routes face the same bind gate.** `/api/v1/version`, `/api/v1/docs` and `/api/v2/version` answered external callers even when the REST API was bound to localhost; they now 403 like everything else on a loopback bind.

### 🖼 Fixed
- **The first DoT/DoH certificate now goes live.** A fresh install that issued the DoH/DoT domain's certificate from Settings persisted the domain, skipped the nil certificate holder, skipped the listener rebuild (a flip flag nothing ever set), and logged that the listeners served the new certificate while they kept serving the panel's until restart. The holder is now constructed mid-process and the listeners rebuilt the moment the issuance lands; clearing the domain detaches the dedicated source just as completely.
- **The DoT/DoH listener rebuild is serialized.** Two concurrent dashboard saves (or a save racing the daily renewal) could interleave the shutdown/start of the TLS listeners and race on their server fields. A mutex covers the source swap and the rebuild.
- **A failed portal rebind no longer leaves the record moved and the portal down.** Issuing a subscription certificate persisted the new domain first and rebound the listener second — a bind failure (port conflict) kept the new record while the portal listener was gone. The previous record is now restored and rebound, and the response says so.
- **ACME robustness.** The HTTP-01 challenge answer strips a default port from the Host header (a validator sending `Host: name:80` no longer misses the pending lookup); the account key is read for persistence through a locked accessor instead of a bare slice-header read; and the client-setup network calls run outside the manager mutex that the port-80 challenge path shares, so a slow registration can no longer stall challenge answering.
- **A stalled live-log viewer can no longer pin the stream.** The SSE stream runs without a global write timeout by necessity, but each frame now carries its own write deadline and a failed write releases the subscriber slot — a client that stops reading used to hold both the goroutine and one of the capped slots until restart.
- **Every certificate the daemon issues now renews itself.** The daily renewal loop checked only the panel domain, so a subscription portal or DoH/DoT certificate hit its expiry date around day 90 with nothing coming. The loop now covers all three surfaces, and a panel domain whose boot issuance once failed is retried daily too. A run that fails after the certificate lands (persist, validation, apply) now marks the progress bar terminal instead of leaving it at 90% with no error, and a failed DoT/DoH listener rebuild is reported to the operator instead of logged as success.
- **A deliberately customised portal port survives panel-port changes.** The dashboard now marks a port the operator chose (and unmarks it when they return to the panel's), so the boot-time drift repair and the live copy-follow only re-point records that still ride the panel origin — and the repair also recognises the cleared-domain shape the current UI can produce.
- **A negative quota or validity can no longer invert a plan.** `traffic_limit_gb: -50` behaved as unlimited and `days: -5` as lifetime; both are refused at creation and on update.
- **v2's strict decoder covers the frame boundary.** Trailing JSON after the first value (`{"a":1}{"b":2}`) was accepted on the first object with the second silently dropped; it is a 400 now.
- **API examples use the configured domain, not the IP.** The panel's curl/Python/Node snippets (and the Node snippet's `window.location.origin` — undefined in Node — replaced by a real `ORIGIN` constant) now speak the domain, the real scheme and the real port, against `/api/v2`.
- **v1's login-2FA reveal ordering** (carried in this release's baseline): the dashboard login form consumed the response body before reading the `twofactor_required` flag, so the 2FA code field never appeared and a correct password looked like a wrong one.
- **`allow_all` can no longer be silently overridden by config.json** at every boot (DB-wins precedence restored), and the v2.2.0 migration respects an operator's later explicit choice.
- **The installer's final banner no longer tells the operator to stop the service before opening the terminal console.** The old wording ("TUI and daemon cannot share the database at once") was stale v2.1.0 guidance: since v2.2.0 the `hdns` console is a pure control-socket client — it talks to the running daemon and never opens the database, so it runs beside the service at any time (`hdns status` and `hdns flush` likewise). Fixed in the online installer, the offline installer and the offline bundle.

### 🧪 Quality gates this release passed
- `go build ./...`, `go vet ./...`, gofmt clean; **19/19 packages** green with `-count=1`.
- New regression suites: whitelist migration (converge-once, idempotent crash-window rerun, operator-choice respected), EDE attachment (OPT-only, quota refusals not mislabelled), ACME challenge path (unknown token / foreign Host / non-GET relay unchanged), preset resolution (shared-CDN exclusion), v2 contract (pagination bounds, strict decode, symmetric names, action routes), v1 deprecation headers, and master-key scoping.
- Installers: `bash -n` clean; the offline bundle mirror is byte-identical to the canonical copy.
- Linux install verification and the race detector run in WSL Ubuntu-24.04 (see the release notes for the result).

### ⚠️ Upgrade notes
- The first boot after upgrading applies the whitelist migration: **unregistered sources stop resolving.** Register clients (or re-enable public mode from the dashboard) deliberately.
- Any integration holding the master key **must keep using `/api/v1` or `/api/v2`**; it can no longer drive dashboard admin routes.
- The offline bundle no longer ships `scripts/ssl_issue.sh` — there is nothing to run by hand; the daemon issues and renews on its own.

---


### ✨ Added
- **The subscriber port is a real listener now.** The Subscription Portal's port field used to change only the *text* of the links it generated — nothing ever bound it, so an operator who set a portal port published a URL that refused the connection. Saving the card now binds a dedicated public listener (and moves it live on the next save, no restart). That listener serves **only** the portal routes — `/sub/`, `/ip/`, `/api/sub/`, `/css/portal.css`, `/js/portal.js`, `/fonts/` — and answers the admin namespace, the REST API, DoH and the SPA with the same bare 404 a stranger gets. Its TLS scheme follows the panel's, reusing the panel certificate by default or the record's own pair for a separate subscription domain, so the link's scheme always matches what is listening.
- **A per-reason registration answer.** `POST /ip/<token>` now returns a machine-readable `reason` beside its English text (`secret`, `suspended`, `expired`, `quota`, `conflict`, `invalid`), and the portal renders its own translated line for each. The subscriber's copy is in both languages, and the reasons are only reachable **after** the secret check — a wrong-secret probe cannot tell a taken address from a free one.

### 🖼 Fixed
- **The footer is inside the content column.** The root cause was not CSS: a `<div class="glass-panel">` in the REST API tab was never closed, and an extra `</div>` in the Settings tab balanced the count while closing the layout wrapper early. The HTML parser then reparented the Connect tab, the desktop footer and the mobile nav onto `<body>`, which is a row-wise flex container — so the footer rendered **beside** the content, at the right edge of the page. Both tags are corrected, and `index.html` now carries structural regression tests (per-tab div balance, footer-inside-main, no mojibake, no control bytes) so the next hand-edit that unbalances a tag fails the build instead of reaching a screenshot.
- **`Reg Link` hands out the subscriber page, not the API.** The button copied `.../ip/<token>` — an API endpoint since Phase B — while `/sub/<token>` is the page a subscriber opens. It now copies `/sub/`, and a separate `data-reg-url` carries the registration API for the Bot Card.
- **The Bot Card is current.** The Telegram text named the retired `/ip/` link as if it were the subscriber page and printed `دی ان اس اختصاصی شما :` with nothing after it. It now carries the four things the subscriber needs: the `/sub/` portal link, the registration secret, the DNS address, and the automation API URL.
- **The Portal title reaches the page.** The h1 rendered a translated constant, so the operator's Portal title changed only the browser tab. The heading is now their `Title` (falling back to "HyperDNS"), and the subtitle and footer carry the **running** version instead of a hardcoded `v2.0.0-beta [HyperRAIN]` that had survived two releases.
- **A failed listener bind is reported, not swallowed.** If the portal port is already held, the save persists and the card says so with the reason, rather than claiming success over a port nothing can reach. The card also names the one manual step the panel cannot take for the operator: opening that port in the host firewall.

### 🧪 Quality gates this hotfix passed
- `go build ./...` clean; **17/17 packages** green with `-count=1`; `go vet` clean.
- **Race detector 17/17** inside an isolated container (`golang:1.26-bookworm`, `--network=none`, modules pre-seeded in a separate networked phase) — zero DATA RACE reports.
- **Playwright E2E 20/20** against the live demo daemon, including a new **12-test Settings sweep** that exercises every card in that tab — portal save/persist, 2FA, LDAP, admin path, SSL, custom proxied domains, custom blocked domains, DoH tokens, static records, session idle, and the credentials modal — asserting persistence across a reload rather than trusting a toast.
- **Mantis PoC set (5 new, all REFUSED)** for the new public listener: the subscriber port exposes no admin namespace, no auth endpoints, DoH or SPA routes (20 path shapes including traversal and case variants); registration is not a token oracle (a live token with a wrong secret answers identically to an unknown token); the new reason codes leak nothing to a caller without the secret; and the operator-supplied Portal title is escaped, not executed.
- Served-asset verification over the running daemon: the portal answers 200 on its own port with the operator's brand line, version-correct subtitle and footer; the admin routes answer 404 there; `/css/portal.css`, `/js/portal.js` and the fonts answer 200.

### 📦 Artifact
- The offline bundle was rebuilt from the fixed sources. `hyperdns-offline-v2.1.0-beta5-20260910-1701.zip`, sha256 `0a57cb817a7e50a9e7cc5c3c80df07d81798527d5af932ef28585285177a8cee` (the beta4 zip is withdrawn).

---

## 🖼 [v2.1.0-beta Hotfix 4] — Dashboard Text Corruption & Footer Placement

### 🖼 Fixed
- **The language selector reads فارسی again (and every stray `â`/`Â` is gone).** The shipped `index.html` carried cp1252-mojibake text baked into the embedded document: the Persian language labels rendered as `ÙØ§Ø±Ø³ÛŒ`, and em-dashes, bullets, curly quotes, the setup-wizard `●` glyph and the Telegram template emojis were all double-encoded. Every sequence in the document was repaired back to proper UTF-8 (140+ runs across the static markup, the language buttons, and the inline Telegram templates); the served document now scans **zero** mojibake markers and **zero** stray control bytes, and the portal's server-rendered strings (`portal.go`, `portal_i18n.go`, `landing.go`) were swept with it.
- **The desktop footer sits inside the content column again.** The `<footer>` had drifted outside `</main>`, so the flex layout pushed it to the right edge of the page. It is moved back inside the main element, and the placement is pinned by the served-document checks.

### 🧪 Quality gates this hotfix passed
- `go build ./...` clean; **17/17 Go packages** green with `-count=1`.
- **Playwright E2E 7/7** against the rebuilt demo daemon — the suite now targets that instance's live credentials and re-verified the standalone login, the 2FA hiding, the portal secret gate, and the session-idle card end to end.
- Served-asset verification over the running daemon: all 6 dashboard assets (CSS/JS) and the admin-rewritten document answer 200 with clean UTF-8; the `/login` page serves with the admin base rewritten and no placeholder leak.
- The offline bundle was **rebuilt** from the fixed sources — the previous beta4 zip contained the corrupted document. Artifact at the time: `hyperdns-offline-v2.1.0-beta4-20260910-1053.zip` (superseded by Hotfix 5's beta5 bundle, which also carries the footer-structure fix).

---


## 🔐 [v2.1.0-beta Hotfix 3] — Standalone Login, Secret-Gated IP Registration, Lockout & Session Controls

### ✨ Added
- **A standalone `/login` page (Phase A):** `/<admin-path>/login` serves a self-contained sign-in document — inline CSS, one small script, **zero external asset requests** — so the whole dashboard bundle (index.html + app.js + chart/icon libraries) is no longer readable pre-auth by whoever holds the namespace. The retired `/<admin-path>/dash/login` redirects to it. The two-factor field appears **only** when the server says the password verified but the code failed (`twofactor_required`, Hotfix 2's flag), so a first-time login never shows a code box.
- **Out-of-band registration secret (Phase B, Mantis C-03):** every account now carries a 96-bit `register_secret` (AES-256-GCM sealed beside the token). The subscriber's `POST /ip/<token>` demands it; the operator's client modal displays and regenerates it. A leaked `/sub/` link alone is now **read-only material**.
- **`/ip/<token>` is an API now (the operator's own algorithm):** POST binds a new address (with no `ip` field it binds the caller's — the 1-click flow); GET serves a bilingual explainer page for old bookmarks. `/sub/<token>` is a pure read-only overview: **no visit, prefetch, or unfurler can move a binding any more** (C-01/C-02/C-03 all closed dynamically — the four Mantis PoCs were re-run against the fixed build and all four now refuse).
- **Gates on the registration path:** a suspended account answers 403 ("suspended"), an expired one 403 ("expired"), a quota-drained one 403 (against the **live** ledger figure, not the stale stored counter), and an address already bound to a *different* subscription answers **409 without disabling either account** — CGNAT makes shared addresses ordinary (C-04).
- **Login lockout hardening + operator unlock (Phase C):** 3 failures → 10 minutes (was 5/15). New `POST /<admin-path>/api/auth/unlock` (session or API key, plus a current TOTP code when 2FA is on) clears one or all locked addresses, and the TUI gained menu entry **[12] Clear Login Lockouts** that calls it over loopback — the tracker lives in the daemon's memory, so this works **while the service runs**, with no restart.
- **Configurable session idle timeout (Phase D):** `POST /api/settings` accepts `session_idle_minutes` (5–1440, default 15), applied **live** on the running SessionManager and persisted. New Settings card shows the value in force and saves a replacement. The 24 h absolute lifetime is unchanged.

### 🖼 Fixed
- **`initSubscriptionSettings` ReferenceError (found by the Playwright E2E):** app.js called the function bare, but it lives inside the twofa ES module and was never exported onto `window` — every dashboard boot threw, and `handleRouteFromURL` never ran, so deep links like `/<admin-path>/dash/settings` silently stayed on Dashboard. The module now exports it through the same bridge as the 2FA/LDAP hooks, and app.js calls it via `window.initSubscriptionSettings?.()`.
- The session-idle card lives in the **Settings panel** (tab-rules), where the route actually lands — not in the API tab.

### 🧪 Quality gates this hotfix passed
- `go vet` clean; **17/17 packages** green twice: on the dev box and inside the isolated Mantis container (`golang:1.26-alpine`, `--network=none`).
- **Race detector 17/17** in `golang:1.26-bookworm` — zero DATA RACE reports.
- **Playwright E2E 7/7** against a live isolated daemon: standalone login renders without external requests and hides the 2FA row; a wrong password never reveals it; the correct password lands on the dashboard; the retired route redirects; the portal binds nothing on a plain visit and binds **only** with the correct secret; the session card saves, persists, and re-reads.
- The four dynamic Mantis PoCs (C-01..C-04) re-run in the container: **all four now refuse** where the beta accepted.

---
## 🛠 [v2.1.0-beta Hotfix 2] — Not-Secure Panel & Broken Dashboard Assets

### 🔐 Fixed
- **The "Not secure" panel is gone — root cause closed.** `ValidatePanelCertificate` now refuses a **self-signed** certificate whenever a panel domain is configured. The fallback generator writes the configured domain into its SAN, so the old date-and-hostname-only check treated the self-signed pair as "a usable certificate is already in place" and the ACME paths never fired; the daemon then served the fallback and every browser showed Not secure. The panel now **fails closed** on a domain install without a CA-signed certificate, with an actionable error, instead of serving one no visitor will trust.
- **The 8443 DoH/DoT listener honors the same policy.** `LoadOrGenerateTLSConfig` no longer generates or accepts a self-signed fallback while a domain is configured — DoT and DoH come up only with a CA-signed certificate, instead of silently answering with one every Android Private DNS client and browser refuses.
- **ACME issuance order fixed.** The startup issuance used to run *after* the SNI proxy bound ports 80/443, so certbot `--standalone` could never bind the challenge port on a default install. It now runs before any listener binds and before the TLS config is loaded, so a freshly issued certificate is what the listeners serve on their first start — and it no longer runs for one-shot subcommands (`hdns flush`, `uninstall`).

### 🖼 Fixed
- **Dashboard CSS/JS actually load behind the hidden admin path.** `index.html` was written for the pre-v2.1 root mount and references `/css/…` and `/js/…` absolutely; behind `/<admin-path>/dash/` the browser resolved those against the host root, where nothing has been served since v2.1 — the panel rendered unstyled with every script 404ing. The document is now served with its asset references rewritten below the live admin namespace (per-prefix cached, its own ETag, gzip preserved), and the rewritten references are pinned by regression tests that fetch every one of them through the real handler.

### 📦 Changed
- **Offline installer issues the certificate itself (3x-ui method).** Step 4b runs the bundled `scripts/ssl_issue.sh` (acme.sh, standalone HTTP-01 with the service stopped around the challenge, full chain + key installed, automatic renewal via acme.sh's cron with a restart) while port 80 is still free. It verifies the result is actually CA-signed (issuer ≠ subject) before continuing, retries once for DNS propagation, and **stops with the real cause** (A record not pointing here / port 80 blocked / rate limit) instead of printing a success banner.
- **The success banner is now earned.** Step 6 polls `is-active` for up to 20 s, then probes the real listener over HTTPS with the system trust store (`--resolve`, no `-k`): the dashboard document, one stylesheet and one script must each return 200 through the hidden path. Any failure exits 1 with diagnostics; the celebration only prints when every check passed.
- **Installer polish:** the public IP is detected up front (the domain prompt used to print "Point an A record at " with an empty address), the domain prompt defaults to and validates the existing config's domain, `HYPERDNS_DOMAIN`/`HYPERDNS_EMAIL` cover non-interactive provisioning, mangled `??` banner text replaced with readable labels, and `ssl_issue.sh` no longer passes `--force` (a re-run no longer burns one of Let's Encrypt's five duplicate-certificate slots per name per week).
- **Release pipeline:** the offline bundle now ships `version.json` (the daemon's drift check needs it), and `scripts/install-offline.sh` ↔ `offline-bundle/install.sh` are byte-identical canonical copies.

---

## ⚡ [v2.1.0-beta] UI/UX & Release Hardening (rework Phases 4+6)

### ⚡ Performance
- **Tailwind JIT Engine Removed (−397 KB + no `eval`):** The Play CDN JIT runtime that compiled utility classes in the browser is replaced by a committed, purged 42 KB stylesheet (`css/tailwind.purged.css`) compiled ahead of time by `tools/tailwind.config.js` (dev machine only — no Node at build or deploy time). `script-src 'unsafe-eval'` is gone from the CSP, the page renders styled on first paint without waiting for a compiler, and the class inventory is pinned by `TestEveryUtilityClassSurvivedThePurge` — a class the purge misses fails the suite with the regeneration command.

### ✨ Added
- **Vendored Swagger UI:** `web/swagger/` (Apache-2.0) ships inside the binary; `/api/v1/docs` loads the viewer same-origin and the per-route CSP exception for `unpkg.com` is gone. "100% offline" is now literally true for every asset.
- **First ES Module:** the 2FA/LDAP settings panel (`js/modules/twofa.js`) is the dashboard's first `<script type="module">` — strict mode, deferred execution, reading shared state through the `window.__hdns` bridge at call time.

### 📦 Changed
- Version bumped to **v2.1.0-beta (HyperSHIELD)**; installer banner and UI placeholders updated.

---
## 🔒 [v2.1.0-beta] - 2026-09-07 (Codename: HyperSHIELD)

### 🔐 Highlights
- **HTTPS Panel, Done Properly (Phase 1):** The dashboard listener serves TLS with `tls.LoadX509KeyPair`, validates that the certificate covers the configured domain and is currently usable, and **fails closed at startup** otherwise. An optional redirect listener answers GET/HEAD with `https://…` (405 + `Allow` for anything else, never redirecting attacker-typed hosts). HSTS `max-age=31536000` goes out only on responses that actually arrived over TLS.
- **The Root Domain Is No Longer the Login Page (Phase 2):** `/` now serves a small, self-contained Matrix-inspired landing page — no external assets, no operational data, no links, no credential-adjacent words. It carries a real title, WCAG-AA contrast, a `prefers-reduced-motion` fallback and a `<noscript>` variant.
- **A Hidden Admin Namespace (Phase 3):** The dashboard SPA and every dashboard API moved below a random, once-generated 16-hex-character path (`/<admin-path>/dash/…`, `/<admin-path>/api/…`). Old root routes answer the same plain 404 a random path gets — no redirect ever reveals the namespace. Regeneration is an authenticated, explicitly confirmed operation that invalidates every session and bookmark immediately. The frontend reads the prefix from the address bar, so the same bundle works on every install.
- **Subscription Surface as a Setting (Phase 4):** A dedicated subscription record (enabled, domain, port, title, certificate paths, panel-certificate mode) seeds itself once from the panel origin and never rewrites operator edits. Subscriber links are built from one effective-URL layer instead of scattered string concatenation; a different subscription domain requires a certificate naming it **before** the settings save, not after a restart.
- **Two-Factor & LDAP (Phase 6):** RFC 6238 TOTP with a proper enrollment flow (secret shown exactly once, confirmation requires the code), and directory login through go-ldap with bounded timeouts and verified TLS. LDAP modes: local, ldap, or ldap-with-local-fallback. When 2FA is on, password changes and API-key rotation demand a current code — a stolen session plus a stolen password is no longer enough.

### 🛡 Security
- Login answers "Invalid credentials" identically for local, LDAP, and second-factor failures — no oracle for which path exists.
- The auth record (TOTP secret, LDAP bind password) is sealed at rest by the settings envelope, and structurally cannot serialise into a response: the snapshot type has no field for either.
- Request paths are cleaned mux-style before the admin-prefix check, so traversal cannot escape the hidden namespace.
- Portal pages accept operator CSS only after `<style>`/`<script>` escaping, `@import` stripping, and external `url()` removal — subscriber pages cannot become data-exfiltration surfaces.

### ✨ Added
- `internal/web/landing.go`, `internal/web/security.go` (validators: admin path, domains, ports, CIDRs, time zones, certificates, CSS), `internal/web/subscription.go` (effective-URL layer), `internal/auth` (TOTP + LDAP), `internal/database/subscription_access.go` and `auth_access.go`.
- `POST /api/settings/regenerate-admin-path` (requires `{"confirm":true}`), `GET/POST /api/settings/subscription`, `GET /api/auth/2fa/status`, `POST /api/auth/2fa/{setup,enable,disable}`, `GET/POST /api/auth/ldap`.
- Settings-tab panels: Hidden Admin Path, Subscription Portal, Two-Factor Authentication, LDAP — all English/Persian.

---

## INTERNAL — Fix Bugs

### [v1.3.0-beta - v2.0.0-beta]
- INTERNAL - Fix Bugs
- INTERNAL - Fix Security Bugs

---

## 🚀 [v1.2.0-beta] - 2026-08-31

### 🌟 Highlights
- **171+ Game & Platform Support Catalog:** Integrated an extensive catalog of gaming presets covering Tactical Shooters, MMORPGs, Anime/Gacha, Sports/Racing, Co-Op/Survival, Anti-Cheats, Launchers, and Cloud Gaming platforms.
- **Developer REST API v1:** Comprehensive headless management API with dual authentication (`X-API-Key` & JWT) and interactive Swagger documentation at `/api/v1/docs`.
- **Strict 1-IP Accounting & Expiration Watcher:** Multi-client subscription management with strict single-IP enforcement per account and instant 1-minute expiration deactivation.
- **Auto-Detection & Zero-Loss Safe Installer:** Installer automatically detects previous installations (e.g. `v1.1.0-beta`), creates timestamped backups, and performs non-destructive configuration schema migration.

### 🎮 Added
- **Game Presets & Routing Rules (171+ Titles):**
  - **Tactical Shooters Extra (`enable_shooters_extra`):** Delta Force: Hawk Ops, Escape from Tarkov, HellDivers 2, Rust, Squad, DayZ, ArmA Reforger & 3, Dead by Daylight, Hunt: Showdown, Insurgency: Sandstorm, SCUM.
  - **Anime, Gacha & Modern MMOs (`enable_anime_gacha`):** Genshin Impact, Honkai: Star Rail, Zenless Zone Zero, Wuthering Waves, Throne & Liberty, Path of Exile 1 & 2, Lost Ark, Arknights: Endfield, Warframe, Elden Ring, Black Desert Online, Final Fantasy XIV.
  - **Sports, Fighting & Racing (`enable_sports_racing`):** EA Sports FC 25 / FIFA, eFootball / PES, Street Fighter 6, Mortal Kombat 1, Tekken 8, 2XKO, Assetto Corsa & Competizione, Euro Truck Simulator 2, Forza Horizon 5, F1 24.
  - **Co-Op, Survival & Strategy (`enable_coop_survival`):** Palworld, Enshrouded, Satisfactory, Deep Rock Galactic, Civilization VI/VII, Paradox Interactive (Hearts of Iron IV, Stellaris, Crusader Kings III).
  - **Extra Platforms, Anti-Cheats & Cloud Gaming (`enable_platforms_extra`):** Faceit AC, Riot Vanguard, EasyAntiCheat (EAC), BattlEye, Ricochet, Denuvo, GeForce NOW, Boosteroid, Xbox Cloud Gaming, Razer Synapse, Logitech G Hub, Corsair iCUE.
  - **SoundCloud Preset (`enable_soundcloud`):** Full unblocking of SoundCloud web, desktop player, mobile apps, and audio streaming CDNs.
- **Developer REST API v1 (`/api/v1`):**
  - `GET /api/v1/status`: Live server status, CPU %, RAM MB, QPS telemetry, upstream health, and client stats.
  - `POST /api/v1/clients`: Create new subscriber accounts with custom validity periods and automatic 1-click IP token generation.
  - `GET /api/v1/clients`: List clients with status filtering (`?status=active|expired`) and real-time search (`?search=`).
  - `GET /api/v1/clients/{id}`: Detailed client inspection including allowed IPs, expiration date, query counts, and last seen timestamps.
  - `POST /api/v1/clients/{id}/renew`: Extend subscription duration by N days and instantly reactivate expired accounts.
  - `POST /api/v1/clients/{id}/ip`: Update/bind client IP with strict single-IP limit enforcement.
  - `DELETE /api/v1/clients/{id}`: Terminate client access and instantly revoke DNS resolution.
  - `GET / POST /api/v1/rules`: Inspect and hot-toggle any game or security preset rule without restarting the daemon.
  - `GET /api/v1/diagnostics`: Run on-demand network latency benchmarks against gaming server regions.
  - `GET /api/v1/docs`: Embedded interactive OpenAPI / Swagger API reference.
- **Installer Auto-Detection & Migration:**
  - Auto-detection of existing installations in `scripts/install.sh` and `install-offline.sh`.
  - Automatic timestamped backup creation (`/opt/hyperdns/backups/backup_YYYYMMDD_HHMMSS/`).
  - Safe JSON schema migration that preserves 100% of existing accounts, admin credentials, custom rules, and SSL certificates while injecting newly introduced keys.
  - CLI version flags: `hyperdns -version`, `hdns -version`, `hdns -v`.
- **Documentation:**
  - Added **`docs/PRESET_CATALOG.md`**: Complete categorized directory of all 171+ supported games, publishers, and platforms.
  - Added **`API.md`**: In-depth REST API guide with Python (Telegram Bot integration), Node.js (Provisioner webhook), and cURL integration samples.

### 🔄 Changed
- **Client Accounting Logic:**
  - Upgraded client IP limit from multi-IP array to a strict 1-IP policy per token to prevent account sharing.
  - Added background ticker running every 60 seconds to automatically disable expired client accounts in real time.
- **Web UI:**
  - Reorganized Gaming Policies section on Web Dashboard to include the 5 new preset categories.
  - Updated all dashboard version badges to `beta 1.2.0`.

### 🐛 Fixed
- **UI Render Crash:** Fixed a missing closing brace `}` in `web/js/app.js` within `renderConfig()` when TLS was not yet configured.
- **Expired Account Filtering:** Fixed edge case where pre-expired accounts (`expires_days: -1`) were not correctly flagged during client creation.

---

## 📦 [v1.1.0-beta] - 2026-08-30

### 🎮 Added
- **Multi-Client Access Control:**
  - Token-based client management allowing individual subscription tokens.
  - 1-Click IP auto-registration URLs (`/r/:token`) for end-users to register their dynamic IP without accessing the admin panel.
  - Granular bandwidth and total query counters per subscriber.
- **Interactive TUI Utility (`hdns`):**
  - Global `hdns` terminal management console.
  - Direct subcommands: `hdns status`, `hdns restart`, `hdns logs`, `hdns flush`, `hdns diag`, `hdns clients`, `hdns uninstall`.
- **Live Query Telemetry:**
  - Real-time Server-Sent Events (SSE) live query log stream in the Web Dashboard.
  - Live upload (`↑ KB/s`) and download (`↓ KB/s`) bandwidth meters.
- **100% Offline Installation Package:**
  - Standalone offline bundle with zero internet access requirement (`hyperdns-offline-bundle.tar.gz`).
- **Automated SSL Management:**
  - Let's Encrypt SSL auto-issuance integration via Certbot and ACME scripts.

### 🔄 Changed
- Refactored in-memory routing table for higher concurrency and zero mutex contention.
- Hardened default OWASP security headers for Web UI and REST endpoints.

---

## 🏁 [v1.0.0-beta] - 2026-08-28

### 🌟 Initial Beta Release
- **Core Engine:**
  - High-performance DNS server written in Go supporting UDP/TCP Port 53, DNS-over-TLS (DoT Port 853), and DNS-over-HTTPS (DoH Port 8443).
  - Sharded in-memory LRU cache with sub-millisecond query response times.
  - Fastest Upstream Racing pool querying Cloudflare (`1.1.1.1`), Google (`8.8.8.8`), and Quad9 (`9.9.9.9`) in parallel.
- **Transparent SNI Proxy:**
  - Non-decrypting zero-knowledge TCP proxy on ports 80 (HTTP) and 443 (HTTPS).
  - Anti-DPI TLS ClientHello fragmentation to bypass restrictive deep packet inspection firewalls.
- **Smart Game Presets:**
  - Core gaming presets: Riot Games (Valorant/LoL), Epic Games (Fortnite), Steam/CS2, PUBG, Call of Duty, Supercell, EA, Blizzard, Ubisoft, Rockstar, Xbox Live, PlayStation Network, Roblox.
  - Streaming presets: Discord (Voice RTC + Chat), Spotify, Twitch, Kick.com.
  - Developer 403 bypass: Docker Hub, OpenAI, Anthropic Claude, npm, Gradle, Android SDK, HuggingFace.
  - AdBlock & Family Safe content sinkholes.
- **Cyberpunk Web Dashboard:**
  - Dark neon cyberpunk theme with live QPS graphs, CPU/RAM usage meters, and preset toggles.
