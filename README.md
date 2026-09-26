# ⚡ HyperDNS — HyperRAIN Standalone SmartDNS & Gaming Gateway

<p align="center">
  <img src="https://img.shields.io/badge/Release-v2.6.0-00f0ff?style=for-the-badge&logo=rocket" alt="Version">
  <img src="https://img.shields.io/badge/Status-Production--Ready%20Beta-amber?style=for-the-badge" alt="Status">
  <img src="https://img.shields.io/badge/Language-Go%201.26-00ADD8?style=for-the-badge&logo=go" alt="Go">
  <img src="https://img.shields.io/badge/Architecture-Single%20Binary%20(Zero%20CGO)-a855f7?style=for-the-badge" alt="Single Binary">
  <img src="https://img.shields.io/badge/Protocols-UDP%20%7C%20DoH%20%7C%20DoT-10b981?style=for-the-badge" alt="Protocols">
  <img src="https://img.shields.io/badge/Gaming-Zero%20Loss%20%26%20Low%20Ping-ff4655?style=for-the-badge" alt="Gaming">
  <img src="https://img.shields.io/badge/License-AGPL--3.0-blue?style=for-the-badge&logo=gnu" alt="License">
</p>

<p align="center">
  <img src="docs/hyperdns-dashboard.png" alt="HyperDNS dashboard — live telemetry, QPS graph and policy presets" width="880">
</p>

> [!NOTE]
> ### v2.2.0 — Built-In ACME, Whitelist by Default, API v2 & a Real Console
> Certificates are now **issued by the daemon itself**: an in-process ACME client (RFC 8555) replaces certbot/acme.sh entirely — issuance and daily renewal happen while the service runs, and renewed certificates hot-swap into the live listeners without a restart. **Client access whitelist is on by default**: an unknown source is refused by DNS (with an RFC 8914 Extended DNS Error so the client learns *why*) instead of being served for free. A new versioned **REST API v2** joins v1 (which carries `Deprecation`/`Sunset` headers), and the console can stop, start and uninstall the service. See [CHANGELOG.md](docs/CHANGELOG.md) for the full list.

<p align="center">
  <a href="#-quick-installation--deployment">🚀 Install</a> •
  <a href="#-first-run-hardening">🔒 Harden</a> •
  <a href="#-key-features">🌟 Features</a> •
  <a href="docs/PRESET_CATALOG.md">🎮 Games (171+)</a> •
  <a href="#-web-administration-dashboard">🖥️ Dashboard</a> •
  <a href="docs/API.md">🔌 REST API</a> •
  <a href="#-technical-architecture--codebase-design">🏛️ Internals</a> •
  <a href="docs/SECURITY.md">🛡️ Security</a> •
  <a href="#-support--donate">☕ Support</a> •
  <a href="README.fa.md"> راهنمای فارسی</a>
</p>

---

## 📚 Documentation

| Document | Covers |
| :--- | :--- |
| **[docs/TUTORIAL.md](docs/TUTORIAL.md)** | Step-by-step walkthrough: first boot, custom domain for the subscriber portal, adding clients, issuing registration tokens. **Start here.** |
| **[SECURITY.md](docs/SECURITY.md)** | Threat model, encryption specifics, hardening checklist, RFC compliance, vulnerability reporting. **Read before exposing the install.** |
| **[API.md](docs/API.md)** | REST API v1 (deprecated) and v2, with Python / Node.js / cURL samples. |
| **[docs/PRESET_CATALOG.md](docs/PRESET_CATALOG.md)** | The full 171+ preset catalog, by category. |
| **[CHANGELOG.md](docs/CHANGELOG.md)** | Release history and the fix behind each one. |
| **[README.fa.md](README.fa.md)** | راهنمای فارسی. |

## 📖 Overview

**HyperDNS** is an ultra-fast, single-binary SmartDNS server and transparent SNI Proxy engine with an embedded cyberpunk/gaming web dashboard, developer REST API, and interactive terminal interface (`hdns`).

It transforms any single cloud VPS (even a \$3/month 1-Core CPU / 1GB RAM instance) into a private **Anti-Sanction (403 Bypass)** and **Low-Latency Gaming Gateway** for **PC, PlayStation 4/5, Xbox Series X/S, Nintendo Switch, Android, iOS, and Routers** with:
- **0 Client Software Required:** Users only set their DNS IP address on their console or router.
- **0 VPN Overhead:** Game UDP traffic (voice, physics, tick rate) connects directly to official servers without double encryption or MTU packet fragmentation.
- **1-Click Self-Healing Registration:** Dynamic mobile & residential IPs update automatically via private one-click slugs (`/ip/{token}`).

---

## 🖥️ Server Requirements

HyperDNS is a single static Go binary. There is no database server, no runtime,
no container image underneath it — the sizing question is only how many
subscribers you serve and whether they relay downloads through you.

| Install class | vCPU | RAM | realistic for |
| :--- | :--- | :--- | :--- |
| **Floor** — runs, personal use | 1 | 1 GB | 1–3 devices, policies on, downloads direct. This is the smallest VPS the daemon starts on. |
| **Recommended** — small reseller | 2 | 2 GB | up to ~10 subscribers on gameplay-only plans, DoT + DoH + portal all enabled |
| **Comfortable** — many clients | 4 | 4 GB | 20+ subscribers, `enable_downloads` on, benchmark runs while serving |

Honest history behind these numbers: on **v1.2.0**, a 1-core / 1-GB box was
pegged at **100% CPU with just 3 clients** — that build also had a serious
memory leak that made the lag worse the longer it ran. v2.2.0 is a different
engine: the lookup and rule-match paths are allocation-free nanosecond reads
(measured, not estimated — see [Architecture](#%EF%B8%8F-technical-architecture--codebase-design)),
the cache is sharded and capped, a relayed connection no longer allocates its
own buffer, and the leak classes of that era are gone. A 1-core / 1-GB box is
now a *usable* personal install — but if you sell access, buy the 2-vCPU tier:
rate limiting, EDE generation and relay fan-out all cost CPU on the query path,
and the box that hosts your resolver should not be the bottleneck your ping
blames.

Also required: a **domain** pointed at the server (HTTPS is mandatory; the
daemon issues its own certificate), and these ports reachable:

| Port | Protocol | Purpose |
|------|----------|---------|
| **53** | UDP + TCP | DNS resolver — the core service |
| **443** | TCP | SNI relay for proxied game traffic + panel HTTPS |
| **80** | TCP | ACME HTTP-01 certificate issuance + SNI relay HTTP |
| **8443** | TCP | DoH (DNS-over-HTTPS) |
| **853** | TCP | DoT (DNS-over-TLS) |
| panel port | TCP | admin dashboard — a random high port, shown by the installer |

If another service already owns **53** (a local `masterdns`/dnsmasq is the
usual one), **443**, or **8443**, free it first or the daemon cannot bind that
listener at start. The installer now lists these ports and warns about conflicts
before it installs anything.

---

## 🚀 Quick Installation & Deployment

### Option 1: One-Line Linux Installer (Recommended)
Run as `root` on Ubuntu 20.04+, Debian 11+, or AlmaLinux/Rocky 8+:
```bash
curl -fsSL https://raw.githubusercontent.com/IzumiRain/HyperDNS/v2.6.0-beta.1/scripts/install.sh | sudo bash
```

> [!IMPORTANT]
> **The installer never upgrades in place.** An existing install is archived to `/root/hyperdns-preinstall-<date>.tar.gz` (its sha256 printed — the only copy of the old data), then **replaced**: fresh config, fresh credentials, fresh certificates. An interactive run types `FRESH` to confirm the wipe; a piped `curl | bash` run refuses unless `HYPERDNS_FRESH=1` is set. Coming from **HyperDNS 1.x**, run `bash migrate-from-v1.sh` from the offline bundle first.
>
> **A panel domain is mandatory** — its A record must point at the server. The daemon issues the Let's Encrypt certificate **itself** over its own port-80 listener: no certbot, no acme.sh, nothing to stop the service for. Non-interactive: `HYPERDNS_DOMAIN=dns.example.com HYPERDNS_EMAIL=you@example.com bash install.sh`. If issuance fails the installer states the cause and exits rather than printing success. Renewal is daily and automatic.
>
> **Subscribers self-serve IP changes** through a secret: `/sub/<token>` is a read-only portal, and moving the binding is `POST /ip/<token>` with the account's registration secret. A leaked portal link alone cannot steal the binding.

### Option 2: Pre-Compiled Standalone Binary
```bash
# On Linux:
chmod +x ./bin/hyperdns_linux_amd64
sudo ./bin/hyperdns_linux_amd64 -server -web-port 8080

# On Windows (PowerShell or cmd, from the folder you extracted):
.\bin\hyperdns.exe -server -web-port 8080
```

### Option 3: Compile from Source
```bash
git clone https://github.com/IzumiRain/HyperDNS.git
cd "HyperDNS"
go build -ldflags="-s -w" -o bin/hyperdns ./cmd/hyperdns
./bin/hyperdns -server
```

### Option 4: Docker / Docker Compose
```bash
git clone https://github.com/IzumiRain/HyperDNS.git
cd "HyperDNS"
mkdir -p data certs
docker compose up -d
```

Create `data/` and `certs/` before the first `up`. Everything that has to survive a rebuild lives in `data/` — `data.db`, `master.key` and `config.json` — and the container names all three paths explicitly, so an image update never comes back to an empty database. `config.json` is optional: drop one in to seed the first run, or leave the directory empty and let the daemon generate its own.

The container runs with `network_mode: host` on purpose. A NAT hop on every UDP datagram is latency added to the query that starts a game, and the daemon has to see the real client address — subscriber recognition, the per-source rate limit and the access list all key on it. Behind Docker's userland proxy every query would arrive from the bridge address, so one client's flood would rate-limit the whole subnet and every subscriber would look like the same subscriber.

---

## 🌟 Key Features

### 🎮 1. Categorized Smart Policies (171+ Games & Services)
- **Gaming & Tactical Shooters:** Valorant, CS2, Call of Duty (Warzone / Mobile / BO6), The Finals, Escape from Tarkov, Delta Force: Hawk Ops, HellDivers 2, PUBG, Apex Legends, Rainbow Six Siege, Rust, Squad, DayZ, ArmA, Dead by Daylight.
- **Anime, Gacha & MMORPGs:** Genshin Impact, Honkai: Star Rail, Zenless Zone Zero, Wuthering Waves, Arknights: Endfield, Lost Ark, Throne & Liberty, Path of Exile 1 & 2, Warframe, Elden Ring, Black Desert, Final Fantasy XIV.
- **Sports, Fighting & Racing:** EA Sports FC 25, eFootball, Street Fighter 6, Mortal Kombat 1, Tekken 8, 2XKO, Assetto Corsa, Euro Truck Simulator 2, Forza Horizon 5, F1 24.
- **Platforms, Anti-Cheats & Cloud Gaming:** Faceit AC, Riot Vanguard, EasyAntiCheat (EAC), BattlEye, Ricochet, GeForce NOW, Boosteroid, Xbox Cloud Gaming, Razer Synapse, Logitech G Hub, Corsair iCUE.
- **Social & Media:** Discord Voice & Gateway (Anti-Filter Encrypted TCP Relay), Spotify, Twitch, Kick.
- **Google Services:** Search, Gmail, Drive, YouTube — with the shared CDN zones deliberately excluded and the update CDNs forced direct (v2.2.0).
- **AI Assistants & Platforms:** Copilot, Perplexity, Grok, DeepSeek, Mistral, OpenRouter, and more (v2.2.0).
- **Social & Messaging:** X, Instagram, Facebook, WhatsApp, Telegram, Reddit (v2.2.0).
- **Developer 403 Bypass:** Docker Hub, Gradle, Android Developers, NPM, PyPI, OpenAI, Anthropic, Claude, Hugging Face, Cursor, Copilot, Kaggle.

### 🛡️ 2. Transparent SNI Proxy Relay
- Layer-4 TCP relaying without SSL termination: the TLS session stays end-to-end between the client and the origin, and HyperDNS never holds the keys for it.
- Anti-DPI TLS ClientHello fragmentation, on by default (`enable_fragmentation`, with a configurable chunk size and inter-chunk delay).
- A `sync.Pool` of 32 KB buffers, so a relayed connection does not allocate its own — the payload is still copied through user space, and each direction carries an inactivity deadline that is refreshed per chunk so half-open connections are reaped instead of pinned.
- Up to 4096 concurrent relays; beyond that new connections are rejected rather than queued, which keeps a flood from exhausting memory.

### 👤 3. Subscriber Management & 1-Click IP Sync
- **Two addresses, two jobs.** `/sub/{token}` is the subscriber's **portal** — a
  read-only overview of their plan, quota and detected address, safe to hand out
  because a leaked link cannot move their binding. `/ip/{token}` is the
  **registration API**: `POST` with the account's 96-bit registration secret
  rebinds the address (send no `ip` field to bind the caller's own — the 1-click
  flow); a bare `GET` serves a bilingual explainer page for old bookmarks.
- **The registration secret travels out-of-band.** It is shown in the operator's
  client panel (and stored AES-256-GCM sealed beside the token), regenerable
  there. This is what makes a leaked portal link read-only material rather than
  a way to steal the subscription.
- **Registration gates:** suspended, expired and over-quota accounts are refused
  with a reason the portal can translate; an address already bound to a
  *different* subscription answers `409` **without disabling either account**,
  because shared CGNAT addresses are ordinary on mobile networks.
- **An optional dedicated portal port.** Set one in Settings → *Subscription
  Portal* and the daemon binds a second listener for the public subscriber
  routes only — the admin namespace, REST API, DoH and the SPA answer a bare 404
  there. Open the port in the host firewall too (`ufw allow <port>/tcp`); the
  panel can bind it but cannot open a firewall for you. Reachability from
  outside is the one thing the card cannot verify, and it says so.
- **RFC 9562 v4 UUIDs:** stable unique identifiers for all clients (the standard that supersedes RFC 4122).
- **Plan Durations & Traffic Limits:** daily/monthly/yearly/lifetime expiry with
  live quota enforcement.
- **Persian Telegram cards:** a 1-click formatted provisioning card carrying the
  portal link, the registration secret, the DNS address and the API URL.
- **Whitelist by default (v2.2.0).** An unknown source is **refused** by DNS —
  with an RFC 8914 *Prohibited* Extended DNS Error for OPT-bearing queries, so
  the client learns *why* — instead of being served for free. Fresh installs
  ship whitelist-on; an existing install converges through a one-time
  idempotent migration on first boot. If you sell access, keep
  `access.allow_all: false` — under `allow_all` revocation does not work, because
  an unindexed address is still served as anonymous `Public`, which has no plan
  to expire and no allowance to exceed. See [First-Run Hardening](#-first-run-hardening).

### 🔐 4. Encrypted DNS That Reuses Its Connections
- **Plain UDP/TCP on 53, DNS-over-TLS on 853, DNS-over-HTTPS on its own port
  (8443 default, configurable)** — one daemon, one process. The DoH listener
  answers `/dns-query` and the public portal routes only; the admin namespace
  never reaches it (v2.2.0).
- **An idle DoT connection is held for 60 seconds** (30 s on plain TCP), and there is no per-connection query limit. What a DoT client pays for a new connection is a full TLS handshake, so a phone on Android Private DNS that looks something up every few seconds used to re-handshake for nearly every name — tens of milliseconds, on mobile data, on the query that starts a game.
- **The reply tells the client how long it may hold the connection** (`edns-tcp-keepalive`, RFC 7828), so it does not have to guess. Guessing long means writing a query into a socket the server already closed; guessing short means throwing away a handshake that would have been reused.
- **Concurrent connections are capped** (512 TCP / 1024 DoT / 512 HTTPS) with header and idle timeouts on the HTTPS listener, so connection reuse cannot be turned into a way to hold the daemon's resources open.

### 📜 5. Certificates Issued by the Daemon (v2.2.0)
- **An embedded ACME client (RFC 8555) replaces certbot and acme.sh entirely.**
  Issuance and daily renewal happen **while the service runs** — the HTTP-01
  challenge is served out of the port-80 listener that is already running, so
  there is nothing to install and nothing to stop the service for. Renewed
  certificates hot-swap into the live listeners without a restart.
- **Three certificate surfaces, three names:** the panel, the subscription
  portal, and the DoT/DoH transports each carry a certificate validated against
  its own domain before anything persists — one wrong name is refused, not
  served.
- **The DoH/DoT transports can carry a dedicated certificate** (the custom
  DoH/DoT domain, e.g. for Android Private DNS), hot-swapped on issue, while
  everything else rides the panel certificate.

### 📥 6. Bulk Downloads Stay Off the Proxy by Default

A game preset unblocks a whole publisher: the store, sign-in, matchmaking, patch metadata — and the depot hosts that carry the actual multi-gigabyte payload. Those last ones are the only part of a gaming DNS that is measured in gigabytes rather than kilobytes, and relaying them is almost never what you want. So HyperDNS separates them into their own category, **Game & App Downloads** (`enable_downloads`), and ships it **off**.

With it off, `steamcontent.com`, `download.epicgames.com`, `dl.playstation.net`, `cdn.blizzard.com`, `dlassets.xboxlive.com`, `cdn.gog.com` and the rest resolve to their **real** addresses. Steam still opens, the library still loads its art, the game still connects — the download itself just runs on the subscriber's own connection. The query log labels those answers `DIRECT · Game & App Downloads`, so you can see it happening rather than guess.

Turn it on from **Policy Presets → Bandwidth & Traffic Policy** in the dashboard, or `POST /api/v1/policies {"key":"enable_downloads","enabled":true}`.

#### ⚠️ Before you turn it on

The short version: **egress is billed by the gigabyte, quotas cannot tell a download from a match, and a relayed download is usually slower than a direct one.** Ten subscribers installing a 100 GB game is 2 TB of paid traffic from one toggle, and a subscriber on a metered plan can exhaust it in an evening and then be unable to play at all. Turn it on only for the one case it exists for — a subscriber whose line **cannot reach the CDN at all** (a hard block, not a throttle): the symptom is a download stuck at 0 B/s with no error while the store page loads fine.

Two mechanics worth knowing: the SNI proxy caps at 4096 concurrent relays, and a download client opens dozens of parallel connections per install — that budget goes much faster than gameplay does, and what gets rejected is whatever connects next, including somebody's match. After toggling, flush the cache (`POST /api/v1/cache/flush`) or cached answers keep their old routing.

#### Scope: global switch and per-client plan

The category behaves like any other policy in a subscriber's plan, with the global switch as the ceiling:

| Global `enable_downloads` | Client's plan lists it | Result |
|---|---|---|
| off | — | Direct. The operator pays the bill, so the operator's off wins even if a plan sold it. |
| on | not listed | Direct for that account, proxied for accounts that do list it. |
| on | listed | Proxied. |
| on | plan is empty (all-inclusive) | Proxied. |

Two more things worth knowing:

- **It cannot proxy a game you have switched off.** The category only ever *subtracts* from what the game presets already route. With `enable_steam` off, a Steam depot is direct either way.
- **To excuse one host without opening the category**, add it to **Custom Proxied**. That outranks the veto for that name and its subdomains, which is the cheap way to rescue one subscriber stuck on one blocked CDN. **Custom Blocked** still outranks both.

---

## 🔒 First-Run Hardening

Four settings decide whether this install is a private resolver or an open one. The defaults target a personal box on a home network — and since v2.2.0, the resolver ships **closed** (whitelist by default): the rows below say which ones still need changing before you let anyone else near it.

| Setting | Ships as | Change it to | Why |
| :--- | :--- | :--- | :--- |
| `access.allow_all` | `false` since v2.2.0 (whitelist by default) | keep it `false` to sell or share; `true` is for a personal all-devices install | While it is `true` the daemon answers every address, so disabling or expiring an account only stops it being *recognised* — the address is then served as anonymous `Public`, which has no plan to expire and no quota to exceed. Traffic limits still bite on accounts it knows, but **revocation does not work at all** until this is off. Fresh installs ship whitelist-on; an existing install converges through a one-time migration on first boot. |
| `security.api_bind` | `127.0.0.1` | leave it, unless a bot runs off-box | `127.0.0.1` means the REST API answers only the server itself and a remote call gets `403` however valid its key is. `0.0.0.0` puts an admin surface on the internet with the API key as the only thing in front of it. Prefer an SSH tunnel to flipping this. |
| Admin password | randomly generated, printed **once** in the install output | your own, ≥10 characters | It is stored as a PBKDF2-HMAC-SHA256 verifier (600,000 iterations) and never in the clear, so it cannot be read back out of `data.db` even with `master.key` in hand — which also means a lost password is a reset, not a recovery. Changing it invalidates every existing dashboard session. |
| `master.key` | generated on first start | back it up, off the server | It decrypts every subscriber record. Losing it makes them unreadable; leaking it makes them readable. It must never enter a git repository — `.gitignore` already covers it. |

An install carrying a password from before the strength policy keeps working — verification never applies the policy, so nobody is locked out of their own server by an upgrade — but it is flagged, and the dashboard asks for a replacement. New passwords must be at least 10 characters and combine two character classes, or be at least 16 characters, or use a non-ASCII script; a Persian passphrase satisfies the rule on its own.

Two things this build does *not* do, so you do not have to configure them: query logs are never written to disk in any form (DNS telemetry lives in memory and on the SSE stream), and the SNI relay never terminates TLS, so it never holds a key for the sessions it carries.

### 🕶 The Hidden Panel (v2.1)

The dashboard no longer lives at the root of the host. On first start the daemon generates a random **16-hex-character admin path** and mounts everything administrative below it — `/<admin-path>/dash/…` for the pages, `/<admin-path>/api/…` for the APIs — and prints the login address **once** to the log. The root domain serves an empty Matrix-style landing page; old panel routes answer the same 404 a random path gets, with no redirect to hint at the namespace. The path is a locator, not a credential, but treat it as one: regenerate it from Settings → *Hidden Admin Path* (every session and bookmark dies with it) if it has leaked anywhere, and never paste it into public docs.

Optional hardening on top, all in Settings:

- **Two-Factor Authentication** — RFC 6238 TOTP. Enroll from Settings → *Two-Factor Authentication*: the secret is shown exactly once, one code confirms it, and from then on logins (plus every password/API-key change) require a current code. Disabling demands both factors one last time.
- **LDAP** — authenticate operators against Active Directory/OpenLDAP (`ldaps://` verified against the system certificate store, bind/search/bind flow, 5-second timeout). Modes: local only, LDAP only, or LDAP with local fallback.
- **Session idle window** — revoke a dashboard session after N minutes without use (5–1440, default 15). Applies live on save; the 24-hour absolute ceiling is unchanged.
- **Login lockouts** — 3 failures from one address locks it for 10 minutes. Clear it without a restart from TUI entry `[12]` or `POST /api/auth/unlock` (session or API key, plus a TOTP code when 2FA is on).
- **Subscription Portal** — the subscriber pages (`/sub/<token>`, `/ip/<token>`, and the dedicated listener if you set a port) stay public by design; Settings controls the title, the domain and port their links advertise, and an optional custom stylesheet that is sanitised (no `@import`, no external `url()`, no script) before it reaches a subscriber's browser.

For the full threat model, the exact list of encrypted fields, and a
report-a-vulnerability process, see **[SECURITY.md](docs/SECURITY.md)**.

---

## 🖥️ Interactive TUI Controller (`hdns`)

Run HyperDNS in terminal mode to read live metrics, provision subscribers and run diagnostics over SSH without opening a browser:
```bash
./hyperdns
# or if installed system-wide:
hdns
```

It is a **numbered menu**, not a full-screen keyboard interface: it prints the banner with this instance's public IP, dashboard URL and API bind, then waits for a number and <kbd>Enter</kbd>. Everything is redrawn each time round, so a value the dashboard changed while you were reading is correct on the next pass.

| Option | Action | | Option | Action |
| :---: | :--- | :---: | :---: | :--- |
| `1` | Service status & telemetry | | `9` | Benchmark DNS upstreams |
| `2` | Diagnostics | | `10` | Flush the DNS cache |
| `3` | Restart the service | | `11` | Change the dashboard panel port |
| `4` | Stop the service | | `12` | View / rotate the API key |
| `5` | Start the service (after a stop) | | `13` | Clear login lockouts |
| `6` | List subscriber accounts | | `14` | Change admin credentials |
| `7` | Add a subscriber | | `15` | Emergency admin reset |
| `8` | Delete a subscriber | | `16` | Uninstall HyperDNS |
| `0`, `q` or `exit` | Quit (daemon keeps running) | | <kbd>Ctrl</kbd>+<kbd>C</kbd> | Quit at any prompt |

Options `3`–`5` and `16` reach **runtime ownership**: the console is a client
process that runs with the daemon down, so it is exactly where an operator
lands when the service is stopped and needs the way back up. Uninstall demands
a typed `UNINSTALL` confirmation. Option `13` calls the daemon's authenticated
unlock endpoint over loopback, so an operator who has locked themselves out
clears it without a restart. Option `12` prints the master API key in the
clear — treat that screen the way you would treat the key itself; rotation
stops the previous key the moment it lands, with no grace period.

Gaming presets are **not** toggled from here — that is the dashboard or the
REST API.

---

## 🌐 Web Administration Dashboard

The dashboard is not at the host root. On first start the daemon prints its one
**hidden login address** to the log — `https://<domain>/<admin-path>/login` — and
that is the only URL that reaches it. Bookmark it then; the path is a random
16-hex string, and the address is printed exactly once. To recover it later: the
TUI banner shows the dashboard URL, `hdns status` reports listener and
certificate state without opening the database, and the log line is printed again
on every start.

- **Login is a standalone page** (`/<admin-path>/login`): it loads no dashboard
  assets, so the panel bundle is not readable before authentication. The
  two-factor field appears only when the password verified and the code is what
  failed — a plain wrong password never shows it.
- **Credentials:** Username `admin`. The installer generates a random password
  and prints it **once** in the install output; if you start the binary directly
  without a config it generates one and prints it in the startup log. There is no
  shared default password.
- **Clients & Whitelist:** Add/edit clients, assign the single allowed IP,
  configure traffic limits, view and regenerate the **registration secret**, and
  copy the Persian Telegram card.
- **Gaming Policies:** 1-click toggles for every preset category, plus custom
  proxied/blocked domains, DoH tokens and static records.
- **Live Stream:** Real-time Server-Sent Events (SSE) stream of DNS queries.
- **Settings & SSL:** the subscription portal (title, domain, port),
  two-factor authentication, LDAP, session idle window, hidden admin path,
  certificate issuance, and the REST API gateway (master key, exposure toggle,
  integration snippets).

---

## 🔌 Developer REST API

HyperDNS exposes a developer-first REST API for bots and billing systems, in
two versions:

- **v2** (the successor contract, `/api/v2/…`): symmetric field names
  (`display_name`, `allowed_ips` — create and update finally agree),
  cursor-paginated lists (`{items, next_cursor}`, bounded limit), RFC 9457
  `application/problem+json` errors, `POST /clients/{id}/actions/{action}` for
  mutations, and **strict decoding** — an unknown field is a 400, not a
  silently dropped typo.
- **v1** (working, deprecated): every v1 route carries `Deprecation` and
  `Sunset` headers with a `Link: successor-version` pointing at v2. The master
  REST key (or a live dashboard session) authorizes both surfaces; it is
  **refused on every dashboard admin route** (v2.2.0 scoping) except the
  lockout-recovery unlock.
- **Interactive Swagger Docs:** `/<admin-path>/api/v1/docs` — press
  **Authorize**, paste the Master API Key from Settings, and every endpoint
  becomes runnable from the browser. No key is needed to open the page itself.
- **The viewer ships inside the binary.** `web/swagger/` (Apache-2.0) is
  embedded and served same-origin, so the docs page works on a network that
  cannot reach a public CDN. "100% offline" is literally true for every asset.
- **Comprehensive API Specification:** See [API.md](docs/API.md).

---

## 🏛️ Technical Architecture & Codebase Design

A query walks four layers, in this order:

1. **Access control** — `IsIPAllowed(clientIP)` is a single map read behind a `sync.RWMutex`. Four indexes (`idMap`, `ipMap`, `tokenMap`, `uuidMap`) are rebuilt from BoltDB on change and re-filed one account at a time on a subscriber IP registration, so the public `/ip/{token}` endpoint never triggers a full rescan. Under `access.allow_all: true` an address that matches no index is served as anonymous `Public` rather than refused — see the warning in [First-Run Hardening](#-first-run-hardening).
2. **Cache** — a 64-shard LRU keyed by name+type+class. A hit returns a *copy* of the stored message, because the caller has to rewrite the transaction ID and count the TTLs down.
3. **Policy match** — an exact-match map plus a longest-suffix wildcard index over the 171+ presets and any per-subscriber or admin-wide custom rules. Longest suffix wins, so `cdn.example.com` can be routed differently from `*.example.com`.
4. **Action** — `proxy` spoofs the answer to this server so the SNI relay picks the connection up; `direct` races the configured upstreams and forwards the unaltered reply; `block` sinkholes it.

Measured on a **13th Gen Intel i5-13420H (12 threads), windows/amd64**, `go test -bench`, `-count 3`:

| Operation | Serial | 12 threads | Allocations |
| --- | --- | --- | --- |
| Subscriber lookup (`IsIPAllowed`, hit) | 16.8–17.6 ns | 30.1–32.1 ns | 0 |
| Subscriber lookup by UUID | 15.6–15.8 ns | — | 0 |
| Rule match, exact hit | 52.3–52.6 ns | 72.1–72.3 ns | 0 |
| Rule match, wildcard hit | 95.7–115.1 ns | — | 0 |
| Rule match, 600 extra admin rules | 132.8–142.8 ns | — | 0 |
| Cache hit | 258–302 ns | 127–133 ns | 6 / 296 B |
| Cache miss | 69.6–77.4 ns | — | 1 / 48 B |

**What these numbers do and do not say.** They are in-process costs for one layer each, not end-to-end query latency — the wire, the kernel, and (on a cache miss) the upstream dominate anything measured here. The index is guarded by one reader-writer mutex, so it does not scale with cores: the parallel figure is *worse* per lookup than the serial one, which is the expected shape for shared-lock reads and is fine at DNS request rates. The cache does scale, because it is sharded. A cache hit is **not** allocation-free — the defensive copy is the 6 allocations. Serial nanosecond figures on this class of CPU move by tens of percent between runs, so treat the ranges as ranges; the durable claims are the shapes (allocation-free matching, cost independent of how many subscribers or rules exist), not the third significant digit.

**Storage.** One BoltDB file. Secret fields — subscriber name, bound IP list, subscription token, REST API key, TLS paths — are individually sealed with AES-256-GCM under the 32-byte key in `master.key`; tokens additionally carry a keyed blind index so `/ip/{token}` stays one lookup. The admin password is never stored, only a PBKDF2-HMAC-SHA256 verifier (600,000 iterations) — so it cannot be read back out of `data.db` *even with `master.key` in hand*; a lost password is a reset, not a recovery. Traffic counters are accumulated in memory and flushed in a single transaction every 30 seconds, because every BoltDB commit is an fsync.

Deliberately in the clear: **policy presets** and their domain lists (no credential, no subscriber name — the same data the binary and [docs/PRESET_CATALOG.md](docs/PRESET_CATALOG.md) publish), and the BoltDB structure itself. **Query logs are never written to disk** in any form — DNS telemetry lives in memory and on the SSE stream only.

Keep `master.key` backed up and off the server. Losing it makes every subscriber record unreadable; leaking it makes them readable — it must never enter a git repository, and `.gitignore` already covers it.

---

## 🏆 Quality Scorecard

Scores are self-assessed against Google's guidance and the Mantis audit trail,
with every claim tied to something verifiable — the benchmark table above, the
named regression tests in [SECURITY.md](docs/SECURITY.md), and the live
external-attacker campaign this build went through. Not a Lighthouse run; a
panel that requires authentication has no public page to light up.

| Dimension | Score | Basis |
| :--- | :---: | :--- |
| 🔐 **Security** | **93 / 100** | Three full Mantis audit rounds + a fix-verification pass — **50+ findings, every one fixed with a named regression test** (master-key scoping, TOTP single-use, LDAP scoping, DoH surface restriction, port-drift, safe installers). A T3MP3ST-style external-attacker campaign against a live deployment found every headline control holding and produced one LOW, fixed live. Race detector: 20/20 packages, zero races. Deductions: the open-resolver posture remains one toggle away (documented non-goal), no WAF or volumetric DDoS layer (the provider's job), the admin path is defence-in-depth only. |
| ⚡ **Performance** | **90 / 100** | The hot paths are allocation-free nanosecond operations (subscriber lookup ~17 ns, exact rule match ~52 ns, cache hit ~258 ns — benchmarked, see Architecture), the cache is 64-shard concurrent, DoT holds idle connections (RFC 7828) instead of re-handshaking, relays draw from a `sync.Pool`, and the whole thing is one zero-CGO binary. Deductions: the subscriber index sits behind one RWMutex and does not scale with cores (documented shape), no published end-to-end wire latency numbers, the v1.2.0-era field reports (CPU pegged, memory leak) are fixed but the memory of them is why this is not a 95. |
| 🔎 **SEO** | **70 / 100** | Deliberate and honest: the public landing page serves `noindex, nofollow` **by design** — a private resolver's landing page has no business ranking, and the subscriber portal carries per-request `Vary` headers so no cache serves one subscriber's page to another. What Google's guidelines ask for structurally is there: real `<title>`, single `<h1>`, viewport meta, semantic HTML, mobile-first rendering. Deductions: no sitemap, no Open Graph/structured data, no indexable content — because the product is not a content site. Raise the score by removing one meta tag if you want the landing indexed. |
| 🧹 **Code hygiene** | **95 / 100** | gofmt/go vet clean across 20 packages, JS/Python/shell syntax gates, a markup↔JS consistency test that catches dead DOM lookups, changelog discipline, and an offline-bundle mirror kept byte-identical. Deduction: the tree carries private planning notes in `.idea/` — keep them out of the published repository. |

---

## 📐 Standards & RFC Compliance

HyperDNS implements and honours the following IETF specifications — the full
table, with what each RFC means in this project, lives in
[SECURITY.md → Standards & RFC Compliance](docs/SECURITY.md#-standards--rfc-compliance):

DNS core [RFC 1035/2181] · DNS-over-TCP [RFC 7766] · DNS-over-TLS [RFC 7858] ·
DNS-over-HTTPS [RFC 8484] · Extended DNS Errors [RFC 8914, verified live] ·
`edns-tcp-keepalive` [RFC 7828] · ACME [RFC 8555] · TOTP [RFC 6238] ·
HTTP semantics & HTTPS [RFC 9110] · problem+json [RFC 9457] · API
Deprecation [RFC 9745] and Sunset [RFC 8594] · TLS SNI [RFC 6066] ·
UUID v4 [RFC 9562].

---

## ☕ Support / Donate

HyperDNS is built and maintained by one person, free and open source. If it
unblocked your games or your work, consider buying me a coffee.

| Method | Address / Link |
| :--- | :--- |
| 💳 **Rial (ایران)** | [coffeebede.com/amtherain](https://coffeebede.com/amtherain) |
| 💰 **USDT · TRC20** | `TKBHWNoeygcaCK8N78e7dQX5Yco3WTb6ZN` |
| 💰 **USDT · BEP20** | `0x0F982640a69D3B9FB944840D7DA8bECCfcF0bb9E` |
| 💰 **TON** | `UQAyLUyxew-eggwhxbzsAZZZ9ULM8MYOk-3IXFh7tNC33LNt` |

All methods, with copy buttons: **[izumirain.github.io](https://izumirain.github.io/)**

---

## 📜 License
HyperDNS is distributed under the **AGPL-3.0 License**.
