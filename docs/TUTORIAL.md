# 🎓 HyperDNS — Complete Step-by-Step Tutorial

<p align="center">
  <a href="../README.md">README</a> •
  <a href="API.md">REST API</a> •
  <a href="SECURITY.md">Security</a> •
  <a href="PRESET_CATALOG.md">Preset Catalog</a> •
  <a href="CHANGELOG.md">Changelog</a> •
  <a href="TUTORIAL.fa.md">نسخهٔ فارسی</a>
</p>

> This tutorial takes you from an empty VPS to a working gaming gateway with
> subscribers, a branded subscriber portal on **your own domain**, and clients
> connected. Every screen, field name and URL below is the real one in v2.2.0.
>
> **Persian version:** [TUTORIAL.fa.md](TUTORIAL.fa.md).

---

## Table of contents

0. [What you need before you start](#0-what-you-need-before-you-start)
1. [Install HyperDNS](#1-install-hyperdns)
2. [First login — save the two secrets](#2-first-login--save-the-two-secrets)
3. [Dashboard tour](#3-dashboard-tour)
4. [Panel domain and HTTPS](#4-panel-domain-and-https)
5. [Custom domain for the subscriber link](#5-custom-domain-for-the-subscriber-link)
6. [Add your first client](#6-add-your-first-client)
7. [How the subscriber registers their IP](#7-how-the-subscriber-registers-their-ip)
8. [Connect devices](#8-connect-devices)
9. [Turn policy presets on or off](#9-turn-policy-presets-on-or-off)
10. [Watch live traffic](#10-watch-live-traffic)
11. [Limits, expiry, and day-to-day client management](#11-limits-expiry-and-day-to-day-client-management)
12. [Advanced rules: custom proxied / blocked / direct / static records](#12-advanced-rules-custom-proxied--blocked--direct--static-records)
13. [The REST API and Swagger](#13-the-rest-api-and-swagger)
14. [The `hdns` console: status, flush, stop, start, uninstall](#14-the-hdns-console-status-flush-stop-start-uninstall)
15. [Backup and restore](#15-backup-and-restore)
16. [Troubleshooting](#16-troubleshooting)

---

## 0. What you need before you start

1. **A VPS** — 1 core / 1 GB RAM is the floor (see the README's hardware table).
   Debian 12 or Ubuntu 24.04 are the tested targets. The installer also handles
   firewalld/ufw and systemd.
2. **A domain name** you control, with access to its DNS panel. You will create
   at least one A record pointing at the VPS. The certificate authority needs to
   reach the server, so the domain must be public.
3. **These ports free on the VPS** — nothing else may be listening on them:

   | Port | Protocol | Purpose |
   | ---: | :--- | :--- |
   | **53** | UDP + TCP | Plain DNS (what consoles and routers set) |
   | **80** | TCP | SNI proxy HTTP + the ACME challenge listener |
   | **443** | TCP | SNI proxy HTTPS (the actual game traffic) |
   | **853** | TCP | DNS-over-TLS (Android "Private DNS", iOS) |
   | **8443** | TCP | DNS-over-HTTPS |
   | **8080** | TCP | The admin dashboard |

   If your provider has a cloud firewall (Hetzner/OVH/Vultr security groups),
   open these **there** too — the host firewall alone is not enough.
4. **Root access.** The installer writes to `/etc/systemd/system/`,
   `/etc/systemd/resolved.conf.d/` and `/opt/hyperdns`.

> ⚠️ **Read [SECURITY.md](SECURITY.md) before you expose the install to the
> public internet.** It covers the threat model, what is encrypted, and the
> hardening checklist.

---

## 1. Install HyperDNS

### 1a. One-line online install

```bash
curl -fsSL https://raw.githubusercontent.com/IzumiRain/HyperDNS/v2.6.0-beta.1/scripts/install.sh | sudo bash
```

The installer is interactive when a TTY is present. To fully script it:

```bash
curl -fsSL https://raw.githubusercontent.com/IzumiRain/HyperDNS/v2.6.0-beta.1/scripts/install.sh \
  -o install.sh

# Required: the panel domain, and an email for the certificate authority
HYPERDNS_DOMAIN=dns.example.com \
HYPERDNS_EMAIL=you@example.com \
sudo bash install.sh
```

### 1b. What the installer does (and what it refuses to do)

- Downloads the pinned release binary, verifies it, installs it to
  `/opt/hyperdns/`, and registers the `hyperdns` systemd service.
- **Generates a random admin password** and a **random 16-character admin
  path**, and prints both **exactly once**. Copy them into a password manager
  now — the password is never stored and cannot be recovered, only reset.
- Issues the Let's Encrypt certificate for the panel domain **itself**, over its
  own port-80 listener. No certbot, no acme.sh, no service stop. If issuance
  fails, the installer prints the reason and exits — it never prints success on
  a broken install.
- **Never upgrades in place.** If it finds an existing install, it archives it
  to `/root/hyperdns-preinstall-<date>.tar.gz` (with its sha256 printed) and then
  replaces it wholesale: fresh config, fresh credentials, fresh certificates.
  An interactive run must type `FRESH` to confirm the wipe; a piped
  `curl | bash` run refuses outright unless `HYPERDNS_FRESH=1` is set.
- Sets `systemd-resolved` aside (it binds 127.0.0.53:53 and would block port 53)
  via a drop-in at `/etc/systemd/resolved.conf.d/hyperdns.conf`, with safe
  permissions (`755` on the directory, `644` on the file).

> **Coming from HyperDNS 1.x?** Run `bash migrate-from-v1.sh` from the offline
> bundle **first**, then install.

### 1c. Offline install (no outbound internet at all)

Grab the offline bundle from the release page — it ships the binary, the
installer, the migration script and every asset, and verifies itself by sha256.
Copy it to the server and:

```bash
tar xzf hyperdns-v2.2.0-beta-linux-amd64-offline.tar.gz
cd hyperdns-offline
HYPERDNS_DOMAIN=dns.example.com HYPERDNS_EMAIL=you@example.com sudo bash install.sh
```

The bundle's own `verify_bundle.py` re-checks every file's checksum before you
trust it.

### 1d. Verify it is running

```bash
systemctl status hyperdns
hdns status
```

`hdns status` needs no database access and is safe to run beside the daemon. It
reports the service state, which listeners are answering on which ports, does a
live DNS query, and prints the panel domain and certificate status.

---

## 2. First login — save the two secrets

The dashboard is **never** served at the root. It lives at a secret path:

```text
https://<panel-domain>/<admin-path>/login
```

- `<admin-path>` is the 16-character random string the installer printed once.
  If you lost it: `hdns status` shows the dashboard URL, and the daemon reprints
  it in the journal on every start (`journalctl -u hyperdns | head`).
- The username is `admin`. The password is the random string the installer
  printed once.

Two things to notice about that login page:

- It loads **none** of the heavy dashboard assets, so the dashboard's source
  cannot be read before authentication.
- The two-factor code field appears **only** after a correct password. A wrong
  password never reveals that 2FA is on.

Bookmark the URL. Then immediately go to **Settings → Administrator
Credentials** and set a password you will remember (or, better, keep the random
one in a password manager and enable **Two-Factor Authentication** in the same
section).

---

## 3. Dashboard tour

The sidebar has seven sections; this tutorial visits each:

| Tab | Route | What it is for |
| :--- | :--- | :--- |
| **Dashboard** | `/home` | Live telemetry: QPS graph, active subscribers, cache hit rate, per-upstream latency. |
| **Clients** | `/clients` | Add/edit/delete subscribers, quotas, expiry, registration links and secrets. |
| **Policy Presets** | `/rules` | The one-click toggles for 171+ games and services, plus custom rule lists. |
| **Live Stream** | `/logs` | Live DNS query stream over SSE, with per-query action labels (`PROXY`, `DIRECT`, `BLOCK`). |
| **API** | `/api` | Generate the Master API key, see ready-to-copy code samples, check public exposure. |
| **Settings** | `/settings` | Whitelist mode, policies, API binding, 2FA, LDAP, hidden admin path, **Subscription Portal**, SSL/TLS. |
| **Connect Guide** | `/guide` | Per-platform connection instructions you can hand to a subscriber. |

The sidebar footer also has the **server's public IP** (click to copy), a
**Run Diagnostics** button, a **Restart** button (restarts the engine and
reloads rules), a **Flush Cache** button, and **Sign Out**.

---

## 4. Panel domain and HTTPS

If you passed `HYPERDNS_DOMAIN` to the installer this is already done — skip to
[step 5](#5-custom-domain-for-the-subscriber-link). Otherwise:

1. In your domain's DNS panel, create an **A record** for the panel hostname,
   e.g. `dns.example.com. A <server-IP>`, TTL 300.
2. In the dashboard: **Settings → SSL / TLS Manager for DoH, DoT (Android
   Private DNS)**. Set the domain and the ACME email, and enable auto-cert.
3. The daemon issues the certificate itself over port 80 and hot-swaps it into
   every live listener — DNS-over-TLS on 853, DNS-over-HTTPS on 8443, the admin
   panel, and the subscriber portal — with no restart and no downtime.
   Renewal runs daily and automatically.

If issuance fails, check in order: the A record propagates (`dig
dns.example.com` from another machine returns your server IP), port 80 is open
end-to-end (including the provider's cloud firewall), and no other service
occupies port 80.

---

## 5. Custom domain for the subscriber link

This is the part most operators want: each subscriber gets a personal page —
their status, quota, and IP registration — and by default it is served on the
panel domain. If you sell the service, you probably want it on a **branded
domain** of its own, so the link you send a customer says
`https://sub.yourbrand.com/sub/<token>` instead of your admin hostname.

Because the subscriber portal is a completely separate listener with its own
TLS settings, its domain can be anything — including a different domain
registrar, or a subdomain of a domain you use for nothing else.

### 5a. Point the domain at the server

In your DNS panel:

```text
sub.yourbrand.com.   A   <server-IP>     TTL 300
```

Use a **dedicated hostname** for the portal. Do not reuse the admin hostname —
the two are deliberately separated so that a subscriber browsing the portal
never reaches the admin login and vice versa.

### 5b. Configure it in the dashboard

**Settings → Subscription Portal**:

| Field | What to enter |
| :--- | :--- |
| **Enable subscriber portal** (`sub-enabled-input`) | On. |
| **Custom Subscription Domain** (`sub-domain-input`) | `sub.yourbrand.com` — *empty means "same as the panel domain"*, which is the default. |
| **Advertised port** (`sub-port-input`) | Leave blank for 443 (recommended). Set only if the portal must run on a non-standard port. |
| **Portal title** (`sub-title-input`) | Your brand name — shown as the page title. Defaults to `HyperDNS`. |

Then click **Issue SSL** (`sub-issue-ssl-btn`). A progress bar appears and the
daemon issues a certificate for that hostname the same way it did for the panel
— over its own port-80 listener, no service stop. When it finishes, click
**Save** (`save-subscription-btn`).

That is it. From now on, every subscriber's link is generated on
`https://sub.yourbrand.com/sub/<token>`.

> **The port field changes only the *advertised* link.** The listener itself
> always serves 443. It exists for setups where a CDN or reverse proxy in front
> of the server terminates TLS on a different port; if you have no such layer,
> leave it empty.

---

### 5c. Brand the subscriber portal with custom CSS

The portal ships with a clean default theme, but you can override it with your own CSS — a background, brand colours, a logo, custom fonts. **Settings → Subscription Portal → Portal custom CSS** offers three sources; only the one you pick is stored:

| Source | What to enter | How it is delivered |
| :--- | :--- | :--- |
| **Inline** | Paste CSS into the textbox (up to 16 KiB). | Sanitised and inlined in a `<style>` element on every portal page. |
| **Local file** | An absolute path on the server, e.g. `/root/css/sub.css` (up to 256 KiB). | The daemon reads it (read-only), sanitises it, and inlines it. A missing or oversized file is ignored with a log line — the portal still renders. |
| **URL** | An `http(s)` stylesheet address, e.g. `https://cdn.example/portal.css`. | Emitted as a `<link rel="stylesheet">` the subscriber's browser loads directly. The daemon never fetches it, so the resolver takes on no SSRF or latency risk. |

**What the sanitiser removes (inline and local-file sources).** The CSS is served on a page shown to strangers, so before it is inlined the daemon strips the constructs that turn a stylesheet into an attack: `<style>`/`<script>` breakouts are defanged, `@import` and external / `//` `url()` loads are removed (including escape-obfuscated ones such as `url(\68 ttps://…)`), and `expression()` is stripped. Relative and `data:` URLs survive, so `background: url('/img/bg.png')` and inline data-URI images work. The **URL** source is *not* sanitised — the browser loads it directly — so point it only at a stylesheet you control.

**Tips.**
- Prefer the portal's structural classes over bare element selectors, so a future markup change does not fight your theme.
- To ship a logo with no external request, embed it as a `data:` URI in `background-image`.
- Changes apply on the next portal page load — no restart.

> Custom CSS is set only by the panel admin and is applied to the pages your subscribers see. Treat a stylesheet copied from an untrusted source like any other code you run — the sanitiser is a safety net, not a licence to paste anything.

---

## 6. Add your first client

**Clients → Add Client**. The modal:

| Field | Meaning |
| :--- | :--- |
| **Name** (required) | Anything that identifies the human, e.g. `Reza (PS5 & Phone)`. Shown only to you. |
| **Traffic Limit (GB)** | `0` = unlimited. Counted on proxied traffic only — direct answers are free. |
| **Auto Reset** | The quota cycle: never / monthly / daily. |
| **Expiry (Gregorian)** | When the account stops working. Blank = never. There is a date picker (`YYYY-MM-DD HH:mm:ss`). |
| **Initial IP Address** | The subscriber's current public IP, if you know it. **Leave blank to let them self-register** via their personal URL. |

Click **Create**. A second modal appears — and this one is the most important
screen in the whole product:

---

## 7. How the subscriber registers their IP

After creating a client you get **two separate things**, and they are
deliberately split:

- **Subscription Link (portal page)** — the URL, of the form
  `https://sub.yourbrand.com/sub/<token>`. This is safe to send over Telegram,
  WhatsApp or SMS. Anyone who opens it sees the subscriber's **status and
  quota** — nothing else.
- **Registration Secret** — a separate password. The subscriber **types it on
  the portal page** to bind their current IP to the account.

The link alone is never enough to register. That is the whole point: a leaked
link must not let a stranger attach their own IP to a paying account. Send the
link in chat, and deliver the secret through a second channel (or read it aloud,
or send a screenshot of it).

### 7a. The subscriber's side

1. They open `https://sub.yourbrand.com/sub/<token>` — on the very network they
   want to register, since the portal sees the IP of whoever opens it.
2. They enter the **Registration Secret**.
3. Behind the scenes that is a `POST /ip/<token>` carrying the secret. The
   daemon verifies it, records the source IP, and the account is live.

From that moment, DNS queries from that IP are served. If the subscriber's IP
changes (mobile data, a new router, a flight), they open the same link and
register again — no intervention from you.

### 7b. If you set the Initial IP yourself

If you filled in **Initial IP Address** at creation time, the account starts
already bound and the subscriber needs to do nothing. Use it for a customer
whose IP you know (a fixed home line), and leave it blank for mobile users.

### 7c. Why unknown IPs are refused

The **client access whitelist is on by default**. A source IP that is not bound
to any account gets a DNS refusal carrying an **RFC 8914 Extended DNS Error**, so
a well-behaved client learns *why* it was blocked rather than silently failing.
This means an open server never becomes free public infrastructure for
strangers. You can switch it off with **Settings → Client Access Whitelist
Mode**, but read [SECURITY.md](SECURITY.md) first — `allow_all` makes the box a
public resolver and you pay the bandwidth.

---

## 8. Connect devices

The subscriber sets **one number** — the server's IP — as their DNS. No app, no
profile, no VPN. The **Connect Guide** tab (`/guide`) generates per-platform
instructions you can paste straight into a chat.

| Platform | Where to set it |
| :--- | :--- |
| **Windows 10/11** | Settings → Network → Ethernet/Wi-Fi → Hardware properties → DNS server assignment → Manual → IPv4, preferred `8.8.8.8` replaced by `<server-IP>`. |
| **PlayStation 4/5** | Settings → Network → Settings → Set Up Internet → Custom → IP Auto, DHCP Host Do Not Specify, DNS Manual: Primary `<server-IP>`, Secondary `<server-IP>` (or leave secondary blank). |
| **Xbox Series X/S** | Settings → General → Network Settings → Advanced Settings → DNS Settings → Manual, both fields `<server-IP>`. |
| **Nintendo Switch** | System Settings → Internet → Change Settings → DNS Settings → Manual, Primary `<server-IP>`. |
| **Android (Private DNS / DoT)** | Settings → Network → Private DNS → "custom" → `dns.example.com` — uses **port 853**, encrypted. The hostname, not the IP. |
| **iOS / iPadOS** | A DoH profile, or a plain DNS IP under Settings → Wi-Fi → ⓘ → Configure DNS. |
| **Router (whole home)** | DHCP-assigned DNS in the router's WAN/LAN settings — every device behind it is covered at once. |

The encrypted transports need the **hostname** (they verify a certificate), the
plain one needs the **IP**.

A quick sanity check from any machine:

```bash
# Plain DNS against your server
dig @<server-IP> api.steampowered.com

# DNS-over-TLS (Android Private DNS path)
kdig -d @dns.example.com +853 api.steampowered.com
```

An answer whose `A` record is **your server's IP** means the SNI proxy is taking
that connection; an answer with the real CDN IP means it is going direct.

---

## 9. Turn policy presets on or off

**Policy Presets** groups 171+ games and services into categories, each one
toggle. They are **all on by default except three**:

- `enable_downloads` — multi-gigabyte game installs. Off, because egress is
  billed by the gigabyte and a relayed download is usually slower than a direct
  one. See the README's "Before you turn it on" paragraph before flipping it.
- `enable_adblock` — ad blocking.
- `enable_familysafe` — adult-content filtering.

Each toggle shows the domains it covers. Changes apply immediately to the live
engine; after a big change, hit **Flush Cache** (sidebar) or
`POST /api/v1/cache/flush` so cached answers do not keep their old routing for
the rest of their TTL.

The full catalog, by category, is in [PRESET_CATALOG.md](PRESET_CATALOG.md).

---

## 10. Watch live traffic

**Live Stream** (`/logs`) is a Server-Sent Events feed — every DNS query the
server handles, live, with the matched rule and the action taken:

- `PROXY` — the answer was spoofed to the server so the SNI proxy grabs the
  connection. This is the gaming-gateway behaviour.
- `DIRECT` — the real answer, untouched, raced between upstreams.
- `BLOCK` — sinkholed.
- `DIRECT · Game & App Downloads` — the downloads veto in action (see step 9).

Nothing here is written to disk, ever. DNS telemetry lives in memory and on this
stream only — there is no query log file to leak. If you close the tab, the
history is gone.

**Dashboard** (`/home`) is the aggregate view: QPS graph, cache hit rate, and
per-upstream latency so you can see which resolver is winning the race.

**Run Diagnostics** (sidebar) checks the listeners, does a test query, and
reports the certificate state — the fastest "is it broken?" answer.

---

## 11. Limits, expiry, and day-to-day client management

From **Clients**, each row offers:

- **Edit** — change name, quota, cycle, expiry, allowed IPs.
- **Reset Traffic** — consumed bytes back to zero (also
  `POST /api/v1/clients/{id}/reset-traffic`).
- **Regenerate UUID** — invalidates the old UUID **immediately**. Use this the
  moment you think a link leaked: the old link dies at once, you get a fresh
  link and secret to hand out.
- **Delete** — permanent.

Two behaviours worth knowing:

- **Quota counts proxied traffic only.** Direct answers are free, so a
  subscriber whose plan is exhausted can still browse — only proxied game
  traffic stops. The counter is aggregated in RAM and written to disk every
  30 seconds in one transaction, because every BoltDB transaction is an `fsync`.
- **Expiry is a hard stop.** An expired account's IP is refused like an unknown
  one. Renew by editing the expiry, or for API-driven renewals,
  `PUT /api/v1/clients/{id}` with `days_to_add`.

---

## 12. Advanced rules: custom proxied / blocked / direct / static records

Under **Policy Presets**, below the toggles, four lists let you override
everything:

| List | Effect | Typical use |
| :--- | :--- | :--- |
| **Custom Proxied** | Route these names through the SNI proxy. | One game not in any preset; or rescuing one subscriber stuck on a blocked CDN. |
| **Custom Blocked** | Sinkhole these names. Outranks everything. | Telemetry, a game you don't want proxied, ad domains. |
| **Custom Direct** | Force real answers, never proxied. | A service whose CDN blocks proxies, or a domain you don't pay for. |
| **Custom Records** | Static DNS answers you control. | Split-horizon: `git.lab.example.com → 10.0.0.5` for insiders, real answer elsewhere. |

Matching is **longest-suffix-wins** with an exact-match index, so
`cdn.example.com` can be proxied while `*.example.com` goes direct — the more
specific rule wins. Custom rules on a **client's plan** are layered on top of
the global ones, and the more specific name always decides.

---

## 13. The REST API and Swagger

Everything above is scriptable. **Settings → API Network Binding & Security**
controls where `/api/*` listens (default `127.0.0.1` only — leave it that way
unless you know why you're opening it), and **Master API Authentication Key**
generates the key.

Interactive docs: **`/<admin-path>/api/v1/docs`** — Swagger UI, embedded in the
binary and served from the server itself, so it works in networks with no CDN
access. Click **Authorize**, paste the Master API key, and run any endpoint from
the browser.

v2 is the current contract (`/api/v2/…`): symmetric field names
(`display_name`, `allowed_ips`), cursor-paginated lists (`{items, next_cursor}`),
RFC 9457 `application/problem+json` errors, dedicated action endpoints
`POST /clients/{id}/actions/{action}`, and **strict decoding** — an unknown
field is a `400`, not a silent typo. v1 still works but carries `Deprecation`
and `Sunset` headers. Full reference with Python / Node.js / cURL samples:
[API.md](API.md).

Create a subscriber by API:

```bash
curl -X POST "https://dns.example.com/<admin-path>/api/v2/clients" \
  -H "Authorization: Bearer $HYPERDNS_KEY" \
  -H "Content-Type: application/json" \
  -d '{"display_name": "Reza (PS5 & Phone)", "traffic_limit_gb": 100}'
```

```python
import requests

r = requests.post(
    "https://dns.example.com/<admin-path>/api/v2/clients",
    headers={"Authorization": f"Bearer {API_KEY}"},
    json={"display_name": "Reza (PS5 & Phone)", "traffic_limit_gb": 100},
)
client = r.json()
print(client["registration_link"])   # send this to the subscriber
print(client["registration_secret"]) # send this via a second channel
```

> The Master API key is **refused on every dashboard management route** — it
> only works on `/api/*`. That separation was added in v2.2.0 so a leaked API
> key cannot become an admin session.

---

## 14. The `hdns` console: status, flush, stop, start, uninstall

```bash
hdns status      # live service report: ports, listeners, DNS test, certs.
                   # needs no database — safe beside a busy daemon
hdns flush       # ask the running daemon to flush its DNS cache
hdns version     # what the binary reports (e.g. HyperDNS v2.2.0-beta)
hdns uninstall   # interactive uninstaller
```

The interactive console can also **stop**, **start** and **uninstall** the
service — useful on a box where you only have a serial/SSH console and the web
panel is unreachable.

Systemd equivalents:

```bash
systemctl stop hyperdns      systemctl start hyperdns
journalctl -u hyperdns -f    # the live daemon log (dashboard URL is reprinted on every start)
```

---

## 15. Backup and restore

Two files are the entire installation — everything else is reproducible:

| File | Why it matters |
| :--- | :--- |
| `/opt/hyperdns/data.db` | The whole state: subscribers, quotas, rules, settings. |
| `/opt/hyperdns/master.key` | The 32-byte AES-256-GCM key sealing the sensitive fields. |

```bash
# Back up
tar czf hyperdns-backup-$(date +%F).tar.gz \
  -C /opt/hyperdns data.db master.key
sha256sum hyperdns-backup-*.tar.gz
```

- **Lose `master.key`** and every sealed field is unreadable forever — the
  backup is worthless without it. Store a copy **off the server**.
- **Leak `master.key`** and the sealed fields become readable. Never commit it
  to git; the repo's `.gitignore` already excludes it.
- **Restore** on a fresh box: install HyperDNS, stop the service, drop both
  files into `/opt/hyperdns/`, start the service. Upgrades from older versions
  migrate the data format on first boot and then rewrite the file once, so
  freed pages holding old plaintext are not recoverable from the backup file.

The admin password is **not** in either file — only a PBKDF2-HMAC-SHA256
verifier (600,000 iterations). Nobody, not even you, can recover it; it can only
be reset. Which fields are encrypted and which are deliberately in the clear is
documented in [SECURITY.md](SECURITY.md).

---

## 16. Troubleshooting

| Symptom | Check |
| :--- | :--- |
| **Installer says the panel certificate failed** | The A record must resolve to this server *from outside*; port 80 must be open end-to-end including the provider's cloud firewall; no other service on 80. The installer names the cause. |
| **I lost the admin path** | `hdns status`, or `journalctl -u hyperdns | head` — it is reprinted on every start. |
| **I lost the admin password** | Not recoverable, only resettable — run the installer with `HYPERDNS_FRESH=1` (it archives the old install first), or boot the binary with a fresh config. |
| **Subscriber says "nothing works"** | Did they register their IP? Their link is `/sub/<token>`; the secret is separate. Check **Clients** for their current bound IP, and ask them to re-register on the network they're using. |
| **Queries answered but game still lags** | Check **Live Stream** for the game's domains: are they `PROXY` (going through the SNI proxy) or `DIRECT`? A `DIRECT` answer means the preset for that game is off. |
| **Downloads stuck at 0 B/s, store page loads fine** | The one case `enable_downloads` exists for — their line cannot reach the CDN at all. Turn it on, or add the specific CDN host to **Custom Proxied**. |
| **Changed a rule, nothing changed** | Cached answers keep their old routing until TTL expiry. **Flush Cache** (sidebar) or `hdns flush`. |
| **Port 53 already in use** | `systemd-resolved`. The installer handles it; if you uninstalled and reinstalled manually, check `/etc/systemd/resolved.conf.d/hyperdns.conf`. |
| **Dashboard loads but `hdns status` shows a listener NOT answering** | Firewall. Verify with `ss -lnup` locally and a port checker from outside. |

---

<p align="center">
  Something missing? <a href="../README.md">README</a> for the overview,
  <a href="SECURITY.md">SECURITY.md</a> before you go public,
  <a href="API.md">API.md</a> for automation.
</p>
