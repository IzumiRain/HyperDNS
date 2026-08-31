# 📜 HyperDNS Changelog

All notable changes to the **HyperDNS** project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
  - Added **`SUPPORTED_GAMES.md`**: Complete categorized directory of all 171+ supported games, publishers, and platforms.
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
