# ⚡ HyperDNS — Next-Gen Standalone SmartDNS & Gaming Gateway

<p align="center">
  <img src="https://img.shields.io/badge/Release-beta%201.1.0-00f0ff?style=for-the-badge&logo=rocket" alt="Version">
  <img src="https://img.shields.io/badge/Status-Beta%20Preview-amber?style=for-the-badge" alt="Status">
  <img src="https://img.shields.io/badge/Language-Go%201.26-00ADD8?style=for-the-badge&logo=go" alt="Go">
  <img src="https://img.shields.io/badge/Architecture-Single%20Binary-a855f7?style=for-the-badge" alt="Single Binary">
  <img src="https://img.shields.io/badge/Protocols-UDP%20%7C%20DoH%20%7C%20DoT-10b981?style=for-the-badge" alt="Protocols">
  <img src="https://img.shields.io/badge/Gaming-Zero%20Loss%20%26%20Low%20Ping-ff4655?style=for-the-badge" alt="Gaming">
  <img src="https://img.shields.io/badge/License-AGPL--3.0-blue?style=for-the-badge&logo=gnu" alt="License">
</p>

> [!WARNING]
> ### ⚠️ BETA VERSION NOTICE
> **IMPORTANT:** This project is currently under active development in **BETA**. It may contain unexpected bugs, unhandled exceptions, or edge-case routing quirks. If you experience any issues, game connectivity bugs, or have improvement suggestions, please report them via **[GitHub Issues](https://github.com/IzumiRain/HyperDNS/issues)**.

<p align="center">
  <a href="#-features">Features</a> •
  <a href="#-quick-installation">Installation</a> •
  <a href="#-tui-terminal-controller-hdns">TUI Controller</a> •
  <a href="#-client-setup-guides">Client Setup</a> •
  <a href="README.fa.md">فارسی (Persian)</a> •
  <a href="#-support--donation">Donation</a>
</p>

---

## 📖 Overview

**HyperDNS** is an ultra-fast, single-binary SmartDNS server and transparent SNI Proxy engine with an embedded cyberpunk/gaming web dashboard and interactive terminal interface (`hdns`).

It transforms any single Linux or Windows server into a private **Anti-Sanction (403 Bypass)** and **Low-Latency Gaming Gateway** for PC, PlayStation 5, Xbox, Nintendo Switch, Android, iOS, and Routers with **zero client software required** and **zero VPN encapsulation overhead**.

```
                                  [ Client Devices ]
                     (Gaming PC, PS5/Xbox, Mobile, Browser)
                                         │
                 ┌───────────────────────┴───────────────────────┐
                 │  UDP/TCP 53, DoH (8443/8080), DoT (853)       │
                 ▼                                               ▼
       ┌───────────────────────────────────┐       ┌───────────────────────────────────┐
       │     HyperDNS Core Engine (Go)     │       │     HyperDNS SNI Proxy (80/443)   │
       │  - In-Memory Sharded LRU Cache    │       │  - TLS ClientHello SNI Parser     │
       │  - Smart Policy Matcher           │       │  - Zero-Knowledge TCP Forwarder   │
       │  - Fastest Upstream Racing Pool   │       │  - Anti-DPI TLS Fragmentation     │
       │  - Access Control (Tokens/IPs)    │       │  - Direct Forward to Target Host  │
       └─────────────────┬─────────────────┘       └─────────────────┬─────────────────┘
                         │                                           │
                         ▼                                           ▼
              [ Upstream Resolvers ]                        [ Destination Servers ]
            (1.1.1.1, 8.8.8.8, Quad9)                  (Riot, Epic, Discord, Steam)
```

---

## 🌟 Features

### 🎮 1. Categorized Smart Policies (171+ Games & Services)
- **Gaming & Tactical Shooters:** Valorant, CS2, Call of Duty (Warzone / Mobile / BO6), The Finals, Tarkov, Delta Force, HellDivers 2, PUBG, Apex Legends, Rainbow Six Siege, Rust, Squad, DayZ, ArmA, Dead by Daylight.
- **Anime, Gacha & MMORPGs:** Genshin Impact, Honkai: Star Rail, Zenless Zone Zero, Wuthering Waves, Arknights, Lost Ark, Throne & Liberty, Path of Exile 1 & 2, Warframe, Elden Ring, Black Desert.
- **Sports, Fighting & Racing:** EA Sports FC 25, eFootball, Street Fighter 6, Mortal Kombat 1, Tekken 8, Assetto Corsa, Euro Truck Simulator 2, 2XKO.
- **Publishers & Ecosystems:** Riot Games, Steam/Valve, Epic Games, Blizzard, EA, Ubisoft, Rockstar, Xbox Live, PlayStation Network, Roblox, Supercell.
- **Streaming & Media:** Discord (Full Suite + RTC Voice + Updates), Spotify & SoundCloud, Twitch, Kick.com.
- **Developer 403 Suite:** Docker Hub, OpenAI / ChatGPT, Claude / Anthropic, npm, Gradle, Android SDK, PyPI, HuggingFace, Supabase, Vercel.
- **Security & Privacy:** AdBlock & Telemetry Sinkhole (`0.0.0.0`), Family Safe Adult Content Protection.

👉 **[View Full Supported Games & Platforms Directory (171+ Titles)](SUPPORTED_GAMES.md)**

### ⚡ 2. Microsecond In-Memory Cache & Racing Resolvers
- **RAM Cache:** Repeated queries resolve in **<0.5ms** with automatic TTL decay.
- **Fastest Upstream Racing:** Parallel queries to Cloudflare (`1.1.1.1`), Google (`8.8.8.8`), and Quad9 (`9.9.9.9`) — the fastest response wins.

### 🛡️ 3. DPI Resistance & Zero-Knowledge SNI Proxy
- Preserves end-to-end encryption without SSL certificate decryption.
- Optional **TLS ClientHello Fragmentation** to bypass DPI middleboxes on restricted networks.

### 🖥️ 4. Dual Interfaces (Web Dashboard + `hdns` TUI)
- **Web Dashboard:** Real-time QPS, CPU %, RAM MB, live bandwidth telemetry (`↓ KB/s` / `↑ KB/s`), and live Server-Sent Events (SSE) query stream.
- **Terminal UI (`hdns`):** Rich interactive terminal management menu.

---

## 🚀 Quick Installation

### Option 1: One-Line Linux Installer (Recommended)
Run as `root` on Ubuntu 20.04+, Debian 11+, or CentOS/RHEL/Alma/Rocky 8+:
```bash
curl -fsSL https://raw.githubusercontent.com/IzumiRain/HyperDNS/main/scripts/install.sh | sudo bash
```

### Option 2: Docker Compose
```bash
git clone https://github.com/IzumiRain/HyperDNS.git
cd HyperDNS
docker compose up -d
```

### Option 3: Compile from Source
```bash
git clone https://github.com/IzumiRain/HyperDNS.git
cd HyperDNS
go build -o hyperdns ./cmd/hyperdns
./hyperdns -config config.json
```

---

## 🖥️ TUI Terminal Controller (`hdns`)

Launch the interactive Terminal User Interface from anywhere on your server:
```bash
hdns
```

### Hotkeys & Features:
- **`[1]`** Live Telemetry Dashboard
- **`[2]`** 15+ Game & Security Presets Configurator
- **`[3]`** Custom Domain & TLS/SSL Manager (DoH / DoT)
- **`[4]`** Admin Credentials Manager
- **`[5]`** Upstream DNS Resolvers Manager
- **`[6]`** Instant DNS Cache Flush
- **`[7]`** Restart HyperDNS System Service
- **`[8]`** Regenerate TLS Certificates
- **`[9]`** Complete Clean Uninstall

### Standalone CLI Commands:
| Command | Description |
|:---|:---|
| `hdns` | Open Interactive Management TUI Console |
| `hdns status` | Display live service health, ports & active stats |
| `hdns restart` | Restart the background service |
| `hdns stop` / `hdns start` | Stop / Start the background service |
| `hdns logs` | Stream live query & system logs |
| `hdns flush` | Flush the in-memory DNS cache |
| `hdns diag` | Run latency benchmark & gaming diagnostics |
| `hdns clients` | List registered clients & whitelist IPs |
| `hdns uninstall` | Completely uninstall HyperDNS and remove all files |

---

## 🎮 Client Setup Guides

### 🖥️ Windows 10 / 11 (Gaming PC)
1. Go to **Settings** &gt; **Network & Internet** &gt; **Ethernet / Wi-Fi**.
2. Click **Edit DNS assignment** &gt; Select **Manual** &gt; Turn on **IPv4**.
3. Set **Preferred DNS** and **Alternate DNS** to your Server Public IP.

### 🎮 PlayStation 5 / Xbox Series X|S
1. Go to **Settings** &gt; **Network** &gt; **Set Up Internet Connection**.
2. Select your connection &gt; **Advanced Settings** &gt; **DNS Settings**: **Manual**.
3. Set **Primary DNS** to your Server Public IP.

### 📱 Android (Private DNS / DoT)
1. Go to **Settings** &gt; **Network & Internet** &gt; **Private DNS**.
2. Select **Private DNS provider hostname** and enter: `dns.yourdomain.com`.

### 🌐 Web Browser (Chrome, Brave, Firefox)
1. Go to **Settings** &gt; **Privacy & Security** &gt; **Use secure DNS**.
2. Select **Custom** and enter: `http://YOUR_SERVER_IP:8080/dns-query`.

---

## 💖 Support & Donation

If you find **HyperDNS** helpful for your gaming and bypassing network restrictions, consider supporting the development!

🌐 **Personal Website:** [https://izumirain.github.io/](https://izumirain.github.io/)

| Network | Address |
|:---|:---|
| **TRC20** (Tron) | `TKBHWNoeygcaCK8N78e7dQX5Yco3WTb6ZN` |
| **BEP20** (BNB Smart Chain) | `0x0F982640a69D3B9FB944840D7DA8bECCfcF0bb9E` |
| **TON** | `UQAyLUyxew-eggwhxbzsAZZZ9ULM8MYOk-3IXFh7tNC33LNt` |

---

## 📄 License
Released under the **[GNU Affero General Public License v3.0 (AGPL-3.0)](LICENSE)**. Developed with ❤️ for gamers and the free open internet.
