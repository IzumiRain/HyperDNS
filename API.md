# 🔌 HyperDNS Developer REST API v1 — Official Specification & Guide

HyperDNS provides a high-performance **REST API v1** designed for bot developers, subscription managers, automated billing systems, Discord/Telegram bots, and enterprise monitoring platforms.

---

## 📑 Table of Contents

- [🔐 Authentication & Security](#-authentication--security)
- [🌐 Base URL & Interactive Docs](#-base-url--interactive-docs)
- [📊 1. System Health & Telemetry (`/status`)](#-1-system-health--telemetry-status)
- [👥 2. Client Management & Accounting (`/clients`)](#-2-client-management--accounting-clients)
  - [Create Client](#post-apiv1clients---create-new-client)
  - [List Clients (with Status Filter)](#get-apiv1clients---list-clients)
  - [Get Client Details](#get-apiv1clientsid---get-client-by-id)
  - [Renew / Extend Subscription](#post-apiv1clientsidrenew---renew-subscription)
  - [Register / Replace Client IP (1-IP Limit)](#post-apiv1clientsidip---register--replace-ip)
  - [Delete Client](#delete-apiv1clientsid---delete-client)
- [🎮 3. SmartDNS Rules & Presets (`/rules`)](#-3-smartdns-rules--presets-rules)
- [⚡ 4. Low-Latency Diagnostics (`/diagnostics`)](#-4-low-latency-diagnostics-diagnostics)
- [🤖 5. Practical Implementation Samples](#-5-practical-implementation-samples)
  - [Python Telegram Bot Integration](#-sample-a-python-telegram-bot-integration)
  - [Node.js / Express Webhook Integration](#-sample-b-nodejs--express-client-provisioner)
  - [cURL Fast Scripts](#-sample-c-curl-cli-one-liners)

---

## 🔐 Authentication & Security

All requests to `/api/v1/*` (except `/api/v1/docs`) require authentication via either a Master **API Key** or a **Bearer JWT Token**.

### Method 1: Master API Key (Recommended for Bots & Scripts)
Pass the API Key in the `X-API-Key` HTTP header:
```http
GET /api/v1/status HTTP/1.1
Host: YOUR_SERVER_IP:8080
X-API-Key: hdns_live_your_secret_api_key_here
```

### Method 2: JWT Bearer Token (For Web Dashboards)
Pass the JWT token obtained from `/api/auth/login`:
```http
GET /api/v1/status HTTP/1.1
Host: YOUR_SERVER_IP:8080
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6...
```

---

## 🌐 Base URL & Interactive Docs

- **Base URL:** `http://<SERVER_IP>:8080/api/v1` (or `https://<YOUR_DOMAIN>:8443/api/v1` when TLS is active)
- **Interactive UI Documentation:** Open `http://<SERVER_IP>:8080/api/v1/docs` in your browser for live Swagger-style docs with copyable cURL and Python payloads.

---

## 📊 1. System Health & Telemetry (`/status`)

Returns real-time server health, QPS rate, CPU/Memory telemetry, cache performance, and active client statistics.

### `GET /api/v1/status`

#### Request
```bash
curl -s http://127.0.0.1:8080/api/v1/status \
  -H "X-API-Key: YOUR_API_KEY"
```

#### Response (`200 OK`)
```json
{
  "success": true,
  "data": {
    "version": "1.2.0-beta",
    "public_ip": "95.179.140.241",
    "bind_host": "0.0.0.0",
    "dns_port": 53,
    "dot_port": 853,
    "doh_port": 8443,
    "web_port": 8080,
    "allow_all_mode": true,
    "clients": {
      "total": 24,
      "active": 20,
      "expired": 4
    },
    "telemetry": {
      "uptime_seconds": 3840,
      "qps": 42.5,
      "total_queries": 163240,
      "active_conns": 12,
      "memory_mb": 0.85,
      "cpu_percent": 1.2,
      "goroutines": 21,
      "cached_records": 1240,
      "cache_hit_ratio": 78.4
    },
    "upstreams": [
      "1.1.1.1:53",
      "8.8.8.8:53"
    ]
  },
  "timestamp": 1788125000
}
```

---

## 👥 2. Client Management & Accounting (`/clients`)

### `POST /api/v1/clients` — Create New Client

Creates a new user subscription. Returns a unique Client ID and instant 1-Click IP registration link.

#### Request Body
```json
{
  "name": "Ali-Gamer",
  "expires_days": 30,
  "initial_ip": "188.245.10.25"
}
```
*(Note: `expires_days: 0` creates a lifetime account. `initial_ip` is optional).*

#### cURL Sample
```bash
curl -s -X POST http://127.0.0.1:8080/api/v1/clients \
  -H "X-API-Key: YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"name":"Ali-Gamer","expires_days":30,"initial_ip":"188.245.10.25"}'
```

#### Response (`201 Created`)
```json
{
  "success": true,
  "data": {
    "client": {
      "id": "784910283",
      "name": "Ali-Gamer",
      "token": "d8f3a1e94b2c019a",
      "allowed_ips": ["188.245.10.25"],
      "expires_at": "2026-09-30T14:30:00Z",
      "created_at": "2026-08-31T14:30:00Z",
      "last_seen": "2026-08-31T14:30:00Z",
      "total_queries": 0,
      "enabled": true
    },
    "register_url": "http://95.179.140.241:8080/ip/d8f3a1e94b2c019a"
  },
  "timestamp": 1788125000
}
```

---

### `GET /api/v1/clients` — List Clients

Lists all clients with optional status filtering (`active` / `expired`) and text search.

#### Query Parameters
- `status`: `active` | `expired` | `all` (default: `all`)
- `search`: filter by client name or IP

#### cURL Sample
```bash
curl -s "http://127.0.0.1:8080/api/v1/clients?status=expired" \
  -H "X-API-Key: YOUR_API_KEY"
```

#### Response (`200 OK`)
```json
{
  "success": true,
  "data": {
    "count": 1,
    "clients": [
      {
        "id": "306974290",
        "name": "Expired-User",
        "token": "982e0999545f40df",
        "registered_ip": "30.30.30.30",
        "status": "expired",
        "is_expired": true,
        "enabled": false,
        "expires_at": "2026-08-29T21:24:24Z",
        "created_at": "2026-08-30T21:24:24Z",
        "last_seen": "2026-08-30T21:24:24Z",
        "total_queries": 1420,
        "register_url": "http://95.179.140.241:8080/ip/982e0999545f40df"
      }
    ]
  },
  "timestamp": 1788125000
}
```

---

### `GET /api/v1/clients/{id}` — Get Client by ID

#### Request
```bash
curl -s http://127.0.0.1:8080/api/v1/clients/784910283 \
  -H "X-API-Key: YOUR_API_KEY"
```

#### Response (`200 OK`)
```json
{
  "success": true,
  "data": {
    "id": "784910283",
    "name": "Ali-Gamer",
    "token": "d8f3a1e94b2c019a",
    "registered_ip": "188.245.10.25",
    "enabled": true,
    "is_expired": false,
    "expires_at": "2026-09-30T14:30:00Z",
    "created_at": "2026-08-31T14:30:00Z",
    "last_seen": "2026-08-31T15:10:00Z",
    "total_queries": 450,
    "register_url": "http://95.179.140.241:8080/ip/d8f3a1e94b2c019a"
  },
  "timestamp": 1788125000
}
```

---

### `POST /api/v1/clients/{id}/renew` — Renew Subscription

Extends the expiration date of an existing client by `extend_days`. If the account was expired and disabled, it automatically re-enables it.

#### Request Body
```json
{
  "extend_days": 30
}
```

#### cURL Sample
```bash
curl -s -X POST http://127.0.0.1:8080/api/v1/clients/784910283/renew \
  -H "X-API-Key: YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"extend_days":30}'
```

#### Response (`200 OK`)
```json
{
  "success": true,
  "data": {
    "id": "784910283",
    "message": "Subscription renewed successfully",
    "expires_at": "2026-10-30T14:30:00Z",
    "enabled": true
  },
  "timestamp": 1788125000
}
```

---

### `POST /api/v1/clients/{id}/ip` — Register / Replace IP

Updates the allowed IP for a client. **Enforces a strict 1-IP limit:** the previous IP is replaced immediately.

#### Request Body
```json
{
  "ip": "2.188.94.10"
}
```

#### cURL Sample
```bash
curl -s -X POST http://127.0.0.1:8080/api/v1/clients/784910283/ip \
  -H "X-API-Key: YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"ip":"2.188.94.10"}'
```

#### Response (`200 OK`)
```json
{
  "success": true,
  "data": {
    "id": "784910283",
    "message": "Client registered IP updated successfully (1-IP limit enforced)",
    "registered_ip": "2.188.94.10"
  },
  "timestamp": 1788125000
}
```

---

### `DELETE /api/v1/clients/{id}` — Delete Client

Permanently deletes a client and revokes their DNS access.

#### Request
```bash
curl -s -X DELETE http://127.0.0.1:8080/api/v1/clients/784910283 \
  -H "X-API-Key: YOUR_API_KEY"
```

#### Response (`200 OK`)
```json
{
  "success": true,
  "data": {
    "id": "784910283",
    "message": "Client deleted successfully"
  },
  "timestamp": 1788125000
}
```

---

## 🎮 3. SmartDNS Rules & Presets (`/rules`)

### `GET /api/v1/rules`

Returns all active policy toggles (Riot, Steam, Shooters Extra, Anime MMOs, Dev 403, AdBlock, etc.).

#### Response (`200 OK`)
```json
{
  "success": true,
  "data": {
    "rules": {
      "enable_riot": true,
      "enable_epic": true,
      "enable_steam": true,
      "enable_pubg": true,
      "enable_call_of_duty": true,
      "enable_shooters_extra": true,
      "enable_anime_gacha": true,
      "enable_sports_racing": true,
      "enable_coop_survival": true,
      "enable_platforms_extra": true,
      "enable_discord": true,
      "enable_spotify": true,
      "enable_soundcloud": true,
      "enable_dev_403": true,
      "enable_adblock": false,
      "enable_family_safe": false
    },
    "custom_domains_count": 0
  },
  "timestamp": 1788125000
}
```

### `POST /api/v1/rules`

Updates rule presets dynamically without server downtime.

#### Request Body
```json
{
  "enable_shooters_extra": true,
  "enable_anime_gacha": true,
  "enable_adblock": true
}
```

---

## ⚡ 4. Low-Latency Diagnostics (`/diagnostics`)

Performs an on-server latency benchmark against top international game servers and DNS resolvers.

### `GET /api/v1/diagnostics`

#### Response (`200 OK`)
```json
{
  "success": true,
  "data": {
    "targets": [
      { "name": "Cloudflare DNS (1.1.1.1)", "ip": "1.1.1.1", "latency_ms": 1.2, "status": "online" },
      { "name": "Riot EU West (104.16.0.0)", "ip": "104.16.0.0", "latency_ms": 3.8, "status": "online" },
      { "name": "Valve Frankfurt (162.254.197.0)", "ip": "162.254.197.0", "latency_ms": 4.1, "status": "online" },
      { "name": "EA FIFA Ultimate Team", "ip": "159.153.0.0", "latency_ms": 6.5, "status": "online" }
    ],
    "average_latency_ms": 3.9
  },
  "timestamp": 1788125000
}
```

---

## 🤖 5. Practical Implementation Samples

### 🐍 Sample A: Python Telegram Bot Integration

Complete asynchronous Python script using `httpx` to create accounts, renew subscriptions, and send 1-click setup links to Telegram users:

```python
import httpx
import asyncio

HYPERDNS_API_URL = "http://95.179.140.241:8080/api/v1"
API_KEY = "hdns_live_testkey_1234567890abcdef1234567890abcdef"

headers = {
    "X-API-Key": API_KEY,
    "Content-Type": "application/json"
}

async def create_gamer_subscription(telegram_username: str, plan_days: int = 30):
    async with httpx.AsyncClient(timeout=10.0) as client:
        payload = {
            "name": f"TG_{telegram_username}",
            "expires_days": plan_days
        }
        res = await client.post(f"{HYPERDNS_API_URL}/clients", json=payload, headers=headers)
        data = res.json()
        
        if res.status_code == 201 and data.get("success"):
            client_info = data["data"]["client"]
            reg_url = data["data"]["register_url"]
            print(f"✅ Subscription Created for @{telegram_username}!")
            print(f"🔑 Client ID : {client_info['id']}")
            print(f"📅 Expires At: {client_info['expires_at']}")
            print(f"🔗 1-Click IP Register Link: {reg_url}")
            return reg_url
        else:
            print(f"❌ Error creating client: {data}")
            return None

async def renew_gamer_subscription(client_id: str, extend_days: int = 30):
    async with httpx.AsyncClient(timeout=10.0) as client:
        payload = {"extend_days": extend_days}
        res = await client.post(f"{HYPERDNS_API_URL}/clients/{client_id}/renew", json=payload, headers=headers)
        return res.json()

# Test Run
if __name__ == "__main__":
    asyncio.run(create_gamer_subscription("Sina_Gamer", 30))
```

---

### 🟢 Sample B: Node.js / Express Client Provisioner

```javascript
import axios from 'axios';

const hdns = axios.create({
  baseURL: 'http://95.179.140.241:8080/api/v1',
  headers: {
    'X-API-Key': 'hdns_live_testkey_1234567890abcdef1234567890abcdef',
    'Content-Type': 'application/json',
  },
});

// 1. Create a client upon user checkout
async function handleUserPurchase(customerName, days) {
  try {
    const res = await hdns.post('/clients', {
      name: customerName,
      expires_days: days,
    });
    
    const { client, register_url } = res.data.data;
    console.log(`Created client ${client.id} for ${customerName}`);
    console.log(`Send this URL to customer: ${register_url}`);
    return { clientId: client.id, registerUrl: register_url };
  } catch (error) {
    console.error('HyperDNS API error:', error.response?.data || error.message);
  }
}

// 2. Fetch server real-time QPS & active clients
async function fetchMonitoringStats() {
  const res = await hdns.get('/status');
  const { clients, telemetry } = res.data.data;
  console.log(`Active Clients: ${clients.active} | Current QPS: ${telemetry.qps} | RAM: ${telemetry.memory_mb} MB`);
}

handleUserPurchase('Reza_Pro', 30);
```

---

### 💻 Sample C: cURL CLI One-Liners

```bash
# 1. Check live QPS & RAM
curl -s http://127.0.0.1:8080/api/v1/status -H "X-API-Key: YOUR_KEY" | jq .data.telemetry

# 2. Add client and extract only registration link
curl -s -X POST http://127.0.0.1:8080/api/v1/clients \
  -H "X-API-Key: YOUR_KEY" \
  -H "Content-Type: application/json" \
  -d '{"name":"FastClient","expires_days":30}' | jq -r .data.register_url

# 3. List all expired users
curl -s "http://127.0.0.1:8080/api/v1/clients?status=expired" -H "X-API-Key: YOUR_KEY" | jq .data.clients

# 4. Run instant latency diagnostic benchmark
curl -s http://127.0.0.1:8080/api/v1/diagnostics -H "X-API-Key: YOUR_KEY" | jq .data
```

---

<p align="center">
  <b>HyperDNS REST API v1</b> — High Performance · Fully Documented · Zero Lag
</p>
