#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
HyperDNS v1.5.0-beta (HyperRAIN) — Telegram Bot Controller & Provisioner
A full-featured Telegram bot for managing HyperDNS smart DNS proxy, subscribers,
game routing policies, and real-time telemetry via the HyperDNS REST API v1.
"""

import html
import json
import logging
import os
import sys
import time
import requests

# -----------------------------------------------------------------------------
# Configuration
#
# Credentials come from the environment only. No default secret belongs here: a
# fallback token committed to the tree is a token handed to everyone who reads
# the repository, and a Telegram bot token is full control of the bot.
# -----------------------------------------------------------------------------
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "")
HYPERDNS_API_BASE = os.getenv("HYPERDNS_API_BASE", "http://127.0.0.1:8080/api/v2")
HYPERDNS_API_KEY = os.getenv("HYPERDNS_API_KEY", "")

# The chat IDs allowed to command the bot, comma-separated. Telegram chat IDs
# are public knowledge to anyone who can message the bot, and the bot speaks
# with the daemon's master API key — /add creates billable accounts, /clients
# hands out subscriber registration links — so "any chat that says /start" is
# not an authorization model. Empty set = the bot serves nobody.
TELEGRAM_ADMIN_CHAT_IDS = os.getenv("TELEGRAM_ADMIN_CHAT_IDS", "")


def parse_admin_chat_ids(raw: str) -> set:
    """Parse the comma-separated admin chat ID list, ignoring junk entries."""
    ids = set()
    for part in raw.split(","):
        part = part.strip()
        if part.lstrip("-").isdigit():
            ids.add(int(part))
    return ids


logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("HyperDNS-Bot")


def require_env(name: str, value: str) -> str:
    """Return a required credential or exit with an actionable message.

    Called from __main__ only, so importing this module (tests, tooling) does not
    depend on the environment being populated.
    """
    if not value.strip():
        sys.exit(
            f"[FATAL] {name} is not set.\n"
            f"        Set it in the environment, your systemd unit, or a .env file:\n"
            f"            export {name}=...\n"
            f"        HyperDNS deliberately ships no credential defaults in source."
        )
    return value.strip()

class HyperDNSClient:
    """HTTP client wrapping the HyperDNS REST API v2."""
    def __init__(self, base_url: str, api_key: str):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.session = requests.Session()

    def _headers(self):
        return {
            "X-API-Key": self.api_key,
            "Content-Type": "application/json"
        }

    def get_version(self) -> dict:
        r = self.session.get(f"{self.base_url}/version")
        r.raise_for_status()
        return r.json()

    def get_status(self) -> dict:
        r = self.session.get(f"{self.base_url}/status", headers=self._headers())
        r.raise_for_status()
        return r.json()

    def list_clients(self) -> list:
        r = self.session.get(f"{self.base_url}/clients?limit=200", headers=self._headers())
        r.raise_for_status()
        return r.json().get("items", [])

    def get_client(self, client_id: str) -> dict:
        r = self.session.get(f"{self.base_url}/clients/{client_id}", headers=self._headers())
        r.raise_for_status()
        return r.json()

    def create_client(self, name: str, days: int = 30, ip: str = "", traffic_gb: float = 0.0, policies: list = None, note: str = "") -> dict:
        payload = {
            "display_name": name,
            "validity_days": days,
            "allowed_ips": [ip] if ip else [],
            "quota_limit_gb": traffic_gb,
            "policy_ids": policies or [],
            "note": note
        }
        r = self.session.post(f"{self.base_url}/clients", json=payload, headers=self._headers())
        r.raise_for_status()
        return r.json()

    def update_client(self, client_id: str, updates: dict) -> dict:
        r = self.session.patch(f"{self.base_url}/clients/{client_id}", json=updates, headers=self._headers())
        r.raise_for_status()
        return r.json()

    def reset_traffic(self, client_id: str) -> bool:
        r = self.session.post(f"{self.base_url}/clients/{client_id}/actions/reset-traffic", headers=self._headers())
        r.raise_for_status()
        return r.json().get("reset", False)

    def regenerate_uuid(self, client_id: str) -> str:
        r = self.session.post(f"{self.base_url}/clients/{client_id}/actions/regenerate-uuid", headers=self._headers())
        r.raise_for_status()
        return r.json().get("uuid", "")

    def delete_client(self, client_id: str) -> bool:
        r = self.session.delete(f"{self.base_url}/clients/{client_id}", headers=self._headers())
        r.raise_for_status()
        return r.json().get("deleted", False)

    def list_policies(self) -> list:
        r = self.session.get(f"{self.base_url}/policies", headers=self._headers())
        r.raise_for_status()
        return r.json().get("policies", [])

    def toggle_policy(self, key: str, enabled: bool) -> dict:
        r = self.session.post(f"{self.base_url}/policies", json={"key": key, "enabled": enabled}, headers=self._headers())
        r.raise_for_status()
        return r.json()

    def flush_cache(self) -> bool:
        r = self.session.post(f"{self.base_url}/cache/flush", headers=self._headers())
        r.raise_for_status()
        return r.json().get("flushed", False)

    def get_api_key(self) -> str:
        r = self.session.get(f"{self.base_url}/api-key", headers=self._headers())
        r.raise_for_status()
        return r.json().get("api_key", "")


class HyperDNSTelegramBot:
    """Telegram Bot implementation handling user interactions."""
    def __init__(self, token: str, api_client: HyperDNSClient, admin_chat_ids: set = None):
        self.token = token
        self.api = api_client
        self.api_url = f"https://api.telegram.org/bot{token}"
        self.last_update_id = 0
        # Fail closed: with no allowlist the bot answers nobody. The bot speaks
        # with the daemon's master API key, so an empty set must mean "mute",
        # not "open to whoever found the bot".
        self.admin_chat_ids = admin_chat_ids if admin_chat_ids is not None else set()

    def is_authorized(self, chat_id) -> bool:
        return chat_id is not None and chat_id in self.admin_chat_ids

    def send_message(self, chat_id: int, text: str, reply_markup: dict = None) -> dict:
        url = f"{self.api_url}/sendMessage"
        payload = {
            "chat_id": chat_id,
            "text": text,
            "parse_mode": "HTML",
            "disable_web_page_preview": True
        }
        if reply_markup:
            payload["reply_markup"] = json.dumps(reply_markup)
        try:
            r = requests.post(url, json=payload, timeout=10)
            return r.json()
        except Exception as e:
            logger.error(f"Failed to send Telegram message: {e}")
            return {"ok": False, "error": str(e)}

    def format_status(self, data: dict) -> str:
        telemetry = data.get("telemetry", {})
        v_info = data.get("version", {})
        return (
            f"⚡ <b>HyperDNS Server Status</b>\n"
            f"━━━━━━━━━━━━━━━━━━━\n"
            f"• <b>Version:</b> <code>{v_info.get('display', 'v1.5.0-beta')}</code> ({v_info.get('codename', 'HyperRAIN')})\n"
            f"• <b>Public IP:</b> <code>{data.get('public_ip', 'Unknown')}</code>\n"
            f"• <b>Health:</b> 🟢 <b>{data.get('status', 'healthy').upper()}</b>\n"
            f"• <b>Current QPS:</b> <code>{telemetry.get('qps', 0):.1f} queries/sec</code>\n"
            f"• <b>Total Queries:</b> <code>{telemetry.get('total_queries', 0):,}</code>\n"
            f"• <b>Cache Hit Rate:</b> <code>{telemetry.get('cache_hit_rate', 0):.1f}%</code>\n"
            f"• <b>Active Relays:</b> <code>{telemetry.get('active_relays', 0)}</code>\n"
            f"• <b>CPU Usage:</b> <code>{telemetry.get('cpu_usage', 0):.1f}%</code>\n"
            f"• <b>Memory (RAM):</b> <code>{telemetry.get('ram_usage_mb', 0):.1f} MB</code>\n"
            f"• <b>Uptime:</b> <code>{telemetry.get('uptime_sec', 0) // 3600}h {(telemetry.get('uptime_sec', 0) % 3600) // 60}m</code>\n"
        )

    def format_client_card(self, c: dict, public_ip: str) -> str:
        # Every interpolation below is a value an operator or the API supplied,
        # rendered into a parse_mode=HTML message: a subscriber named
        # <b>Free</b> or one whose note carries a link must not reach Telegram
        # as markup.
        esc = html.escape
        # v2 field names (display_name / policy_ids / quota_limit_gb), falling
        # back to the v1 names so a bot pointed at an older daemon still renders.
        policies = c.get("policy_ids") or c.get("custom_policies") or []
        policy_str = esc(", ".join(policies)) if policies else "All Global Policies (Inherit)"
        status_emoji = "🟢 Active" if c.get("enabled", True) else "🔴 Disabled"
        quota = c.get('quota_limit_gb') or c.get('traffic_limit_gb') or 0
        traffic_limit = f"{quota:.1f} GB" if quota > 0 else "Unlimited"
        traffic_used_mb = c.get('traffic_used_bytes', 0) / (1024 * 1024)

        reg_link = f"http://{public_ip}:8080/ip/{c.get('token')}"

        return (
            f"👤 <b>Subscriber:</b> <b>{esc(str(c.get('display_name') or c.get('name')))}</b>\n"
            f"━━━━━━━━━━━━━━━━━━━\n"
            f"• <b>ID:</b> <code>{esc(str(c.get('id')))}</code>\n"
            f"• <b>Status:</b> {status_emoji}\n"
            f"• <b>UUID:</b> <code>{esc(str(c.get('uuid')))}</code>\n"
            f"• <b>Allowed IPs:</b> <code>{esc(', '.join(c.get('allowed_ips') or ['(Auto-Link)'])) }</code>\n"
            f"• <b>Traffic:</b> <code>{traffic_used_mb:.2f} MB / {esc(traffic_limit)}</code>\n"
            f"• <b>Expires:</b> <code>{esc(str(c.get('expires_at') or 'Lifetime'))}</code>\n"
            f"• <b>Custom Policies:</b> <i>{policy_str}</i>\n"
            f"• <b>Note:</b> <i>{esc(str(c.get('note') or 'None'))}</i>\n"
            f"• 🔗 <b>1-Click IP Link:</b>\n<code>{reg_link}</code>\n"
        )

    def build_main_keyboard(self) -> dict:
        return {
            "inline_keyboard": [
                [
                    {"text": "📊 Server Status", "callback_data": "cmd_status"},
                    {"text": "👥 List Clients", "callback_data": "cmd_list_clients"}
                ],
                [
                    {"text": "➕ Add Subscriber", "callback_data": "cmd_add_client"},
                    {"text": "🎮 Game Policies", "callback_data": "cmd_policies"}
                ],
                [
                    {"text": "🧹 Flush DNS Cache", "callback_data": "cmd_flush_cache"},
                    {"text": "🔄 Refresh", "callback_data": "cmd_refresh"}
                ]
            ]
        }

    def process_message(self, message: dict):
        chat_id = message.get("chat", {}).get("id")
        # Every command below is an admin action on the daemon; the allowlist is
        # the only thing standing between a stranger and the master API key.
        # Strangers are ignored rather than answered: a refusal confirms the bot
        # is live and worth harassing.
        if not self.is_authorized(chat_id):
            logger.warning("Ignoring command from unauthorized chat %r", chat_id)
            return

        text = message.get("text", "").strip()

        if text.startswith("/start"):
            welcome = (
                f"⚡ <b>Welcome to HyperDNS Controller Bot!</b>\n\n"
                f"Manage your SmartDNS high-speed proxy, subscribers, bandwidth quotas, "
                f"and game routing policies in real time.\n\n"
                f"Use the buttons below to interact with your HyperDNS engine:"
            )
            self.send_message(chat_id, welcome, self.build_main_keyboard())

        elif text.startswith("/status"):
            try:
                data = self.api.get_status()
                msg = self.format_status(data)
                self.send_message(chat_id, msg, self.build_main_keyboard())
            except Exception as e:
                self.send_message(chat_id, f"❌ Error querying status: {e}")

        elif text.startswith("/clients"):
            try:
                status_data = self.api.get_status()
                pub_ip = status_data.get("public_ip", "127.0.0.1")
                clients = self.api.list_clients()
                if not clients:
                    self.send_message(chat_id, "ℹ️ No registered clients found. Use /add to create one.")
                    return
                for c in clients[:5]: # Show first 5
                    self.send_message(chat_id, self.format_client_card(c, pub_ip))
            except Exception as e:
                self.send_message(chat_id, f"❌ Error listing clients: {e}")

        elif text.startswith("/add"):
            # Usage: /add <Name> [days] [limit_gb]
            parts = text.split()
            name = parts[1] if len(parts) > 1 else f"User_{int(time.time())%1000}"
            days = int(parts[2]) if len(parts) > 2 and parts[2].isdigit() else 30
            limit_gb = float(parts[3]) if len(parts) > 3 else 0.0

            try:
                c = self.api.create_client(name=name, days=days, traffic_gb=limit_gb)
                status_data = self.api.get_status()
                pub_ip = status_data.get("public_ip", "127.0.0.1")
                card = "✅ <b>Subscriber Created Successfully!</b>\n\n" + self.format_client_card(c, pub_ip)
                self.send_message(chat_id, card, self.build_main_keyboard())
            except Exception as e:
                self.send_message(chat_id, f"❌ Error creating client: {e}")

        elif text.startswith("/flush"):
            try:
                if self.api.flush_cache():
                    self.send_message(chat_id, "🧹 <b>DNS Cache successfully flushed across all 16 shards!</b>")
                else:
                    self.send_message(chat_id, "⚠️ Failed to flush cache.")
            except Exception as e:
                self.send_message(chat_id, f"❌ Error flushing cache: {e}")

    def run_poll_iteration(self):
        """Poll Telegram updates once (non-blocking testable loop)."""
        url = f"{self.api_url}/getUpdates?offset={self.last_update_id + 1}&timeout=1"
        try:
            r = requests.get(url, timeout=5)
            if r.status_code == 200:
                data = r.json()
                if data.get("ok"):
                    for update in data.get("result", []):
                        self.last_update_id = update.get("update_id", self.last_update_id)
                        if "message" in update:
                            self.process_message(update["message"])
        except Exception as e:
            logger.debug(f"Polling update error (expected if network isolated): {e}")

if __name__ == "__main__":
    token = require_env("TELEGRAM_BOT_TOKEN", TELEGRAM_BOT_TOKEN)
    api_key = require_env("HYPERDNS_API_KEY", HYPERDNS_API_KEY)
    # The allowlist is as much a credential as the token: without it the bot
    # would answer whoever messages it, and it answers with the master API key.
    admin_ids = parse_admin_chat_ids(require_env("TELEGRAM_ADMIN_CHAT_IDS", TELEGRAM_ADMIN_CHAT_IDS))
    if not admin_ids:
        sys.exit(
            "[FATAL] TELEGRAM_ADMIN_CHAT_IDS did not parse into any chat ID.\n"
            "        Set it to a comma-separated list of the chats allowed to\n"
            "        command the bot, e.g. export TELEGRAM_ADMIN_CHAT_IDS=123456789."
        )
    client = HyperDNSClient(HYPERDNS_API_BASE, api_key)
    bot = HyperDNSTelegramBot(token, client, admin_ids)
    logger.info("HyperDNS Telegram Bot Controller initialized successfully.")
    logger.info("Serving %d authorized chat(s); polling for updates.", len(admin_ids))
    # The loop is the bot: without it __main__ initialized and exited, and the
    # process was a very slow no-op.
    try:
        while True:
            bot.run_poll_iteration()
            time.sleep(1)
    except KeyboardInterrupt:
        logger.info("Shut down by operator.")
