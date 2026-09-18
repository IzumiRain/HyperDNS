#!/usr/bin/env bash
# ==============================================================================
# HyperDNS v1 → v2.2.0 MIGRATION SCRIPT
#
# Run this on a server that still carries an old HyperDNS 1.x install.
# It removes EVERY trace of the old install, then hands over to the v2.2.0
# offline installer sitting in the same directory as this script.
#
#   bash migrate-from-v1.sh [-y] [--no-backup]
#
#   -y            skip the typed confirmation (still safe: v1 data is
#                 archived to /root before anything is deleted, and an
#                 archive failure aborts the run)
#   --no-backup   do not archive the old install to /root (faster, and
#                 irreversible — the old database is NOT v2-compatible)
#
# What v1.x touched (swept here, learned from the v1.2 installers):
#   - systemd unit: /etc/systemd/system/hyperdns.service (+ any copy in
#     /usr/lib/systemd/system)
#   - systemd-resolved drop-in: /etc/systemd/resolved.conf.d/hyperdns.conf
#   - CLI: /usr/local/bin/hdns (+ /usr/bin/hdns, /usr/local/bin/hyperdns,
#     /usr/bin/hyperdns)
#   - install tree: /opt/hyperdns (binary, config.json, certs, backups, logs)
#   - extras a hand-run v1 may have left: /etc/hyperdns, /var/log/hyperdns,
#     cron lines mentioning hyperdns, still-running processes
#
# What it does NOT do:
#   - it does not migrate v1 data. v1's database format is not v2-compatible
#     (v2 is BoltDB with AES-256-GCM field sealing); subscribers must be
#     re-provisioned. The archive in /root is the only copy of the old data.
#   - it does not delete firewall rules (it prints any it finds, you decide).
# ==============================================================================

set -u

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'
say()  { printf "%b\n" "$1"; }
ok()   { printf "  ${GREEN}✓${NC} %b\n" "$1"; }
warn() { printf "  ${YELLOW}!${NC} %b\n" "$1"; }
step() { printf "\n${CYAN}${BOLD}[%s] %s${NC}\n" "$1" "$2"; }

ASSUME_YES=0
NO_BACKUP=0
for arg in "$@"; do
    case "$arg" in
        -y|--yes)      ASSUME_YES=1 ;;
        --no-backup)   NO_BACKUP=1 ;;
        *) say "${RED}unknown argument: $arg${NC}"; exit 1 ;;
    esac
done

if [ "$(id -u)" -ne 0 ]; then
    say "${RED}Error: run as root (or with sudo).${NC}"
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [ ! -f "${SCRIPT_DIR}/install.sh" ] || [ ! -f "${SCRIPT_DIR}/hyperdns" ]; then
    say "${RED}Error: install.sh and the hyperdns binary must sit next to this script.${NC}"
    say "Put this file inside the v2.2.0 offline bundle directory and run it from there."
    exit 1
fi

# ── What did this server actually carry? ─────────────────────────────────────
step "1/8" "Detecting the old install"

FOOTPRINT=()
systemctl list-unit-files 2>/dev/null | grep -qi '^hyperdns' \
    && FOOTPRINT+=("systemd unit: $(systemctl list-unit-files | grep -i '^hyperdns' | awk '{print $1}' | tr '\n' ' ')")
[ -f /etc/systemd/system/hyperdns.service ] && FOOTPRINT+=("/etc/systemd/system/hyperdns.service")
[ -f /usr/lib/systemd/system/hyperdns.service ] && FOOTPRINT+=("/usr/lib/systemd/system/hyperdns.service")
[ -f /etc/systemd/resolved.conf.d/hyperdns.conf ] && FOOTPRINT+=("systemd-resolved drop-in")
[ -d /opt/hyperdns ] && FOOTPRINT+=("/opt/hyperdns")
for cli in /usr/local/bin/hdns /usr/bin/hdns /usr/local/bin/hyperdns /usr/bin/hyperdns; do
    [ -e "$cli" ] && FOOTPRINT+=("$cli")
done
[ -d /etc/hyperdns ] && FOOTPRINT+=("/etc/hyperdns")
[ -d /var/log/hyperdns ] && FOOTPRINT+=("/var/log/hyperdns")
for f in $(grep -rls hyperdns /etc/cron.d /var/spool/cron/crontabs /var/spool/cron/root 2>/dev/null); do
    FOOTPRINT+=("cron: $f")
done
OLD_VERSION="unknown"
[ -x /opt/hyperdns/hyperdns ] && OLD_VERSION="$(/opt/hyperdns/hyperdns -version 2>/dev/null || echo 'unknown')"

if [ "${#FOOTPRINT[@]}" -eq 0 ]; then
    say "${YELLOW}No HyperDNS v1 footprint found on this server. Nothing to remove.${NC}"
    say "Jumping straight to the v2.2.0 installer."
else
    say "Found ${BOLD}${#FOOTPRINT[@]}${NC} traces of an old install (version: ${OLD_VERSION}):"
    for item in "${FOOTPRINT[@]}"; do say "  - $item"; done
fi

if pgrep -x hyperdns >/dev/null 2>&1; then
    warn "a hyperdns process is RUNNING right now:"
    pgrep -ax hyperdns | sed 's/^/    /'
fi

# ── Confirmation + archive ───────────────────────────────────────────────────
if [ "$ASSUME_YES" -ne 1 ]; then
    say ""
    say "${RED}${BOLD}This will DELETE every trace listed above and install HyperDNS v2.2.0.${NC}"
    say "The old database is NOT compatible with v2 — subscribers start from scratch."
    printf "%b" "${YELLOW}Type MIGRATE to continue: ${NC}"
    read -r CONFIRM
    [ "$CONFIRM" = "MIGRATE" ] || { say "${YELLOW}Cancelled. Nothing was modified.${NC}"; exit 0; }
fi

if [ "$NO_BACKUP" -ne 1 ]; then
    step "2/8" "Archiving the old install to /root"
    # Stop the daemon first: data.db is a BoltDB file the running service
    # writes continuously, and a tar taken mid-commit is not a consistent copy.
    systemctl stop hyperdns 2>/dev/null && ok "hyperdns service stopped for a consistent archive"
    pkill -x hyperdns 2>/dev/null && warn "leftover hyperdns processes killed" || true
    sleep 1
    # Archive EVERYTHING this script is about to delete — not just /opt: a
    # hand-maintained /etc/hyperdns or stray logs are irreversible losses too,
    # and the archive-then-delete contract has to cover the full deletion set.
    ARCHIVE="/root/hyperdns-v1-remnant-$(date +%Y%m%d_%H%M%S).tar.gz"
    tar czf "$ARCHIVE" -C / \
        $([ -d /opt/hyperdns ] && echo opt/hyperdns) \
        $([ -d /etc/hyperdns ] && echo etc/hyperdns) \
        $([ -d /var/log/hyperdns ] && echo var/log/hyperdns) \
        2>/dev/null || true
    if [ -s "$ARCHIVE" ]; then
        ok "archived to ${ARCHIVE} (keep it until the new install is verified)"
    else
        # The wipe below is irreversible; with no archive it must not run.
        say "${RED}ARCHIVE FAILED — ${ARCHIVE} is empty or missing (is /root full?).${NC}"
        say "${RED}The old install was NOT touched and will NOT be deleted. Re-run after freeing space.${NC}"
        exit 1
    fi
else
    systemctl stop hyperdns 2>/dev/null || true
    pkill -x hyperdns 2>/dev/null || true
fi

# ── Stop everything ──────────────────────────────────────────────────────────
step "3/8" "Stopping services and processes"
systemctl stop hyperdns 2>/dev/null    && ok "hyperdns service stopped"
systemctl disable hyperdns 2>/dev/null && ok "hyperdns service disabled"
pkill -x hyperdns 2>/dev/null && ok "leftover hyperdns processes killed" || true
sleep 1
pgrep -x hyperdns >/dev/null 2>&1 && { pkill -9 -x hyperdns 2>/dev/null || true; warn "had to force-kill"; } || ok "no hyperdns process left"

# ── Units ────────────────────────────────────────────────────────────────────
step "4/8" "Removing systemd units"
rm -f /etc/systemd/system/hyperdns.service
rm -f /usr/lib/systemd/system/hyperdns.service
systemctl daemon-reload 2>/dev/null || true
systemctl reset-failed hyperdns 2>/dev/null || true
ok "units removed, daemon reloaded"

# ── Resolver ─────────────────────────────────────────────────────────────────
step "5/8" "Restoring the system DNS resolver"
rm -f /etc/systemd/resolved.conf.d/hyperdns.conf
if systemctl is-active --quiet systemd-resolved 2>/dev/null; then
    systemctl restart systemd-resolved 2>/dev/null || true
    ok "systemd-resolved restarted on port 53"
else
    warn "systemd-resolved not active — if port 53 is still held, that is another resolver, check: ss -ulnp | grep :53"
fi

# ── Files ────────────────────────────────────────────────────────────────────
step "6/8" "Removing binaries, CLI links, configs and logs"
rm -rf /opt/hyperdns                 && ok "/opt/hyperdns removed"
rm -rf /etc/hyperdns 2>/dev/null     && ok "/etc/hyperdns removed"
rm -rf /var/log/hyperdns 2>/dev/null && ok "/var/log/hyperdns removed"
for cli in /usr/local/bin/hdns /usr/bin/hdns /usr/local/bin/hyperdns /usr/bin/hyperdns; do
    rm -f "$cli"
done
ok "hdns / hyperdns CLI links removed"

# cron lines that reference hyperdns (v1 never installed any, but a hand-run may have)
for f in /etc/cron.d/hyperdns /var/spool/cron/root /var/spool/cron/crontabs/root; do
    if [ -f "$f" ] && grep -q hyperdns "$f" 2>/dev/null; then
        sed -i '/hyperdns/d' "$f" && ok "hyperdns cron lines removed from $f"
    fi
done

# ── Verification ─────────────────────────────────────────────────────────────
step "7/8" "Verifying the sweep"
LEFT=0
systemctl is-active --quiet hyperdns 2>/dev/null && { warn "hyperdns service STILL ACTIVE"; LEFT=1; }
[ -d /opt/hyperdns ] && { warn "/opt/hyperdns still present"; LEFT=1; }
for cli in /usr/local/bin/hdns /usr/bin/hdns /usr/local/bin/hyperdns /usr/bin/hyperdns; do
    [ -e "$cli" ] && { warn "$cli still present"; LEFT=1; }
done
pgrep -x hyperdns >/dev/null 2>&1 && { warn "a hyperdns process is still alive"; LEFT=1; }
if [ "$LEFT" -eq 0 ]; then
    ok "no hyperdns trace left on the system"
fi

# Firewall rules are printed, not deleted — the operator decides.
if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -qiE 'active'; then
    RULES="$(ufw status 2>/dev/null | grep -E '^(53|80|443|853|8443)(/tcp)? ' || true)"
    [ -n "$RULES" ] && { say ""; warn "ufw rules for the HyperDNS ports (left in place, remove by hand if unwanted):"; echo "$RULES" | sed 's/^/    /'; }
fi

# ── Install v2.2.0 ───────────────────────────────────────────────────────────
step "8/8" "Installing HyperDNS v2.2.0"
cd "$SCRIPT_DIR" || exit 1
chmod +x install.sh hyperdns 2>/dev/null || true
say "Handing over to the v2.2.0 installer (it asks for the panel domain —"
say "HTTPS is mandatory and the daemon issues its own certificate)."
say ""
exec bash ./install.sh
