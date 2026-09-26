#!/usr/bin/env bash
# ==============================================================================
# HyperDNS — 100% Offline Standalone Installer
# Works with ZERO internet connection using pre-packaged binary & assets.
# Supported OS: Ubuntu 20.04+, Debian 11+, CentOS/RHEL/Alma/Rocky 8+
# ==============================================================================

set -e

# Terminal Colors & Styling
RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
PURPLE='\033[0;35m'
BOLD='\033[1m'
NC='\033[0m'

# Clear screen & display Cyberpunk ASCII Banner.
# Guarded because this script runs under `set -e` and clear exits non-zero when
# TERM is unset or unknown to terminfo -- which is exactly the case for
# `ssh host 'bash install.sh'`, cron, CI and setsid, none of which allocate a
# terminal. Unguarded, the offline installer died on line 20 with
# "TERM environment variable not set." and installed nothing.
clear 2>/dev/null || true
echo -e "${CYAN}${BOLD}"
echo "  ██╗  ██╗██╗   ██╗██████╗ ███████╗██████╗ ██████╗ ███╗   ██╗███████╗"
echo "  ██║  ██║╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗██╔══██╗████╗  ██║██╔════╝"
echo "  ███████║ ╚████╔╝ ██████╔╝█████╗  ██████╔╝██║  ██║██╔██╗ ██║███████╗"
echo "  ██╔══██║  ╚██╔╝  ██╔═══╝ ██╔══╝  ██╔══██╗██║  ██║██║╚██╗██║╚════██║"
echo "  ██║  ██║   ██║   ██║     ███████╗██║  ██║██████╔╝██║ ╚████║███████║"
echo "  ╚═╝  ╚═╝   ╚═╝   ╚═╝     ╚══════╝╚═╝  ╚═╝╚═════╝ ╚═╝  ╚═══╝╚══════╝"
echo -e "       ${PURPLE}⚡ Standalone Low-Latency SmartDNS & Anti-Sanction Gaming Gateway ⚡${NC}"
echo -e "       ${YELLOW}Package: 100% OFFLINE INSTALLER · Single Binary · Go 1.26 · OWASP Hardened${NC}"
echo ""

if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}[Error] Please run this installer as root (or use sudo).${NC}"
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_DIR="/opt/hyperdns"

# ==============================================================================
# PUBLIC IP DETECTION (used by the domain prompt and the closing banner)
# ==============================================================================
# Detected once, up front. It used to be fetched after the banner — which is
# why the domain prompt printed "Point an A record at  first" with an empty
# address: the prompt runs in step 4 and the variable did not exist yet.
PUBLIC_IP=""
for _ip_ep in https://api.ipify.org https://ifconfig.me/ip https://icanhazip.com https://checkip.amazonaws.com; do
    _ip_val=$(curl -fsS --connect-timeout 3 --max-time 5 "${_ip_ep}" 2>/dev/null | tr -d '[:space:]')
    if [ -n "${_ip_val}" ]; then
        PUBLIC_IP="${_ip_val}"
        break
    fi
done
if [ -z "${PUBLIC_IP}" ]; then
    PUBLIC_IP=$(hostname -I 2>/dev/null | awk '{print $1}')
fi
if [ -z "${PUBLIC_IP}" ]; then
    PUBLIC_IP="YOUR_SERVER_IP"
fi

# Detection is unreliable on NAT'd VPSes (Iran-routed boxes report an
# Azerbaijan/UAE address), and offline there is often no echo service to ask at
# all — hostname -I returns the private LAN address. Let the operator set the
# real public IP; it is written into config.json's public_ip so the daemon uses
# it verbatim instead of auto-detecting the wrong one. HYPERDNS_PUBLIC_IP
# overrides non-interactively.
validate_ip() {
    case "$1" in
        *[!0-9.:a-fA-F]* | "" ) return 1 ;;
    esac
    case "$1" in
        *.*.*.* | *:* ) return 0 ;;
        * ) return 1 ;;
    esac
}
PUBLIC_IP_MANUAL=0
if [ -n "${HYPERDNS_PUBLIC_IP:-}" ]; then
    if validate_ip "${HYPERDNS_PUBLIC_IP}"; then
        PUBLIC_IP="${HYPERDNS_PUBLIC_IP}"; PUBLIC_IP_MANUAL=1
        echo -e "  ${CYAN}Using HYPERDNS_PUBLIC_IP=${PUBLIC_IP} (manual override).${NC}"
    else
        echo -e "  ${RED}HYPERDNS_PUBLIC_IP='${HYPERDNS_PUBLIC_IP}' is not a valid IP address; ignoring it.${NC}"
    fi
elif [ -t 0 ] || (exec </dev/tty) 2>/dev/null; then
    _ip_reply=""
    printf "%b" "${YELLOW}Detected public IP: ${BOLD}${PUBLIC_IP}${NC}${YELLOW}. If your VPS is NAT'd and its real public IP differs, type it now; otherwise press Enter to accept: ${NC}" >&2
    if [ -t 0 ]; then read -r _ip_reply || _ip_reply=""; else read -r _ip_reply </dev/tty 2>/dev/null || _ip_reply=""; fi
    if [ -n "${_ip_reply}" ]; then
        if validate_ip "${_ip_reply}"; then
            PUBLIC_IP="${_ip_reply}"; PUBLIC_IP_MANUAL=1
            echo -e "  ${GREEN}Using ${PUBLIC_IP} as the server's public IP.${NC}"
        else
            echo -e "  ${RED}'${_ip_reply}' is not a valid IP address; keeping ${PUBLIC_IP}.${NC}"
        fi
    fi
fi

# Domain validation. The value is fed to sed against config.json, so a name
# with a slash or ampersand in it corrupts the expression instead of failing;
# it is also what the certificate is issued for. Anything that is not
# a bare hostname is rejected before any of that happens.
validate_domain() {
    case "$1" in
        *[!a-zA-Z0-9.-]* | .* | *. | *..* | -* | "" ) return 1 ;;
    esac
    case "$1" in
        *.*) return 0 ;;
        *)   return 1 ;;
    esac
}

# ==============================================================================
# STEP 1: LOCATE OFFLINE BINARY
# ==============================================================================
echo -e "${CYAN}${BOLD}[1/6] Verifying Offline Package Integrity...${NC}"

SRC_BIN=""
if [ -f "${SCRIPT_DIR}/hyperdns" ]; then
    SRC_BIN="${SCRIPT_DIR}/hyperdns"
elif [ -f "${SCRIPT_DIR}/hyperdns-linux" ]; then
    SRC_BIN="${SCRIPT_DIR}/hyperdns-linux"
elif [ -f "./hyperdns" ]; then
    SRC_BIN="./hyperdns"
elif [ -f "./hyperdns-linux" ]; then
    SRC_BIN="./hyperdns-linux"
fi

if [ -z "${SRC_BIN}" ]; then
    echo -e "${RED}[Error] Offline binary 'hyperdns' not found in current directory!${NC}"
    echo -e "Please ensure you have extracted all files from the offline package."
    exit 1
fi

echo -e "  ${GREEN}✓ Found offline binary: ${SRC_BIN}${NC}"

install -d -o root -g root -m 0755 "${INSTALL_DIR}"
install -d -o root -g root -m 0700 "${INSTALL_DIR}/certs"

# ==============================================================================
# SAFE INSTALL: every run of this installer produces a completely fresh
# install. An existing installation is archived to /root (that archive is the
# only copy of the old data — the old database is not v2-compatible), then
# REPLACED, and every step below runs from the beginning: fresh config, fresh
# credentials, fresh admin path, fresh certificates. No upgrade path, no
# half-migrated state — that is what "safe" means here: the installer can
# never leave an old record behind to drift.
# ==============================================================================
IS_UPGRADE=false
PREV_VERSION=""

if [ -f "${INSTALL_DIR}/hyperdns" ] || [ -f "${INSTALL_DIR}/config.json" ] || [ -f "${INSTALL_DIR}/data.db" ] || [ -f "${INSTALL_DIR}/master.key" ] || systemctl is-active --quiet hyperdns 2>/dev/null || systemctl is-enabled --quiet hyperdns 2>/dev/null; then
    IS_UPGRADE=true
    if [ -x "${INSTALL_DIR}/hyperdns" ]; then
        PREV_VERSION="$("${INSTALL_DIR}/hyperdns" -version 2>/dev/null | head -n1 || true)"
    fi
    [ -z "${PREV_VERSION}" ] && PREV_VERSION="unknown (pre-2.2.0)"

    echo -e "${YELLOW}${BOLD}\u250c${NC}"
    echo -e "${YELLOW}│ SAFE INSTALL — an existing HyperDNS installation was detected${NC}"
    echo -e "${YELLOW}│ • Installed Version : ${CYAN}${PREV_VERSION}${NC}"
    echo -e "${YELLOW}│ • Target Version    : ${GREEN}v2.2.0 (this package)${NC}"
    echo -e "${YELLOW}│ • Mode              : ${GREEN}Fresh install — old data ARCHIVED, then REPLACED${NC}"
    echo -e "${YELLOW}\u2514${NC}"
    echo ""

    # Archive the WHOLE install tree to /root — outside /opt/hyperdns, so it
    # survives the wipe below. data.db + master.key + config.json + certs are
    # one unit; the archive keeps them together. 600 on the archive: it holds
    # master.key and plaintext credentials.
    if systemctl is-active --quiet hyperdns 2>/dev/null; then
        echo -e "  ${CYAN}Gracefully stopping the running service...${NC}"
        systemctl stop hyperdns || true
    fi

    ARCHIVE="/root/hyperdns-preinstall-$(date +%Y%m%d_%H%M%S).tar.gz"
    tar czf "${ARCHIVE}" -C / opt/hyperdns 2>/dev/null || true
    chmod 600 "${ARCHIVE}" 2>/dev/null || true
    if [ -s "${ARCHIVE}" ]; then
        echo -e "  ${GREEN}\u2713 Previous install archived to: ${ARCHIVE}${NC}"
        echo -e "  ${GREEN}  archive sha256: $(sha256sum "${ARCHIVE}" | awk '{print $1}')${NC}"
        echo -e "  ${YELLOW}  This is the ONLY copy of the old data once this installer finishes.${NC}"
    else
        echo -e "  ${RED}✗ ARCHIVE FAILED — ${ARCHIVE} is empty or missing.${NC}"
        echo -e "  ${RED}  The old install was NOT touched and will NOT be wiped.${NC}"
        echo -e "  ${RED}  Free space in /root (or investigate the tar error) and re-run.${NC}"
        exit 1
    fi

    # The wipe is destructive and must never happen silently: an interactive
    # run types FRESH, an unattended run (piped stdin) sets HYPERDNS_FRESH=1.
    if [ "${HYPERDNS_FRESH:-0}" = "1" ]; then
        echo -e "  ${CYAN}HYPERDNS_FRESH=1 — wipe confirmed by environment.${NC}"
    elif [ -t 0 ]; then
        printf "%b" "${YELLOW}Type ${RED}FRESH${YELLOW} to wipe the existing install and reinstall: ${NC}"
        read -r CONFIRM
        [ "${CONFIRM}" = "FRESH" ] || { echo -e "  ${YELLOW}Cancelled — the existing install is untouched (archive kept).${NC}"; exit 0; }
    else
        echo -e "  ${RED}\u2717 Non-interactive run detected and HYPERDNS_FRESH=1 is not set.${NC}"
        echo -e "  ${RED}  Refusing to wipe an existing install silently. Re-run with:${NC}"
        echo -e "  ${RED}    HYPERDNS_FRESH=1 bash install.sh${NC}"
        exit 1
    fi

    rm -rf "${INSTALL_DIR}"
    echo -e "  ${GREEN}\u2713 Previous install fully removed — installing from scratch${NC}"
fi

# The wipe above may have taken the whole tree with it; the directories the
# rest of this script writes into must exist either way.
install -d -o root -g root -m 0755 "${INSTALL_DIR}"
install -d -o root -g root -m 0700 "${INSTALL_DIR}/certs"

# Copy binary atomically
cp -f "${SRC_BIN}" "${INSTALL_DIR}/hyperdns.new"
chmod +x "${INSTALL_DIR}/hyperdns.new"
mv -f "${INSTALL_DIR}/hyperdns.new" "${INSTALL_DIR}/hyperdns"
ln -sf "${INSTALL_DIR}/hyperdns" /usr/local/bin/hdns


install -d -o root -g root -m 0755 "${INSTALL_DIR}/scripts"
# v2.2.0: ssl_issue.sh no longer ships. The daemon issues its own certificate
# (embedded ACME client) at first start and renews daily — there is no
# stop-the-service issuance step for an operator to run by hand either.

if [ -f "${SCRIPT_DIR}/scripts/uninstall.sh" ]; then
    cp -f "${SCRIPT_DIR}/scripts/uninstall.sh" "${INSTALL_DIR}/scripts/uninstall.sh"
    chmod +x "${INSTALL_DIR}/scripts/uninstall.sh"
elif [ -f "./scripts/uninstall.sh" ]; then
    cp -f ./scripts/uninstall.sh "${INSTALL_DIR}/scripts/uninstall.sh"
    chmod +x "${INSTALL_DIR}/scripts/uninstall.sh"
fi

for candidate in "${SCRIPT_DIR}/scripts/restore.sh" "./scripts/restore.sh"; do
    if [ -f "${candidate}" ]; then
        install -o root -g root -m 0755 "${candidate}" "${INSTALL_DIR}/scripts/restore.sh"
        break
    fi
done

# Ship version.json so the binary's startup drift check has a matching file
if [ -f "${SCRIPT_DIR}/version.json" ]; then
    cp -f "${SCRIPT_DIR}/version.json" "${INSTALL_DIR}/version.json"
elif [ -f "./version.json" ]; then
    cp -f ./version.json "${INSTALL_DIR}/version.json"
fi

# Provide a starting config on a fresh install (used as defaults by -config)
FRESH_CONFIG_SOURCE=""
if [ ! -f "${INSTALL_DIR}/config.json" ] && [ -f "${SCRIPT_DIR}/config.example.json" ]; then
    FRESH_CONFIG_SOURCE="${SCRIPT_DIR}/config.example.json"
elif [ ! -f "${INSTALL_DIR}/config.json" ] && [ -f "./config.example.json" ]; then
    FRESH_CONFIG_SOURCE="./config.example.json"
fi

if [ -n "${FRESH_CONFIG_SOURCE}" ]; then
    cp -f "${FRESH_CONFIG_SOURCE}" "${INSTALL_DIR}/config.json"

    # config.example.json is a public template, so its placeholder credentials are
    # public too. Replace them with per-install random values before the daemon
    # ever reads the file. The password is printed once in the closing banner.
    # Both values are hex-only, so they are safe inside the sed replacement.
    GENERATED_ADMIN_PASSWORD="$(openssl rand -hex 12 2>/dev/null || tr -dc 'a-f0-9' < /dev/urandom | head -c 24)"
    GENERATED_API_KEY="hdns_live_$(openssl rand -hex 16 2>/dev/null || tr -dc 'a-f0-9' < /dev/urandom | head -c 32)"
    sed -i "s|\"admin_password\": \"[^\"]*\"|\"admin_password\": \"${GENERATED_ADMIN_PASSWORD}\"|" "${INSTALL_DIR}/config.json"
    sed -i "s|\"api_key\": \"[^\"]*\"|\"api_key\": \"${GENERATED_API_KEY}\"|" "${INSTALL_DIR}/config.json"

    # Pin the confirmed public IP so the daemon uses it verbatim instead of
    # auto-detecting (the NAT/offline misdetection this prompt exists to fix).
    if [ "${PUBLIC_IP}" != "YOUR_SERVER_IP" ] && validate_ip "${PUBLIC_IP}"; then
        sed -i "s|\"public_ip\": \"[^\"]*\"|\"public_ip\": \"${PUBLIC_IP}\"|" "${INSTALL_DIR}/config.json"
    fi

    # v2.2.0: a random management (panel) port for fresh installs. 8080 is
    # everyone's default — panels, dev servers, proxies — and the dashboard
    # landing on it collides with whatever the operator already runs far more
    # often than chance. A random high port, drawn once here and written into
    # the fresh config, sidesteps the whole class; the standard data-plane
    # ports (53/80/443/853) stay exactly where the protocols say they are.
    # Every install takes this branch now: a safe install always generates
    # a fresh config, so every install also draws a fresh panel port.
    PANEL_PORT="$(shuf -i 20000-60000 -n 1 2>/dev/null || awk 'BEGIN{srand();print int(20000+rand()*40000)}')"
    # Avoid the handful of high ports with common occupants: nothing exotic,
    # just the ones a default VPS image tends to run.
    for _busy in 27017 3306 5432 6379 8080 8443 9000 10000; do
        if [ "${PANEL_PORT}" = "${_busy}" ]; then PANEL_PORT=28443; break; fi
    done
    sed -i "s|\"web_port\": [0-9]*|\"web_port\": ${PANEL_PORT}|" "${INSTALL_DIR}/config.json"
    echo -e "  ${CYAN}Panel management port for this install: ${BOLD}${PANEL_PORT}${NC}"

    if grep -q 'CHANGE-ME-BEFORE-FIRST-RUN' "${INSTALL_DIR}/config.json"; then
        # sed did not take. Warn loudly rather than silently shipping the public
        # placeholder as a working login.
        GENERATED_ADMIN_PASSWORD=""
        echo -e "  ${RED}✗ Could not inject a per-install admin password.${NC}"
        echo -e "  ${YELLOW}    Set server.admin_password in ${INSTALL_DIR}/config.json before exposing the dashboard.${NC}"
    else
        echo -e "  ${GREEN}✓ Fresh config created at ${INSTALL_DIR}/config.json with per-install credentials${NC}"
    fi
fi

# config.json holds server.admin_password and server.api_key in plaintext, so it must
# not be world-readable. `cp -f` above inherits 644 from config.example.json, which is a
# public template and rightly readable, and the copy then keeps that mode through both
# sed passes. This runs outside the fresh-config branch on purpose: a box installed
# before this line still has a 644 file on disk, and an upgrade is the only run that can
# repair it. Guarded by -f because a migration that bailed out leaves the file exactly as
# it found it, and chmod on a missing path is not worth aborting for.
if [ -f "${INSTALL_DIR}/config.json" ]; then
    chmod 600 "${INSTALL_DIR}/config.json" 2>/dev/null || true
fi

# On an upgrade the fresh-config block did not run; if the operator supplied the
# public IP by hand, write it into the existing config so the daemon stops
# auto-detecting the wrong (NAT) address.
if [ "${PUBLIC_IP_MANUAL:-0}" = "1" ] && [ -f "${INSTALL_DIR}/config.json" ]; then
    sed -i "s|\"public_ip\": \"[^\"]*\"|\"public_ip\": \"${PUBLIC_IP}\"|" "${INSTALL_DIR}/config.json"
    echo -e "  ${GREEN}✓ Wrote public IP ${PUBLIC_IP} into config.json${NC}"
fi

echo -e "  ${GREEN}✓ Binary installed to ${INSTALL_DIR}/hyperdns${NC}"
echo -e "  ${GREEN}✓ Global CLI command installed: 'hdns'${NC}"

# ==============================================================================
# STEP 2: RESOLVE PORT 53 CONFLICTS (SYSTEMD-RESOLVED)
# ==============================================================================
echo -e "${CYAN}${BOLD}[2/6] Freeing Port 53 (systemd-resolved resolver)...${NC}"
if systemctl is-active --quiet systemd-resolved; then
    echo -e "  ${YELLOW}Configuring systemd-resolved to release port 53 listener...${NC}"
    mkdir -p /etc/systemd/resolved.conf.d/
    cat << 'EOF' > /etc/systemd/resolved.conf.d/hyperdns.conf
[Resolve]
DNSStubListener=no
EOF
    # systemd-resolved runs as its own unprivileged user, so a drop-in written
    # under a restrictive caller umask (077) is unreadable by it, silently
    # ignored, and the stub listener stays on 127.0.0.53:53 — the daemon then
    # fails to bind port 53 over a conflict the installer was asked to clear.
    chmod 755 /etc/systemd/resolved.conf.d
    chmod 644 /etc/systemd/resolved.conf.d/hyperdns.conf
    systemctl restart systemd-resolved || true

    # /etc/resolv.conf is a symlink to /run/systemd/resolve/stub-resolv.conf on a stock
    # Ubuntu, and every nameserver in that file is 127.0.0.53 — the address of the stub
    # listener just disabled. It has to be repointed or the host stops resolving names.
    #
    # Redirecting into the symlink would follow it and rewrite resolved's own generated
    # file, which resolved regenerates on the next restart, so the link itself is replaced.
    # The marker records what was there beforehand; scripts/uninstall.sh reads it to put
    # the original resolver back.
    RESOLV_MARKER="${INSTALL_DIR}/.resolv-backup"
    if [ ! -f "${RESOLV_MARKER}" ]; then
        if [ -L /etc/resolv.conf ]; then
            printf 'symlink\n%s\n' "$(readlink /etc/resolv.conf)" > "${RESOLV_MARKER}"
        elif [ -f /etc/resolv.conf ]; then
            { printf 'file\n'; cat /etc/resolv.conf; } > "${RESOLV_MARKER}"
        else
            printf 'absent\n' > "${RESOLV_MARKER}"
        fi
        chmod 600 "${RESOLV_MARKER}" 2>/dev/null || true
    fi
    rm -f /etc/resolv.conf
    printf 'nameserver 1.1.1.1\nnameserver 8.8.8.8\noptions timeout:2 attempts:2\n' > /etc/resolv.conf
    echo -e "  ${GREEN}✓ Port 53 released successfully!${NC}"
    echo -e "  ${CYAN}  Previous resolver configuration recorded for uninstall.${NC}"
else
    echo -e "  ${GREEN}✓ Port 53 is clear.${NC}"
fi

# ==============================================================================
# STEP 3: FIREWALL RULES CONFIGURATION
# ==============================================================================
echo -e "${CYAN}${BOLD}[3/6] Configuring Firewall Rules for Gaming & DNS...${NC}"
PORTS=(53 80 443 853 2099 5222 5223 8393 8443)
# The panel's port joins the fixed set when this install chose one at random
# (v2.2.0). An upgrade with no PANEL_PORT (or the default 8080, already in the
# installed set from before) adds nothing. The rule is recorded like the
# others, so the uninstaller removes exactly what it opened.
if [ -n "${PANEL_PORT:-}" ] && [ "${PANEL_PORT}" != "8080" ]; then
    PORTS+=("${PANEL_PORT}")
fi

# Every rule this step creates is recorded, and the uninstaller removes only what it finds
# recorded. Closing all ten unconditionally on uninstall would take down whatever was
# already listening on 80, 443 or 8080 before HyperDNS was installed here.
FIREWALL_MARKER="${INSTALL_DIR}/.firewall-backup"

if command -v ufw >/dev/null 2>&1; then
    # `ufw status` is the wrong question, and it fails in the state that is by far the
    # most common: on a stock Ubuntu box ufw is installed but inactive, and while it is
    # inactive `ufw status` prints "Status: inactive" and nothing else — no rules at all.
    # The guard that used to be here grepped that output, so it could never match. Every
    # port looked new on every run, each install re-recorded all ten, and — the part that
    # actually hurts — a port the operator had opened themselves was invisible to it, got
    # recorded as ours, and was then closed by the uninstaller: exactly the outcome the
    # comment above promises will not happen.
    #
    # `ufw show added` prints the rule definitions whether or not the firewall is running,
    # in the same "ufw allow <spec>" form used to create them, so one snapshot taken before
    # the loop is enough to tell someone else's rule from the ones opened here.
    UFW_ADDED="$(ufw show added 2>/dev/null || true)"
    for p in "${PORTS[@]}"; do
        # Only an exact match counts as "already allowed". ufw keeps "allow 53" and
        # "allow 53/tcp" as two separate rules, and `ufw delete allow 53` removes just the
        # bare one, so adding the bare form alongside an operator's proto-qualified rule is
        # safe — the delete on uninstall cannot reach theirs. Skipping on a partial match
        # would be the unsafe choice: a host with only 53/tcp allowed would never get
        # 53/udp, and the resolver would go deaf the moment the operator enables ufw.
        if printf '%s\n' "${UFW_ADDED}" | grep -qxF "ufw allow ${p}"; then
            continue
        fi
        if ufw allow "${p}" >/dev/null 2>&1; then
            # `ufw allow` on a rule that already exists prints "Skipping adding existing
            # rule" and still exits 0, so a repeat install must not read that as licence to
            # append a second identical line. The uninstaller would then run the same delete
            # twice and report double the rules it really removed.
            if ! grep -qxF "ufw ${p}" "${FIREWALL_MARKER}" 2>/dev/null; then
                echo "ufw ${p}" >> "${FIREWALL_MARKER}"
            fi
        fi
    done
    echo -e "  ${GREEN}✓ UFW firewall rules configured for all gaming & DNS ports.${NC}"
elif command -v firewall-cmd >/dev/null 2>&1; then
    # No equivalent fix is needed here: --query-port reads the permanent configuration
    # directly and answers correctly whether or not firewalld is running, so a port the
    # operator already opened is seen, skipped, and never recorded as ours.
    for p in "${PORTS[@]}"; do
        for proto in tcp udp; do
            if firewall-cmd --permanent --query-port="${p}/${proto}" >/dev/null 2>&1; then
                continue
            fi
            if firewall-cmd --permanent --add-port="${p}/${proto}" >/dev/null 2>&1; then
                echo "firewalld ${p}/${proto}" >> "${FIREWALL_MARKER}"
            fi
        done
    done
    firewall-cmd --reload >/dev/null 2>&1 || true
    echo -e "  ${GREEN}✓ Firewalld rules configured.${NC}"
else
    echo -e "  ${YELLOW}No active firewall detected (skipping).${NC}"
fi

# ==============================================================================
# STEP 4: DOMAIN & SSL (HTTPS) CONFIGURATION PROMPT
# ==============================================================================
echo ""
echo -e "${CYAN}${BOLD}[4/6] Domain & HTTPS Security Setup...${NC}"
echo -e "${YELLOW}┌────────────────────────────────────────────────────────────────────────┐${NC}"
echo -e "${YELLOW}│ A panel domain with HTTPS is REQUIRED (Let's Encrypt).                 │${NC}"
echo -e "${YELLOW}│ The dashboard is NOT reachable as a bare IP over plain HTTP.           │${NC}"
echo -e "${YELLOW}└────────────────────────────────────────────────────────────────────────┘${NC}"

# Helper for reading user input cleanly in piped or interactive bash.
# Order: real terminal → /dev/tty → plain stdin. The plain-stdin fallback is
# what keeps `curl | bash` and other non-tty runs from looping forever on a
# mandatory question: without it, every read returns "" and a required-input
# while-loop spins eternally (the exact failure seen in the field).
ask_user() {
    local prompt_msg="$1"
    local default_val="$2"
    local user_var=""

    printf "%b" "${prompt_msg}" >&2
    if [ -t 0 ]; then
        read -r user_var || user_var=""
    elif (exec </dev/tty) 2>/dev/null; then
        read -r user_var </dev/tty 2>/dev/null || user_var=""
    else
        read -r user_var || user_var=""
    fi

    if [ -z "${user_var}" ]; then
        echo "${default_val}"
    else
        echo "${user_var}"
    fi
}

USER_DOMAIN=""
USER_EMAIL=""
IS_HTTPS=false

# Panel exposure policy (mandatory): the dashboard is an admin surface and is
# never served as a bare IP over plain HTTP. A domain + Let's Encrypt is
# REQUIRED; the installer loops until a domain is provided. Skipping is not
# offered (v2.2.0 installer contract).
#
# The existing config's domain is offered as the default so an upgrade only
# needs Enter, and HYPERDNS_DOMAIN covers every shell with no terminal — an
# offline bundle is often run from a provisioning script.
EXISTING_DOMAIN=""
if [ -f "${INSTALL_DIR}/config.json" ]; then
    EXISTING_DOMAIN=$(sed -n 's/.*"domain":[[:space:]]*"\([^"]*\)".*/\1/p' "${INSTALL_DIR}/config.json" | head -1)
fi

echo ""
echo -e "${BOLD}${YELLOW}Panel domain + HTTPS is REQUIRED.${NC}"
echo -e "${YELLOW}The dashboard will NOT be reachable as a bare IP over plain HTTP.${NC}"
echo -e "${YELLOW}Point an A record at ${PUBLIC_IP} first, then enter the domain.${NC}"
echo ""

if [ -n "${HYPERDNS_DOMAIN:-}" ]; then
    if validate_domain "${HYPERDNS_DOMAIN}"; then
        USER_DOMAIN="${HYPERDNS_DOMAIN}"
        echo -e "  ${GREEN}✓ Using domain from HYPERDNS_DOMAIN: ${USER_DOMAIN}${NC}"
    else
        echo -e "${RED}[Error] HYPERDNS_DOMAIN='${HYPERDNS_DOMAIN}' is not a valid hostname.${NC}" >&2
        echo -e "${YELLOW}Expected a bare name such as dns.example.com -- no scheme, port or path.${NC}" >&2
        exit 1
    fi
else
    _askTries=0
    while [ -z "$USER_DOMAIN" ]; do
        _askTries=$((_askTries + 1))
        if [ "$_askTries" -gt 5 ]; then
            echo -e "${RED}[Error] No panel domain provided after 5 attempts.${NC}" >&2
            echo -e "${YELLOW}The panel cannot run without a domain (HTTPS is mandatory).${NC}" >&2
            echo -e "${YELLOW}Point an A record at this server, then re-run: sudo ./install.sh${NC}" >&2
            exit 1
        fi
        _default=""
        [ -n "${EXISTING_DOMAIN}" ] && _default="${EXISTING_DOMAIN}"
        USER_DOMAIN=$(ask_user " ${BOLD}${CYAN}? Panel domain (A record -> ${PUBLIC_IP}) e.g. dns.example.com${_default:+ [$_default]}: ${NC}" "${_default}")
        if [ -z "$USER_DOMAIN" ]; then
            echo -e "${RED}  A domain is required to continue. The panel cannot run on HTTP/IP.${NC}"
        elif ! validate_domain "$USER_DOMAIN"; then
            echo -e "${RED}  '${USER_DOMAIN}' is not a valid hostname.${NC}"
            echo -e "${YELLOW}  Enter a bare name such as dns.example.com -- no https://, no port, no path.${NC}"
            USER_DOMAIN=""
        fi
    done
fi
USER_EMAIL="${HYPERDNS_EMAIL:-}"
if [ -z "${USER_EMAIL}" ]; then
    USER_EMAIL=$(ask_user " ${BOLD}${CYAN}? Admin email for Let's Encrypt (optional, press Enter to skip): ${NC}" "")
fi

if [ -f "${INSTALL_DIR}/config.json" ]; then
    sed -i "s/\"domain\": .*/\"domain\": \"${USER_DOMAIN}\",/" "${INSTALL_DIR}/config.json" || true
    sed -i "s/\"email\": .*/\"email\": \"${USER_EMAIL}\",/" "${INSTALL_DIR}/config.json" || true
    sed -i "s/\"auto_cert\": .*/\"auto_cert\": true,/" "${INSTALL_DIR}/config.json" || true
fi
IS_HTTPS=true
echo -e "  ${GREEN}? Custom domain '${USER_DOMAIN}' configured with HTTPS (mandatory).${NC}"

# ==============================================================================
# STEP 4b: CERTIFICATE — ISSUED BY THE DAEMON AT FIRST START (v2.2.0)
# ==============================================================================
# The installer contract is an HTTPS-only panel, and the daemon refuses to
# serve a self-signed fallback on a configured domain. v2.1 met that contract
# by running acme.sh here, before the service started — because a standalone
# client needs port 80 free, which the daemon's own SNI proxy would take.
#
# v2.2.0 removes that whole dance: the daemon carries its own ACME client
# (embedded in the binary — nothing to install, works on an offline host the
# moment it has internet) and serves the HTTP-01 challenge out of its own
# running port-80 listener. Issuance therefore happens at first start, in
# StartACMEIfNeeded, and renews itself daily from then on. This step is now
# only the DNS propagation pre-check, so the operator learns about a missing
# A record NOW rather than from a daemon that fail-closed at boot.
echo ""
echo -e "${CYAN}${BOLD}[4b/6] Verifying DNS for ${USER_DOMAIN} (the daemon issues its certificate at first start)...${NC}"
if command -v dig >/dev/null 2>&1; then
    _resolved=$(dig +short "${USER_DOMAIN}" A 2>/dev/null | tail -1)
    if [ -n "${_resolved}" ] && [ "${_resolved}" != "${PUBLIC_IP}" ]; then
        echo -e "${YELLOW}  Note: ${USER_DOMAIN} currently resolves to ${_resolved}, not ${PUBLIC_IP}.${NC}"
        echo -e "${YELLOW}  The certificate cannot be issued until the A record points here; the daemon will keep retrying daily.${NC}"
    elif [ -z "${_resolved}" ]; then
        echo -e "${YELLOW}  Note: no A record found yet for ${USER_DOMAIN}.${NC}"
        echo -e "${YELLOW}  Point it at ${PUBLIC_IP}; the daemon issues the certificate on its next start or daily retry.${NC}"
    else
        echo -e "  ${GREEN}✓ ${USER_DOMAIN} resolves to ${PUBLIC_IP}.${NC}"
    fi
else
    echo -e "${YELLOW}  dig not available — skipping the A-record check. The daemon will verify at issuance time.${NC}"
fi

# ==============================================================================
# STEP 5: SYSTEMD SERVICE SETUP
# ==============================================================================
echo -e "${CYAN}${BOLD}[5/6] Creating & Starting Systemd Background Service...${NC}"
cat << 'EOF' > /etc/systemd/system/hyperdns.service
[Unit]
Description=HyperDNS — Standalone SmartDNS & Gaming Gateway
Documentation=https://github.com/IzumiRain/hyperdns
After=network.target network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/hyperdns
RuntimeDirectory=hyperdns
RuntimeDirectoryMode=0700

# The daemon binds its root-local control socket at /run/hyperdns/control.sock.

# Every path is named explicitly. The daemon can work them out on its own — it
# probes for /opt/hyperdns and otherwise falls back to the working directory — but
# a unit that states them is a unit an operator can read the state locations out
# of, and it keeps being correct if the binary is ever installed elsewhere.
ExecStart=/opt/hyperdns/hyperdns -daemon \
    -config /opt/hyperdns/config.json \
    -db /opt/hyperdns/data.db \
    -key /opt/hyperdns/master.key

Restart=always
RestartSec=3s
TimeoutStopSec=15s
SyslogIdentifier=hyperdns

# 65535 because connection caps are what bound this daemon's stream listeners:
# 512 on TCP, 1024 on DoT, 512 on HTTPS/DoH — 2048 sockets before UDP, the
# upstream pool or the SNI relay's two-per-session pairs are counted at all.
# Against a 1024 soft limit those caps never bind; accepts fail first.
LimitNOFILE=65535

# Issuance is in-process since v2.2.0 (no certbot child), but the daemon
# itself is the process most likely to be OOM-pressured on a 1 GB VPS, and the
# default policy stops the whole unit when any process in its cgroup dies that
# way. Ignored with a warning on systemd older than 243.
OOMPolicy=continue

# Deliberately NOT sandboxed further: the daemon binds 53/80/443/853 and now
# performs its own ACME issuance in-process (writes only under
# /opt/hyperdns/certs). The full note is in scripts/hyperdns.service in the
# repository.

[Install]
WantedBy=multi-user.target
EOF

# The heredoc above inherits the caller's umask, and a unit file is not a place to trust
# it: under `umask 000` the redirect creates the file 0666, and a world-writable unit means
# any local user can rewrite ExecStart and have systemd run it as root on the next boot.
chmod 644 /etc/systemd/system/hyperdns.service

systemctl daemon-reload
systemctl enable hyperdns >/dev/null 2>&1
systemctl restart hyperdns

sleep 2

# ==============================================================================
# STEP 6: VERIFICATION & COMPLETION BANNER
# ==============================================================================
echo -e "${CYAN}${BOLD}[6/6] Verifying Service Health...${NC}"

# The service may need a few seconds to bind every listener. is-active is
# polled rather than asked once — a single check two seconds after start
# reported "ACTIVE" while the panel was still coming up, and on a fail-closed
# start (no certificate) it reported success for a process systemd was about
# to restart.
SERVICE_UP=false
for _hc in $(seq 1 20); do
    if systemctl is-active --quiet hyperdns; then
        SERVICE_UP=true
        break
    fi
    sleep 1
done

if [ "${SERVICE_UP}" = true ]; then
    echo -e "  ${GREEN}✓ HyperDNS core engine is ACTIVE and RUNNING!${NC}"
else
    echo -e "  ${RED}✕ Service failed to start. Run 'journalctl -u hyperdns -n 50' to inspect.${NC}"
    echo -e "  ${YELLOW}If the journal says the HTTPS certificate is not usable, the domain has no${NC}"
    echo -e "  ${YELLOW}CA-signed certificate yet — see the issuance step above for the fix.${NC}"
    exit 1
fi

# Pull the hidden admin path AND the actual panel port out of the journal so
# the banner and the health probes address the real listener. v2.2.0 draws a
# random management port per install — probing a hardcoded 8443 reported a
# healthy daemon as failed (curl 000, connection refused) on the first v2.2.0
# field install.
ADMIN_PATH=""
PANEL_PORT_LIVE=""
for _ in 1 2 3 4 5; do
    _JOURNAL=$(journalctl -u hyperdns --no-pager -n 120 2>/dev/null)
    ADMIN_PATH=$(printf '%s' "${_JOURNAL}" | grep -oE "/[0-9a-f]{16}/dash/login" | tail -1 | cut -d'/' -f2)
    PANEL_PORT_LIVE=$(printf '%s' "${_JOURNAL}" | grep -oE "Dashboard : https://0\.0\.0\.0:[0-9]+/" | grep -oE "[0-9]+" | tail -1)
    [ -n "$ADMIN_PATH" ] && [ -n "$PANEL_PORT_LIVE" ] && break
    sleep 1
done
if [ -z "$PANEL_PORT_LIVE" ]; then
    # Fall back to the stored config's web_port; the journal line only prints
    # once per boot and an upgrade may have missed it in the window above.
    PANEL_PORT_LIVE=$(python3 -c "import json;print(json.load(open('${INSTALL_DIR}/config.json'))['server'].get('web_port',''))" 2>/dev/null || true)
fi
[ -n "$PANEL_PORT_LIVE" ] && [ -n "${PANEL_PORT:-}" ] && PANEL_PORT="${PANEL_PORT_LIVE}"

# End-to-end HTTPS health gate. Everything below is verified against the real
# listener with the system trust store — no -k, no shortcuts. A 000 from curl
# means the connection itself failed; a non-200 on the assets is the hidden-
# namespace asset regression this gate exists to catch.
HEALTH_OK=true
HEALTH_DETAIL=""
if [ "$IS_HTTPS" = true ] && [ -n "$USER_DOMAIN" ] && [ -n "$ADMIN_PATH" ] && [ -n "$PANEL_PORT_LIVE" ]; then
    _resolve="--resolve ${USER_DOMAIN}:${PANEL_PORT_LIVE}:127.0.0.1"
    for _probe in "dash:${ADMIN_PATH}/dash/" "css:${ADMIN_PATH}/css/tailwind.purged.css" "js:${ADMIN_PATH}/js/app.js"; do
        _name="${_probe%%:*}"
        _path="${_probe#*:}"
        _code=$(curl -sS ${_resolve} --connect-timeout 4 --max-time 8 -o /dev/null -w '%{http_code}' "https://${USER_DOMAIN}:${PANEL_PORT_LIVE}/${_path}" 2>/dev/null || echo 000)
        if [ "${_code}" = "200" ]; then
            echo -e "  ${GREEN}✓ HTTPS ${_name} endpoint verified on port ${PANEL_PORT_LIVE} (200, trusted certificate).${NC}"
        else
            echo -e "  ${RED}✕ HTTPS ${_name} endpoint returned ${_code} (expected 200, port ${PANEL_PORT_LIVE}).${NC}"
            HEALTH_OK=false
            HEALTH_DETAIL="https://${USER_DOMAIN}:${PANEL_PORT_LIVE}/${_path}"
        fi
    done
elif [ "$IS_HTTPS" = true ] && [ -n "$USER_DOMAIN" ] && [ -z "$PANEL_PORT_LIVE" ]; then
    echo -e "  ${YELLOW}⚠ Could not read the panel port from the journal — skipping the URL probes.${NC}"
elif [ "$IS_HTTPS" = true ] && [ -n "$USER_DOMAIN" ]; then
    echo -e "  ${YELLOW}⚠ Could not read the admin path from the journal — skipping the URL probes.${NC}"
fi

if [ "${HEALTH_OK}" != true ]; then
    echo ""
    echo -e "${RED}${BOLD}  ✕ HEALTH CHECK FAILED — the install is NOT complete.${NC}"
    echo -e "${YELLOW}  Failing probe: ${HEALTH_DETAIL:-see above}${NC}"
    echo -e "${YELLOW}  Inspect:  journalctl -u hyperdns -n 80 --no-pager${NC}"
    echo -e "${YELLOW}  The most likely cause is a DNS record that has not reached this server yet:${NC}"
    echo -e "${YELLOW}  the daemon issues its own certificate at first start and retries daily.${NC}"
    echo -e "${YELLOW}  Verify the A record for ${USER_DOMAIN} points at ${PUBLIC_IP} and that port 80${NC}"
    echo -e "${YELLOW}  is open to the internet, then:  systemctl restart hyperdns${NC}"
    exit 1
fi

echo ""
echo -e "${GREEN}${BOLD}══════════════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}${BOLD}       🎉 HYPERDNS OFFLINE INSTALLATION COMPLETED SUCCESSFULLY!       ${NC}"
echo -e "${GREEN}${BOLD}══════════════════════════════════════════════════════════════════════${NC}"
echo ""

if [ "$IS_HTTPS" = true ] && [ -n "$USER_DOMAIN" ]; then
    if [ -n "$ADMIN_PATH" ]; then
        echo -e "  ${BOLD}?? Web Dashboard (HTTPS):${NC}  ${CYAN}https://${USER_DOMAIN}:${PANEL_PORT:-8443}/${ADMIN_PATH}/dash/${NC}"
        echo -e "  ${BOLD}?? Hidden admin path:${NC}      ${YELLOW}${ADMIN_PATH}${NC}  ${YELLOW}(recovered: journalctl -u hyperdns | grep 'admin panel path')${NC}"
    else
        echo -e "  ${BOLD}?? Web Dashboard (HTTPS):${NC}  ${CYAN}https://${USER_DOMAIN}:${PANEL_PORT:-8443}/<admin-path>/dash/${NC}"
        echo -e "  ${BOLD}?? Hidden admin path:${NC}      read it with: ${YELLOW}journalctl -u hyperdns | grep 'admin panel path'${NC}"
    fi
    echo -e "  ${BOLD}?? Private DNS (DoT):${NC}      ${CYAN}${USER_DOMAIN}:853${NC}"
    echo -e "  ${BOLD}?? DNS-over-HTTPS (DoH):${NC}   ${CYAN}https://${USER_DOMAIN}:8443/dns-query${NC}"
else
    _display_port="${PANEL_PORT:-8080}"
    echo -e "  ${BOLD}?? Web Dashboard:${NC}          ${CYAN}bound to 127.0.0.1:${_display_port} ONLY (no domain configured)${NC}"
    echo -e "  ${BOLD}?? Reach it via tunnel:${NC}    ${CYAN}ssh -L ${_display_port}:127.0.0.1:${_display_port} root@${PUBLIC_IP}${NC} then open http://127.0.0.1:${_display_port}/<admin-path>/dash/"
    echo -e "${YELLOW}  ??  Panel is NOT exposed publicly without a domain+HTTPS - by design.${NC}"
fi

echo ""
echo -e "  ${BOLD}👤 Default Username:${NC}       ${YELLOW}admin${NC}"
if [ -n "${GENERATED_ADMIN_PASSWORD:-}" ]; then
    echo -e "  ${BOLD}🔑 Generated Password:${NC}     ${YELLOW}${GENERATED_ADMIN_PASSWORD}${NC}"
    echo -e "${YELLOW}     ⚠️  Shown once only — save it now, then change it in the Web UI.${NC}"
    if [ -n "${GENERATED_API_KEY:-}" ]; then
        echo -e "  ${BOLD}🗝️  Master API Key:${NC}        ${YELLOW}${GENERATED_API_KEY}${NC}"
    fi
else
    echo -e "  ${BOLD}🔑 Password:${NC}               ${YELLOW}(unchanged — your existing password)${NC}"
fi
echo ""
echo -e "  ${BOLD}🎮 Dedicated Primary DNS IP:${NC} ${CYAN}${PUBLIC_IP}${NC}"
echo -e "  ${BOLD}🖥️  Terminal console:${NC}       run ${PURPLE}hdns${NC} anytime — it talks to the running service over its control socket (live telemetry, stop/start/uninstall included); ${PURPLE}hdns status${NC} and ${PURPLE}hdns flush${NC} also work beside the daemon"
echo -e "  ${BOLD}📂 Config File Location:${NC}   ${YELLOW}/opt/hyperdns/config.json${NC}"
echo ""
echo -e "${GREEN}${BOLD}══════════════════════════════════════════════════════════════════════${NC}"
echo ""
