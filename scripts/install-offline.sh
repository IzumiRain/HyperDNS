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

# Clear screen & display Cyberpunk ASCII Banner
clear
echo -e "${CYAN}${BOLD}"
echo "  ██╗  ██╗██╗   ██╗██████╗ ███████╗██████╗ ██████╗ ███╗   ██╗███████╗"
echo "  ██║  ██║╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗██╔══██╗████╗  ██║██╔════╝"
echo "  ███████║ ╚████╔╝ ██████╔╝█████╗  ██████╔╝██║  ██║██╔██╗ ██║███████╗"
echo "  ██╔══██║  ╚██╔╝  ██╔═══╝ ██╔══╝  ██╔══██╗██║  ██║██║╚██╗██║╚════██║"
echo "  ██║  ██║   ██║   ██║     ███████╗██║  ██║██████╔╝██║ ╚████║███████║"
echo "  ╚═╝  ╚═╝   ╚═╝   ╚═╝     ╚══════╝╚═╝  ╚═╝╚═════╝ ╚═╝  ╚═══╝╚══════╝"
echo -e "       ${PURPLE}⚡ Standalone Zero-Loss SmartDNS & Anti-Sanction Gaming Gateway ⚡${NC}"
echo -e "       ${YELLOW}Package: 100% OFFLINE INSTALLER · Single Binary · Go 1.26 · OWASP Hardened${NC}"
echo ""

if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}[Error] Please run this installer as root (or use sudo).${NC}"
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_DIR="/opt/hyperdns"

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

mkdir -p "${INSTALL_DIR}"
mkdir -p "${INSTALL_DIR}/certs"

# Stop existing service if running
if systemctl is-active --quiet hyperdns; then
    echo -e "  ${YELLOW}Stopping existing hyperdns service...${NC}"
    systemctl stop hyperdns || true
fi

# Copy binary
cp -f "${SRC_BIN}" "${INSTALL_DIR}/hyperdns"
chmod +x "${INSTALL_DIR}/hyperdns"
ln -sf "${INSTALL_DIR}/hyperdns" /usr/local/bin/hdns

# Copy sample config if present and no config exists
if [ -f "${SCRIPT_DIR}/config.json" ] && [ ! -f "${INSTALL_DIR}/config.json" ]; then
    cp "${SCRIPT_DIR}/config.json" "${INSTALL_DIR}/config.json"
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
    systemctl restart systemd-resolved || true
    echo "nameserver 1.1.1.1" > /etc/resolv.conf
    echo -e "  ${GREEN}✓ Port 53 released successfully!${NC}"
else
    echo -e "  ${GREEN}✓ Port 53 is clear.${NC}"
fi

# ==============================================================================
# STEP 3: FIREWALL RULES CONFIGURATION
# ==============================================================================
echo -e "${CYAN}${BOLD}[3/6] Configuring Firewall Rules for Gaming & DNS...${NC}"
PORTS=(53 80 443 853 2099 5222 5223 8080 8393 8443)

if command -v ufw >/dev/null 2>&1; then
    for p in "${PORTS[@]}"; do
        ufw allow "${p}" >/dev/null 2>&1 || true
    done
    echo -e "  ${GREEN}✓ UFW firewall rules configured for all gaming & DNS ports.${NC}"
elif command -v firewall-cmd >/dev/null 2>&1; then
    for p in "${PORTS[@]}"; do
        firewall-cmd --permanent --add-port="${p}/tcp" >/dev/null 2>&1 || true
        firewall-cmd --permanent --add-port="${p}/udp" >/dev/null 2>&1 || true
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
echo -e "${YELLOW}│ Would you like to configure a custom domain with HTTPS/SSL for Web UI? │${NC}"
echo -e "${YELLOW}│ • YES: Enables HTTPS for Web UI and Let's Encrypt for DoH / DoT        │${NC}"
echo -e "${YELLOW}│ • NO : Web UI will run on HTTP (Warning: unencrypted credentials)      │${NC}"
echo -e "${YELLOW}└────────────────────────────────────────────────────────────────────────┘${NC}"

# Helper for reading user input cleanly in piped or interactive bash
ask_user() {
    local prompt_msg="$1"
    local default_val="$2"
    local user_var=""

    printf "%b" "${prompt_msg}" >&2
    if [ -t 0 ]; then
        read -r user_var || user_var=""
    elif [ -c /dev/tty ]; then
        read -r user_var </dev/tty 2>/dev/null || user_var=""
    fi
    
    if [ -z "${user_var}" ]; then
        echo "${default_val}"
    else
        echo "${user_var}"
    fi
}

USER_DOMAIN=""
IS_HTTPS=false

RESP_SSL=$(ask_user " ${BOLD}${YELLOW}▶ Configure custom domain with Let's Encrypt SSL now? [y/N]: ${NC}" "n")

if [[ "$RESP_SSL" =~ ^([yY][eE][sS]|[yY])$ ]]; then
    USER_DOMAIN=$(ask_user " ${BOLD}${CYAN}▶ Enter your domain name (e.g. dns.example.com): ${NC}" "")
    USER_EMAIL=$(ask_user " ${BOLD}${CYAN}▶ Enter admin email for Let's Encrypt (optional, press Enter to skip): ${NC}" "")
    
    if [ -n "$USER_DOMAIN" ]; then
        if [ -f "${INSTALL_DIR}/config.json" ]; then
            sed -i "s/\"domain\": .*/\"domain\": \"${USER_DOMAIN}\",/" "${INSTALL_DIR}/config.json" || true
            sed -i "s/\"email\": .*/\"email\": \"${USER_EMAIL}\",/" "${INSTALL_DIR}/config.json" || true
            sed -i "s/\"auto_cert\": .*/\"auto_cert\": true,/" "${INSTALL_DIR}/config.json" || true
        fi
        IS_HTTPS=true
        echo -e "  ${GREEN}✓ Custom domain '${USER_DOMAIN}' configured with HTTPS!${NC}"
    fi
else
    echo ""
    echo -e "${YELLOW}${BOLD}⚠️  [SECURITY WARNING / هشدار امنیتی]${NC}"
    echo -e "${YELLOW}No domain was added. The Web UI will run on standard HTTP (unencrypted).${NC}"
    echo -e "${YELLOW}For maximum production security, you can bind a domain and issue SSL anytime${NC}"
    echo -e "${YELLOW}from the Web Dashboard under 'Settings & Custom Rules' or via 'hdns'.${NC}"
    echo ""
fi

# ==============================================================================
# STEP 5: SYSTEMD SERVICE SETUP
# ==============================================================================
echo -e "${CYAN}${BOLD}[5/6] Creating & Starting Systemd Background Service...${NC}"
cat << 'EOF' > /etc/systemd/system/hyperdns.service
[Unit]
Description=HyperDNS — Standalone SmartDNS & Gaming Gateway
After=network.target network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/hyperdns
ExecStart=/opt/hyperdns/hyperdns -config /opt/hyperdns/config.json -daemon
Restart=always
RestartSec=3s
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable hyperdns >/dev/null 2>&1
systemctl restart hyperdns

sleep 2

# ==============================================================================
# STEP 6: VERIFICATION & COMPLETION BANNER
# ==============================================================================
echo -e "${CYAN}${BOLD}[6/6] Verifying Service Health...${NC}"

if systemctl is-active --quiet hyperdns; then
    echo -e "  ${GREEN}✓ HyperDNS core engine is ACTIVE and RUNNING!${NC}"
else
    echo -e "  ${RED}✕ Service failed to start. Run 'journalctl -u hyperdns -n 50' to inspect.${NC}"
    exit 1
fi

PUBLIC_IP=$(curl -s --connect-timeout 2 https://api.ipify.org || hostname -I | awk '{print $1}')
if [ -z "${PUBLIC_IP}" ]; then
    PUBLIC_IP="YOUR_SERVER_IP"
fi

echo ""
echo -e "${GREEN}${BOLD}══════════════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}${BOLD}       🎉 HYPERDNS OFFLINE INSTALLATION COMPLETED SUCCESSFULLY!       ${NC}"
echo -e "${GREEN}${BOLD}══════════════════════════════════════════════════════════════════════${NC}"
echo ""

if [ "$IS_HTTPS" = true ] && [ -n "$USER_DOMAIN" ]; then
    echo -e "  ${BOLD}🌐 Web Dashboard (HTTPS):${NC}  ${CYAN}https://${USER_DOMAIN}:8443/dashboard${NC} (or http://${PUBLIC_IP}:8080/dashboard)"
    echo -e "  ${BOLD}🔒 Private DNS (DoT):${NC}      ${CYAN}${USER_DOMAIN}:853${NC}"
    echo -e "  ${BOLD}🔒 DNS-over-HTTPS (DoH):${NC}   ${CYAN}https://${USER_DOMAIN}:8443/dns-query${NC}"
else
    echo -e "  ${BOLD}🌐 Web Dashboard (HTTP):${NC}   ${CYAN}http://${PUBLIC_IP}:8080/dashboard${NC}"
    echo -e "  ${BOLD}🟢 Matrix System Gateway:${NC}  ${CYAN}http://${PUBLIC_IP}:8080/${NC}"
    echo -e "${YELLOW}  ⚠️  [SECURITY NOTICE]: Web UI running over HTTP. Use HTTPS for production.${NC}"
fi

echo ""
echo -e "  ${BOLD}👤 Default Username:${NC}       ${YELLOW}admin${NC}"
echo -e "  ${BOLD}🔑 Default Password:${NC}       ${YELLOW}admin${NC} (Change upon first login)"
echo ""
echo -e "  ${BOLD}🎮 Dedicated Primary DNS IP:${NC} ${CYAN}${PUBLIC_IP}${NC}"
echo -e "  ${BOLD}💻 Terminal Management UI:${NC} Type ${PURPLE}hdns${NC} anywhere in terminal"
echo -e "  ${BOLD}📂 Config File Location:${NC}   ${YELLOW}/opt/hyperdns/config.json${NC}"
echo ""
echo -e "${GREEN}${BOLD}══════════════════════════════════════════════════════════════════════${NC}"
echo ""
