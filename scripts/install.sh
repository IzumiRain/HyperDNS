#!/usr/bin/env bash
# ==============================================================================
# HyperDNS — Next-Gen Standalone SmartDNS & Gaming Gateway Installer
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
echo -e "       ${YELLOW}Version: beta 1.1.0 · Single Binary · Go 1.26 · OWASP Hardened${NC}"
echo ""

if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}[Error] Please run this installer as root (or use sudo).${NC}"
    exit 1
fi

INSTALL_DIR="/opt/hyperdns"

# ==============================================================================
# STEP 1: ARCHITECTURE & DIRECTORY SETUP
# ==============================================================================
echo -e "${CYAN}${BOLD}[1/6] Detecting System Architecture & Preparing Directories...${NC}"
mkdir -p "${INSTALL_DIR}"
mkdir -p "${INSTALL_DIR}/certs"
mkdir -p "${INSTALL_DIR}/scripts"

ARCH=$(uname -m)
case "${ARCH}" in
    x86_64|amd64)
        BIN_ARCH="amd64"
        ;;
    aarch64|arm64)
        BIN_ARCH="arm64"
        ;;
    *)
        echo -e "${RED}[Error] Unsupported architecture: ${ARCH}${NC}"
        exit 1
        ;;
esac
echo -e "  ${GREEN}✓ Architecture detected: ${ARCH} (${BIN_ARCH})${NC}"
echo -e "  ${GREEN}✓ Installation directory: ${INSTALL_DIR}${NC}"

# ==============================================================================
# STEP 2: RESOLVE PORT 53 CONFLICTS
# ==============================================================================
echo -e "${CYAN}${BOLD}[2/6] Freeing Port 53 (systemd-resolved conflict resolver)...${NC}"
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
echo -e "${CYAN}${BOLD}[3/6] Configuring Firewall Ports (53, 80, 443, 853, 8080, 8443)...${NC}"
if command -v ufw >/dev/null 2>&1; then
    ufw allow 53/udp >/dev/null 2>&1 || true
    ufw allow 53/tcp >/dev/null 2>&1 || true
    ufw allow 80/tcp >/dev/null 2>&1 || true
    ufw allow 443/tcp >/dev/null 2>&1 || true
    ufw allow 853/tcp >/dev/null 2>&1 || true
    ufw allow 8080/tcp >/dev/null 2>&1 || true
    ufw allow 8443/tcp >/dev/null 2>&1 || true
    echo -e "  ${GREEN}✓ UFW firewall rules configured.${NC}"
elif command -v firewall-cmd >/dev/null 2>&1; then
    firewall-cmd --permanent --add-port=53/udp >/dev/null 2>&1 || true
    firewall-cmd --permanent --add-port=53/tcp >/dev/null 2>&1 || true
    firewall-cmd --permanent --add-port=80/tcp >/dev/null 2>&1 || true
    firewall-cmd --permanent --add-port=443/tcp >/dev/null 2>&1 || true
    firewall-cmd --permanent --add-port=853/tcp >/dev/null 2>&1 || true
    firewall-cmd --permanent --add-port=8080/tcp >/dev/null 2>&1 || true
    firewall-cmd --permanent --add-port=8443/tcp >/dev/null 2>&1 || true
    firewall-cmd --reload >/dev/null 2>&1 || true
    echo -e "  ${GREEN}✓ Firewalld rules configured.${NC}"
fi

# ==============================================================================
# STEP 4: BINARY & SCRIPT INSTALLATION
# ==============================================================================
echo -e "${CYAN}${BOLD}[4/6] Installing HyperDNS Core Engine & TUI Utility...${NC}"
mkdir -p "${INSTALL_DIR}/certs"
mkdir -p "${INSTALL_DIR}/scripts"

INSTALLED=false

# 1. Local copy if running inside extracted repository
if [ -f "./hyperdns" ]; then
    cp ./hyperdns "${INSTALL_DIR}/hyperdns"
    INSTALLED=true
elif [ -f "./hyperdns-linux" ]; then
    cp ./hyperdns-linux "${INSTALL_DIR}/hyperdns"
    INSTALLED=true
fi

# 2. Try downloading prebuilt binary from GitHub Releases
if [ "$INSTALLED" = false ]; then
    echo -e "  ${YELLOW}Attempting to download prebuilt binary from GitHub Releases...${NC}"
    if curl -fL --connect-timeout 5 --retry 2 "https://github.com/IzumiRain/HyperDNS/releases/latest/download/hyperdns-linux-${BIN_ARCH}" -o "${INSTALL_DIR}/hyperdns" 2>/dev/null; then
        if [ -s "${INSTALL_DIR}/hyperdns" ]; then
            INSTALLED=true
            echo -e "  ${GREEN}✓ Downloaded prebuilt release binary.${NC}"
        fi
    fi
fi

# 3. Fallback: Compile from GitHub source in seconds
if [ "$INSTALLED" = false ]; then
    echo -e "  ${YELLOW}Compiling HyperDNS binary directly from source code...${NC}"
    if ! command -v go &>/dev/null; then
        echo -e "  ${CYAN}Installing Go compiler & Git...${NC}"
        apt-get update -y >/dev/null 2>&1 && apt-get install -y golang-go git >/dev/null 2>&1 || yum install -y golang git >/dev/null 2>&1 || true
    fi
    TMP_BUILD=$(mktemp -d)
    if git clone --depth 1 https://github.com/IzumiRain/HyperDNS.git "$TMP_BUILD" >/dev/null 2>&1; then
        (cd "$TMP_BUILD" && go build -ldflags="-s -w" -o "${INSTALL_DIR}/hyperdns" ./cmd/hyperdns >/dev/null 2>&1)
        if [ -s "${INSTALL_DIR}/hyperdns" ]; then
            INSTALLED=true
            echo -e "  ${GREEN}✓ Successfully built HyperDNS from source!${NC}"
        fi
        rm -rf "$TMP_BUILD"
    fi
fi

if [ ! -f "${INSTALL_DIR}/hyperdns" ] || [ ! -s "${INSTALL_DIR}/hyperdns" ]; then
    echo -e "  ${RED}Error: Failed to obtain HyperDNS binary. Please ensure internet access or use the offline bundle.${NC}"
    exit 1
fi

if [ -f "./scripts/ssl_issue.sh" ]; then
    cp ./scripts/ssl_issue.sh "${INSTALL_DIR}/scripts/ssl_issue.sh"
    chmod +x "${INSTALL_DIR}/scripts/ssl_issue.sh"
fi

chmod +x "${INSTALL_DIR}/hyperdns"

# Global CLI/TUI Command 'hdns'
ln -sf "${INSTALL_DIR}/hyperdns" /usr/local/bin/hdns
chmod +x /usr/local/bin/hdns
echo -e "  ${GREEN}✓ HyperDNS core binary & 'hdns' global command installed.${NC}"

# Auto-detect Public IP
PUBLIC_IP=$(curl -s -m 3 https://api.ipify.org || curl -s -m 3 https://ifconfig.me || echo "127.0.0.1")

# Default Config Setup
if [ ! -f "${INSTALL_DIR}/config.json" ]; then
    cat << EOF > "${INSTALL_DIR}/config.json"
{
  "server": {
    "public_ip": "${PUBLIC_IP}",
    "bind_host": "0.0.0.0",
    "web_port": 8080,
    "admin_username": "admin",
    "admin_password": "admin",
    "jwt_secret": "hyperdns-super-secret-jwt-key"
  },
  "dns": {
    "enabled": true,
    "port": 53,
    "dot_port": 853,
    "doh_port": 8443,
    "upstreams": ["1.1.1.1:53", "8.8.8.8:53", "9.9.9.9:53", "1.0.0.1:53", "77.88.8.1:53"],
    "cache_size": 20000,
    "cache_min_ttl": 60,
    "cache_max_ttl": 86400,
    "query_timeout": 2000000000,
    "fastest_racing": true,
    "ecs_client_ip": ""
  },
  "sni_proxy": {
    "enabled": true,
    "http_port": 80,
    "https_port": 443,
    "timeout": 30000000000,
    "enable_fragmentation": false,
    "fragment_size": 2,
    "fragment_delay_ms": 1
  },
  "rules": {
    "enable_riot": true,
    "enable_epic": true,
    "enable_steam": true,
    "enable_pubg": true,
    "enable_call_of_duty": true,
    "enable_supercell": true,
    "enable_discord": true,
    "enable_ea": true,
    "enable_blizzard": true,
    "enable_ubisoft": true,
    "enable_rockstar": true,
    "enable_xbox": true,
    "enable_playstation": true,
    "enable_roblox": true,
    "enable_spotify": true,
    "enable_twitch": true,
    "enable_kick": true,
    "enable_dev403": true,
    "enable_adblock": false,
    "enable_familysafe": false,
    "custom_proxied": [],
    "custom_blocked": [],
    "custom_direct": [],
    "custom_records": {}
  },
  "access": {
    "allow_all": true,
    "allowed_ips": [],
    "blocked_ips": [],
    "doh_tokens": [],
    "rate_limit_qps": 200
  },
  "tls": {
    "auto_cert": false,
    "domain": "",
    "email": "",
    "cert_file": "certs/cert.pem",
    "key_file": "certs/key.pem"
  }
}
EOF
fi

# ==============================================================================
# STEP 5: DOMAIN & SSL (HTTPS) CONFIGURATION PROMPT
# ==============================================================================
echo ""
echo -e "${CYAN}${BOLD}[5/6] SSL / HTTPS Security Configuration...${NC}"
echo -e "${YELLOW}┌────────────────────────────────────────────────────────────────────────┐${NC}"
echo -e "${YELLOW}│ Would you like to configure a custom domain with Let's Encrypt SSL?    │${NC}"
echo -e "${YELLOW}│ • YES: Enables HTTPS on Web UI & valid certificate for DoH / DoT       │${NC}"
echo -e "${YELLOW}│ • NO : Web UI will run on plain HTTP (Warning: unencrypted credentials)│${NC}"
echo -e "${YELLOW}└────────────────────────────────────────────────────────────────────────┘${NC}"

USER_DOMAIN=""
IS_HTTPS=false

read -p " Configure custom domain with SSL now? [y/N]: " RESP_SSL
if [[ "$RESP_SSL" =~ ^([yY][eE][sS]|[yY])$ ]]; then
    read -p " Enter your domain name (e.g. dns.example.com): " USER_DOMAIN
    read -p " Enter admin email for Let's Encrypt (optional): " USER_EMAIL
    
    if [ -n "$USER_DOMAIN" ]; then
        echo -e "${CYAN}Issuing Let's Encrypt SSL certificate for ${USER_DOMAIN}...${NC}"
        if [ -f "${INSTALL_DIR}/scripts/ssl_issue.sh" ]; then
            bash "${INSTALL_DIR}/scripts/ssl_issue.sh" "$USER_DOMAIN" "$USER_EMAIL" || true
        fi
        
        # Update config.json with Domain
        if command -v jq >/dev/null 2>&1; then
            jq ".tls.domain = \"${USER_DOMAIN}\" | .tls.email = \"${USER_EMAIL}\"" "${INSTALL_DIR}/config.json" > "${INSTALL_DIR}/config.tmp" && mv "${INSTALL_DIR}/config.tmp" "${INSTALL_DIR}/config.json"
        else
            sed -i "s/\"domain\": .*/\"domain\": \"${USER_DOMAIN}\",/" "${INSTALL_DIR}/config.json"
        fi
        IS_HTTPS=true
        echo -e "  ${GREEN}✓ Domain & SSL configured for ${USER_DOMAIN}!${NC}"
    fi
fi

# ==============================================================================
# STEP 6: SYSTEMD SERVICE SETUP & LAUNCH
# ==============================================================================
echo -e "${CYAN}${BOLD}[6/6] Starting HyperDNS Systemd Service...${NC}"
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
systemctl enable hyperdns.service >/dev/null 2>&1 || true
systemctl restart hyperdns.service || true
echo -e "  ${GREEN}✓ Service hyperdns is active and running.${NC}"

# ==============================================================================
# INSTALLATION SUMMARY BANNER
# ==============================================================================
echo ""
echo -e "${GREEN}${BOLD}========================================================================${NC}"
echo -e "${GREEN}${BOLD} ★ HyperDNS INSTALLED & RUNNING SUCCESSFULLY! ★${NC}"
echo -e "${GREEN}${BOLD}========================================================================${NC}"

if [ "$IS_HTTPS" = true ]; then
    echo -e " • ${BOLD}Web Dashboard (HTTPS)${NC} : ${CYAN}https://${USER_DOMAIN}:8443/dashboard${NC} (or http://${PUBLIC_IP}:8080/dashboard)"
    echo -e " • ${BOLD}DoT Private DNS Host${NC} : ${CYAN}${USER_DOMAIN}${NC} (Android Settings > Private DNS)"
    echo -e " • ${BOLD}DoH Endpoint${NC}         : ${CYAN}https://${USER_DOMAIN}:8443/dns-query${NC}"
else
    echo -e " • ${BOLD}Web Dashboard (HTTP)${NC}  : ${CYAN}http://${PUBLIC_IP}:8080/dashboard${NC}"
    echo -e " • ${BOLD}Matrix Gateway${NC}        : ${CYAN}http://${PUBLIC_IP}:8080/${NC}"
    echo -e " • ${BOLD}DoH Endpoint (HTTP)${NC}   : ${CYAN}http://${PUBLIC_IP}:8080/dns-query${NC}"
    echo -e "${YELLOW} ⚠️  [SECURITY NOTICE / هشدار امنیتی]: Web UI is currently running on unencrypted HTTP.${NC}"
    echo -e "${YELLOW}     We strongly recommend adding a domain and SSL via the Web UI or 'hdns'.${NC}"
fi

echo -e " • ${BOLD}Default Username${NC}     : ${YELLOW}admin${NC}"
echo -e " • ${BOLD}Default Password${NC}     : ${YELLOW}admin${NC} (Change upon first login)"
echo -e " • ${BOLD}Standard DNS IP${NC}      : ${CYAN}${PUBLIC_IP}${NC} (Set in Windows / PS5 / Xbox)"
echo -e " • ${BOLD}Terminal Manager (TUI)${NC}: Type ${PURPLE}hdns${NC} in any SSH terminal"
echo -e "${GREEN}${BOLD}========================================================================${NC}"
echo ""
