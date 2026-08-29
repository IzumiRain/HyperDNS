#!/usr/bin/env bash
# ==============================================================================
# HyperDNS SSL Certificate Issuer (Powered by ACME & Let's Encrypt / ZeroSSL)
# ==============================================================================

set -e

DOMAIN="$1"
EMAIL="${2:-admin@$DOMAIN}"
DEST_DIR="${3:-/opt/hyperdns/certs}"

if [ -z "$DOMAIN" ]; then
    echo "Usage: $0 <domain> [email] [dest_dir]"
    exit 1
fi

echo "======================================================"
echo " Requesting Let's Encrypt SSL Certificate for: $DOMAIN"
echo "======================================================"

mkdir -p "$DEST_DIR"

# Install dependencies if needed
if ! command -v socat &> /dev/null; then
    echo "[SSL] Installing socat..."
    apt-get update -y && apt-get install -y socat curl || true
fi

# Install acme.sh if not installed
if [ ! -f "$HOME/.acme.sh/acme.sh" ]; then
    echo "[SSL] Installing acme.sh client..."
    curl -fsSL https://get.acme.sh | sh -s email="$EMAIL"
fi

ACME="$HOME/.acme.sh/acme.sh"

# Set default CA to Let's Encrypt
$ACME --set-default-ca --server letsencrypt || true

echo "[SSL] Issuing certificate for $DOMAIN via standalone HTTP-01 / DNS..."
$ACME --issue -d "$DOMAIN" --standalone --httpport 8880 --force || \
$ACME --issue -d "$DOMAIN" --alpn --force || \
$ACME --issue -d "$DOMAIN" --standalone --force

echo "[SSL] Installing certificate to $DEST_DIR..."
$ACME --install-cert -d "$DOMAIN" \
    --cert-file "$DEST_DIR/cert.pem" \
    --key-file "$DEST_DIR/key.pem" \
    --fullchain-file "$DEST_DIR/cert.pem" \
    --reloadcmd "systemctl restart hyperdns || true"

chmod 600 "$DEST_DIR/key.pem"
chmod 644 "$DEST_DIR/cert.pem"

echo "======================================================"
echo " ✓ SSL Certificate successfully installed for $DOMAIN"
echo "======================================================"
