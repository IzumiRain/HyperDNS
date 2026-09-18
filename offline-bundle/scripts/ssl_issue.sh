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
    echo "[SSL] Installing socat and curl..."
    if command -v apt-get &> /dev/null; then
        # Two statements rather than `update && install`. Chained with &&, a single stale
        # mirror entry makes apt-get update exit non-zero and the install is skipped
        # silently — the script then fails several steps later at the ACME challenge, with
        # no socat and no hint of why.
        apt-get update -y || true
        apt-get install -y socat curl || true
    elif command -v dnf &> /dev/null; then
        dnf install -y socat curl || true
    elif command -v yum &> /dev/null; then
        yum install -y socat curl || true
    elif command -v apk &> /dev/null; then
        apk add socat curl || true
    elif command -v pacman &> /dev/null; then
        pacman -Sy --noconfirm socat curl || true
    fi
fi

# Locate or install acme.sh client
if command -v acme.sh &> /dev/null; then
    ACME="acme.sh"
elif [ -f "$HOME/.acme.sh/acme.sh" ]; then
    ACME="$HOME/.acme.sh/acme.sh"
elif [ -f "/root/.acme.sh/acme.sh" ]; then
    ACME="/root/.acme.sh/acme.sh"
else
    echo "[SSL] Installing acme.sh client..."
    curl -fsSL https://get.acme.sh | sh -s email="$EMAIL"
    if [ -f "$HOME/.acme.sh/acme.sh" ]; then
        ACME="$HOME/.acme.sh/acme.sh"
    elif [ -f "/root/.acme.sh/acme.sh" ]; then
        ACME="/root/.acme.sh/acme.sh"
    else
        ACME="acme.sh"
    fi
fi

# Set default CA to Let's Encrypt
$ACME --set-default-ca --server letsencrypt || true

echo "[SSL] Issuing certificate for $DOMAIN via standalone HTTP-01 (port 80)..."
# NOTE: Let's Encrypt always validates HTTP-01 on port 80. Ports 80/443 are
# normally occupied by the HyperDNS SNI proxy, so stop the service for the
# duration of the challenge and start it again right after (post-hook).
#
# The post-hook is not enough on its own. acme.sh only runs it after a successful
# issuance, so a wrong domain, a closed port 80 or a rate limit leaves the service
# stopped — every subscriber loses DNS because a certificate request failed. With
# `set -e` the script would exit right there and never restart anything. The trap makes
# the restart unconditional, whichever way this script ends.
restore_service() {
    if command -v systemctl >/dev/null 2>&1 && systemctl is-enabled hyperdns >/dev/null 2>&1; then
        systemctl start hyperdns >/dev/null 2>&1 || true
    fi
}
trap restore_service EXIT

# No --force on purpose. A valid, not-near-expiry certificate makes --issue a
# no-op ("Skip. So next time use --force"), which is exactly what a re-run of
# the installer or a daemon-startup retry wants; --force would burn one of
# Let's Encrypt's five duplicate-certificate slots per name per week every
# single time.
$ACME --issue -d "$DOMAIN" --standalone \
    --pre-hook "systemctl stop hyperdns || true" \
    --post-hook "systemctl start hyperdns || true" || \
$ACME --issue -d "$DOMAIN" --alpn \
    --pre-hook "systemctl stop hyperdns || true" \
    --post-hook "systemctl start hyperdns || true"

echo "[SSL] Installing certificate to $DEST_DIR..."
# cert.pem holds the full chain, and --cert-file is deliberately absent. Both used to be
# pointed at the same path, which worked only because acme.sh happens to copy the leaf
# before the chain: the last writer won. Asking for the chain alone says what is wanted
# instead of relying on that order, and Go's tls.LoadX509KeyPair reads a fullchain file
# happily. A leaf without its intermediate is the classic "works in curl, fails on
# Android" certificate.
$ACME --install-cert -d "$DOMAIN" \
    --key-file "$DEST_DIR/key.pem" \
    --fullchain-file "$DEST_DIR/cert.pem" \
    --reloadcmd "systemctl restart hyperdns || true"

chmod 600 "$DEST_DIR/key.pem"
chmod 644 "$DEST_DIR/cert.pem"

echo "======================================================"
echo " ✓ SSL Certificate successfully installed for $DOMAIN"
echo "======================================================"
