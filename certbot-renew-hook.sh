#!/bin/bash
#
# Certbot renewal hook for HAProxy
# This script is called after certbot successfully renews certificates
# Location: /etc/letsencrypt/renewal-hooks/deploy/haproxy-reload.sh
#

set -e

HAPROXY_CERTS_DIR="/etc/haproxy/certs"
HAPROXY_CFG="/etc/haproxy/haproxy.cfg"

# Process each renewed domain
for domain in $RENEWED_DOMAINS; do
    LIVE_DIR="/etc/letsencrypt/live/$domain"
    HAPROXY_CERT="${HAPROXY_CERTS_DIR}/${domain}.pem"
    
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] Processing certificate for: $domain"
    
    # Check if certificate files exist
    if [ -f "$LIVE_DIR/fullchain.pem" ] && [ -f "$LIVE_DIR/privkey.pem" ]; then
        # Concatenate fullchain and private key for HAProxy
        cat "$LIVE_DIR/fullchain.pem" "$LIVE_DIR/privkey.pem" > "$HAPROXY_CERT"
        chmod 600 "$HAPROXY_CERT"
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] Certificate merged: $HAPROXY_CERT"
    else
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] ERROR: Certificate files not found for $domain" >&2
    fi
done

# Validate HAProxy configuration before reload
if haproxy -c -f "$HAPROXY_CFG" > /dev/null 2>&1; then
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] HAProxy configuration valid, reloading..."
    systemctl reload haproxy
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] HAProxy reloaded successfully"
else
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] ERROR: HAProxy configuration invalid, skipping reload" >&2
    exit 1
fi
