#!/bin/bash
set -e

echo "============================================"
echo "  Surfshark VPN Dashboard"
echo "============================================"
echo ""

if [ ! -f /vpn/auth.txt ]; then
    echo "ERROR: Credentials file not found at /vpn/auth.txt"
    echo "Create auth.txt with your Surfshark service credentials (username on line 1, password on line 2)"
    exit 1
fi

# Sanity-check the credentials file (the app also sanitizes CRLF at runtime)
AUTH_LINES=$(grep -c . /vpn/auth.txt || true)
if [ "$AUTH_LINES" -lt 2 ]; then
    echo "ERROR: auth.txt must contain username on line 1 and password on line 2"
    exit 1
fi

mkdir -p /vpn/data

echo "Dashboard:    http://0.0.0.0:8000"
echo "SOCKS5 proxy: port ${SOCKS_PORT:-1080} (after connecting)"
echo "HTTP proxy:   port ${HTTP_PORT:-8888} (after connecting)"
echo ""

exec python3 /app/app.py
