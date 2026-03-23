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

echo "Starting dashboard on http://0.0.0.0:8080"
echo "SOCKS5 proxy will be available on port ${SOCKS_PORT:-1080} after connecting"
echo ""

exec python3 /app/app.py
