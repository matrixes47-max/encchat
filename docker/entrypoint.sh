#!/bin/sh
# enc.chat Docker entrypoint - runs Tor + Node.js

set -e

echo "╔════════════════════════════════════════════════════════════════════╗"
echo "║  enc.chat v4.1 — Tor Integrated Container                         ║"
echo "╚════════════════════════════════════════════════════════════════════╝"

# Start Tor in background
echo "🧅 Starting Tor Hidden Service..."
tor -f /etc/tor/torrc &
TOR_PID=$!

# Wait for Tor to establish circuit
sleep 5

# Check if .onion address exists
if [ -f /var/lib/tor/encchat/hostname ]; then
    ONION_ADDRESS=$(cat /var/lib/tor/encchat/hostname)
    echo "✅ Tor Hidden Service ready!"
    echo "🧅 Your .onion address: $ONION_ADDRESS"
else
    echo "⏳ Tor is starting... .onion address will be available soon"
fi

# Start Node.js application
echo "🚀 Starting enc.chat server..."
exec node server.js
