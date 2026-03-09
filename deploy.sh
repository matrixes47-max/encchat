#!/bin/bash
# enc.chat v4.1 Quick Start Script
# Automatically detects environment and deploys

set -e

echo "╔════════════════════════════════════════════════════════════════════╗"
echo "║  enc.chat v4.1 — Quick Start                                      ║"
echo "╚════════════════════════════════════════════════════════════════════╝"
echo ""

# Detect deployment method
if command -v docker &> /dev/null && command -v docker-compose &> /dev/null; then
    echo "✅ Docker detected"
    DEPLOY_METHOD="docker"
elif command -v node &> /dev/null && command -v npm &> /dev/null; then
    echo "✅ Node.js detected"
    DEPLOY_METHOD="node"
else
    echo "❌ Neither Docker nor Node.js found"
    echo "Please install either:"
    echo "  - Docker: https://docs.docker.com/get-docker/"
    echo "  - Node.js: https://nodejs.org/"
    exit 1
fi

# Ask for deployment variant
echo ""
echo "Choose deployment variant:"
echo "  1) Standard (HTTP only)"
echo "  2) Tor Hidden Service (.onion)"
echo "  3) Development (with hot reload)"
read -p "Enter choice [1-3]: " VARIANT

case $VARIANT in
    1)
        echo "📦 Deploying standard version..."
        DEPLOY_VARIANT="standard"
        ;;
    2)
        echo "🧅 Deploying Tor version..."
        DEPLOY_VARIANT="tor"
        ;;
    3)
        echo "🔧 Deploying development version..."
        DEPLOY_VARIANT="dev"
        ;;
    *)
        echo "Invalid choice. Using standard."
        DEPLOY_VARIANT="standard"
        ;;
esac

# Deploy based on method
if [ "$DEPLOY_METHOD" = "docker" ]; then
    echo ""
    echo "🐳 Building Docker images..."
    
    case $DEPLOY_VARIANT in
        standard)
            docker-compose up -d encchat
            PORT=3000
            ;;
        tor)
            docker-compose up -d encchat-tor
            PORT=3001
            echo ""
            echo "⏳ Waiting for Tor to initialize..."
            sleep 10
            if docker exec encchat-tor cat /var/lib/tor/encchat/hostname 2>/dev/null; then
                ONION=$(docker exec encchat-tor cat /var/lib/tor/encchat/hostname)
                echo ""
                echo "🧅 Your .onion address: $ONION"
            else
                echo "⚠️  Tor address not ready yet. Check with:"
                echo "   docker exec encchat-tor cat /var/lib/tor/encchat/hostname"
            fi
            ;;
        dev)
            docker-compose up encchat
            PORT=3000
            ;;
    esac
    
    echo ""
    echo "✅ Deployment complete!"
    echo ""
    echo "Access your chat:"
    echo "  Local: http://localhost:$PORT"
    if [ "$DEPLOY_VARIANT" = "tor" ]; then
        echo "  Tor:   http://$ONION (use Tor Browser)"
    fi
    echo ""
    echo "Useful commands:"
    echo "  Status:  docker-compose ps"
    echo "  Logs:    docker-compose logs -f"
    echo "  Stop:    docker-compose down"
    echo "  Health:  curl http://localhost:$PORT/health"
    
elif [ "$DEPLOY_METHOD" = "node" ]; then
    echo ""
    echo "📦 Installing dependencies..."
    npm install
    
    echo ""
    echo "⚙️  Configuring environment..."
    if [ ! -f .env ]; then
        cp .env.example .env
        echo "Created .env file. Edit if needed:"
        echo "  nano .env"
    fi
    
    case $DEPLOY_VARIANT in
        tor)
            echo "TOR_ENABLED=true" >> .env
            echo "TRUST_PROXY=true" >> .env
            echo ""
            echo "⚠️  You need to configure Tor separately:"
            echo "   1. Install: sudo apt install tor"
            echo "   2. Configure: sudo nano /etc/tor/torrc"
            echo "   3. Add contents from: tor/torrc.example"
            echo "   4. Restart: sudo systemctl restart tor"
            echo "   5. Get address: sudo cat /var/lib/tor/encchat/hostname"
            ;;
    esac
    
    echo ""
    echo "🚀 Starting server..."
    if [ "$DEPLOY_VARIANT" = "dev" ]; then
        npm run dev
    else
        npm start &
        SERVER_PID=$!
        sleep 2
        
        echo ""
        echo "✅ Server started (PID: $SERVER_PID)"
        echo ""
        echo "Access your chat:"
        echo "  Local: http://localhost:3000"
        echo ""
        echo "Useful commands:"
        echo "  Stop:    kill $SERVER_PID"
        echo "  Health:  curl http://localhost:3000/health"
        echo "  Logs:    tail -f logs/server.log"
    fi
fi

echo ""
echo "════════════════════════════════════════════════════════════════════"
echo "For more information, see README.md"
echo "════════════════════════════════════════════════════════════════════"
