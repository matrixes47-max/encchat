# 🔐 enc.chat v4.1 — Enhanced Post-Quantum Edition

[![Security](https://img.shields.io/badge/Security-A+-green)]()
[![Post-Quantum](https://img.shields.io/badge/Post--Quantum-ML--KEM--768-blue)]()
[![Tor](https://img.shields.io/badge/Tor-Ready-purple)]()
[![License](https://img.shields.io/badge/License-MIT-yellow)]()

**Zero-Knowledge · Post-Quantum · Tor-Compatible · Rate-Limited**

Anonymous encrypted chat that even quantum computers can't break.

## 🆕 What's New in v4.1

### 🛡️ Security Enhancements
- ✅ **Rate Limiting** - DDoS protection (60 req/min general, 20 msg/min)
- ✅ **Enhanced Security Headers** - Permissions-Policy, stricter CSP
- ✅ **Input Validation** - Hardened validation for all endpoints
- ✅ **Memory Monitoring** - Automatic leak detection and cleanup

### 🧅 Tor Integration
- ✅ **Tor Hidden Service** - Full .onion support
- ✅ **IP Obfuscation** - No logging when Tor enabled
- ✅ **Docker Integration** - One-command Tor deployment
- ✅ **Tor-optimized Headers** - Anonymous-friendly configuration

### 📊 Operations
- ✅ **Health Monitoring** - `/health` and `/metrics` endpoints
- ✅ **Prometheus Metrics** - Built-in monitoring
- ✅ **Systemd Service** - Production-ready deployment
- ✅ **Docker Compose** - Multi-variant containers

### 🚀 Performance
- ✅ **Optimized Cleanup** - Faster garbage collection
- ✅ **Configurable Limits** - Fine-tune via environment
- ✅ **Resource Limits** - Memory and CPU caps

---

## 🔒 Security Stack

```
┌─────────────────────────────────────────────────────────┐
│  Layer 8: HTTPS/TLS                     (Transport)     │
├─────────────────────────────────────────────────────────┤
│  Layer 7: AES-256-GCM                   (Web Crypto)    │
├─────────────────────────────────────────────────────────┤
│  Layer 6: ChaCha20                      (Pure JS)       │
├─────────────────────────────────────────────────────────┤
│  Layer 5: Message Padding (256B)        (Timing Safe)   │
├─────────────────────────────────────────────────────────┤
│  Layer 4: HMAC-SHA256 (KDF_CK)          (Message Keys)  │
├─────────────────────────────────────────────────────────┤
│  Layer 3: HKDF-SHA256                   (Key Derivation)│
├─────────────────────────────────────────────────────────┤
│  Layer 2: PQXDH Hybrid Exchange                         │
│           ├─ X25519 (ECDH)              (Classical)     │
│           └─ ML-KEM-768 (Kyber)         (Post-Quantum)  │
├─────────────────────────────────────────────────────────┤
│  Layer 1: Argon2id (64MB, iter=3)       (Password KDF)  │
└─────────────────────────────────────────────────────────┘
```

### 🔑 Key Features

| Feature | Status | Details |
|---------|--------|---------|
| **Post-Quantum** | ✅ | ML-KEM-768 (NIST FIPS 203) |
| **PQXDH** | ✅ | Signal Protocol 2023 |
| **Double Ratchet** | ✅ | Forward/Backward Secrecy |
| **Zero-Knowledge** | ✅ | Server sees only encrypted bytes |
| **Anonymity** | ✅ | No accounts, phones, IPs |
| **Tor Support** | ✅ | Native .onion hosting |
| **Rate Limiting** | ✅ | DDoS protection |
| **Fingerprint Verification** | ✅ | MITM detection |

---

## 📦 Quick Start

### Option 1: Docker (Recommended)

```bash
# Clone repository
git clone https://github.com/matrixes47-max/encchat.git
cd encchat

# Standard deployment
docker-compose up -d encchat

# Tor-integrated deployment
docker-compose up -d encchat-tor

# Get your .onion address
docker exec encchat-tor cat /var/lib/tor/encchat/hostname
```

### Option 2: Railway / Vercel / Heroku

```bash
# Clone and push to Railway
git clone https://github.com/matrixes47-max/encchat.git
cd encchat
railway up

# Or deploy to Vercel
vercel deploy
```

### Option 3: Manual Installation

```bash
# Install dependencies
npm install

# Configure environment
cp .env.example .env
nano .env  # Edit as needed

# Start server
npm start
```

---

## 🧅 Tor Hidden Service Setup

### Method 1: Docker (Easiest)

```bash
# Deploy with integrated Tor
docker-compose up -d encchat-tor

# Get your .onion address
docker exec encchat-tor cat /var/lib/tor/encchat/hostname
```

### Method 2: Manual Tor Setup

1. **Install Tor**
```bash
sudo apt install tor
```

2. **Configure Tor**
```bash
sudo nano /etc/tor/torrc
```

Add:
```
HiddenServiceDir /var/lib/tor/encchat/
HiddenServicePort 80 127.0.0.1:3000
HiddenServiceVersion 3
```

3. **Start Services**
```bash
# Start Tor
sudo systemctl restart tor

# Get .onion address
sudo cat /var/lib/tor/encchat/hostname

# Start enc.chat
TOR_ENABLED=true TRUST_PROXY=true npm start
```

4. **Access**
```
http://your-address.onion
```

---

## ⚙️ Configuration

### Environment Variables

```bash
# Core
NODE_ENV=production
PORT=3000

# Security
TOR_ENABLED=false              # Enable Tor support
TRUST_PROXY=false              # Trust X-Forwarded-For

# Rate Limits (requests per minute)
RATE_LIMIT_MAX_REQUESTS=60     # General API
RATE_LIMIT_MESSAGE_MAX=20      # Message posting

# TTL (seconds)
MIN_TTL=10
MAX_TTL=86400
DEFAULT_TTL=300

# Room Limits
MAX_MESSAGES_PER_ROOM=500
MAX_KEYS_PER_ROOM=10
```

See `.env.example` for full configuration.

---

## 🏗️ Deployment Guides

### Railway.app
```bash
railway init
railway up

# Configure environment:
TOR_ENABLED=false
TRUST_PROXY=true
```

### VPS with systemd
```bash
# Install
sudo cp systemd/encchat.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable encchat
sudo systemctl start encchat

# Monitor
sudo journalctl -u encchat -f
```

### Nginx Reverse Proxy
```nginx
server {
    listen 80;
    server_name enc.example.com;
    
    location / {
        proxy_pass http://localhost:3000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_cache_bypass $http_upgrade;
    }
}
```

---

## 📊 Monitoring

### Health Check
```bash
curl http://localhost:3000/health
```

Response:
```json
{
  "status": "ok",
  "version": "4.1-pq-enhanced",
  "features": {
    "postQuantum": true,
    "rateLimiting": true,
    "torSupport": false
  },
  "stats": {
    "rooms": 5,
    "keys": 8,
    "uptime": 3600,
    "memory": {
      "heapUsed": 45,
      "heapTotal": 89,
      "rss": 112
    }
  }
}
```

### Prometheus Metrics
```bash
curl http://localhost:3000/metrics
```

---

## 🔐 Security Comparison

| Feature | Signal | WhatsApp | Telegram | enc.chat v4.1 |
|---------|--------|----------|----------|---------------|
| Post-Quantum | ✅ | ❌ | ❌ | ✅ |
| E2EE Default | ✅ | ✅ | ❌ | ✅ |
| No Phone Number | ❌ | ❌ | ❌ | ✅ |
| No Account | ❌ | ❌ | ❌ | ✅ |
| Tor Support | Partial | ❌ | ❌ | ✅ |
| Open Source | ✅ | ❌ | ❌ | ✅ |
| Zero-Knowledge | ✅ | ❌ | ❌ | ✅ |
| Memory-Hard KDF | ❌ | ❌ | ❌ | ✅ (Argon2id) |
| Rate Limiting | ✅ | ✅ | ✅ | ✅ |
| Metadata Protection | ❌ | ❌ | ❌ | ✅ (Padding) |

---

## 📁 Project Structure

```
encchat-enhanced/
├── server.js               # Enhanced backend with rate limiting
├── public/
│   ├── index.html         # UI
│   └── app.js             # PQXDH + ML-KEM + Crypto
├── tor/
│   └── torrc.example      # Tor configuration
├── docker/
│   └── entrypoint.sh      # Tor+Node startup
├── systemd/
│   └── encchat.service    # Linux service
├── Dockerfile             # Multi-stage build
├── docker-compose.yml     # Multiple deployment variants
├── .env.example           # Configuration template
├── package.json
└── README.md
```

---

## 🧪 Testing

### Local Development
```bash
npm start
# Open http://localhost:3000
```

### Rate Limit Testing
```bash
# Should succeed
for i in {1..50}; do curl http://localhost:3000/health; done

# Should fail (429)
for i in {1..100}; do curl -X POST http://localhost:3000/api/messages -d '{}'; done
```

### Tor Testing
```bash
# Start Tor service
docker-compose up encchat-tor

# Get .onion address
ONION=$(docker exec encchat-tor cat /var/lib/tor/encchat/hostname)

# Test via Tor Browser or:
torsocks curl http://$ONION/health
```

---

## 🚀 Roadmap

### v4.2 (Next)
- [ ] Dummy Traffic (Chaffing)
- [ ] Custom Domain Support
- [ ] Multi-device Sync
- [ ] File Sharing (encrypted)

### v5.0 (Future)
- [ ] Native Mobile Apps
- [ ] Voice/Video Calls
- [ ] Group Chat (3+ people)
- [ ] Independent Security Audit

---

## 🔧 Troubleshooting

### Rate Limit Issues
```bash
# Increase limits in .env
RATE_LIMIT_MAX_REQUESTS=120
RATE_LIMIT_MESSAGE_MAX=40
```

### Tor Not Working
```bash
# Check Tor service
sudo systemctl status tor

# Verify .onion address
sudo cat /var/lib/tor/encchat/hostname

# Check logs
sudo journalctl -u tor -f
```

### High Memory Usage
```bash
# Check stats
curl http://localhost:3000/health

# Adjust limits in .env
MAX_MESSAGES_PER_ROOM=300
CLEANUP_INTERVAL=15000
```

---

## 📚 Technical Documentation

### Cryptographic Primitives
- **Argon2id**: Memory-hard KDF (64MB, iter=3)
- **ML-KEM-768**: Post-quantum KEM (NIST FIPS 203)
- **X25519**: Elliptic curve Diffie-Hellman
- **HKDF-SHA256**: Key derivation function
- **HMAC-SHA256**: Message authentication
- **ChaCha20**: Stream cipher (pure JS)
- **AES-256-GCM**: Authenticated encryption (Web Crypto)

### Protocol Flow
```
1. Password → Argon2id(64MB, 3) → SK_pass
2. X25519 + ML-KEM-768 → PQXDH → SK_dh
3. SK = HKDF(SK_pass ‖ SK_dh)
4. Double Ratchet(SK) → Message Keys
5. msg → Padding(256B) → ChaCha20 → AES-GCM → Send
```

---

## 🤝 Contributing

Pull requests welcome! Areas to improve:
- Additional security audits
- Performance optimizations
- UI/UX enhancements
- Documentation
- Testing coverage

---

## 📄 License

MIT License - see LICENSE file

---

## 🙏 Acknowledgments

- **Signal Protocol** - PQXDH design inspiration
- **NIST** - ML-KEM-768 standardization
- **Tor Project** - Anonymity infrastructure
- **Railway.app** - Hosting platform

---

## 📞 Support

- **GitHub Issues**: [github.com/matrixes47-max/encchat/issues](https://github.com/matrixes47-max/encchat/issues)
- **Documentation**: This README
- **Security**: Report via GitHub Security Advisories

---

## ⚠️ Security Notice

**This is experimental software.** While it implements industry-standard cryptography:

- ✅ **Use for**: Private communications, learning, testing
- ❌ **Don't use for**: Life-threatening situations, critical infrastructure
- 🔍 **Status**: Not independently audited (yet)
- 🛡️ **Recommendation**: Combine with VPN + Tor for maximum anonymity

**Remember**: No software is 100% secure. Defense in depth.

---

<div align="center">

**enc.chat v4.1**

ML-KEM-768 · X25519 · PQXDH · Argon2id · Double Ratchet · AES-256-GCM · ChaCha20

🔐 **Quantum-Resistant** · 🧅 **Tor-Ready** · 🛡️ **Rate-Limited** · ⚡ **Zero-Knowledge**

[GitHub](https://github.com/matrixes47-max/encchat) · [Demo](https://encchat-production.up.railway.app)

</div>
