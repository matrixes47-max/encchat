# 🔐 enc.chat v4.2 — Security Hardened Edition

[![Security](https://img.shields.io/badge/Security-A+-green)]()
[![Post-Quantum](https://img.shields.io/badge/Post--Quantum-ML--KEM--768-blue)]()
[![Tor](https://img.shields.io/badge/Tor-Ready-purple)]()
[![License](https://img.shields.io/badge/License-MIT-yellow)]()

**Zero-Knowledge · Post-Quantum · Anonymous · Security Hardened**

Anonymous encrypted chat that even quantum computers can't break.  
No account. No phone number. No IP logging. No room name exposure.

---

## 🆕 What's New in v4.2

### 🔑 Key Zeroization
- ✅ **wipeDR()** — Double Ratchet state buffers filled with zeros before deletion
- ✅ **wipeSessionKeys()** — Argon2id SK, ML-KEM private key, X25519 all zeroed
- ✅ **beforeunload** — Tab/browser close immediately wipes all key material
- ✅ **visibilitychange** — Tab switch to background wipes keys instantly

### 🏠 Client-Side Room Hashing
- ✅ **Room name never reaches server** — SHA-256 hash sent instead
- ✅ `SHA256('enc.chat-room-v4:' + roomName)` → base64 hash
- ✅ Server logs, memory, and forensics can never reveal room names

### 🌐 IP Hashing
- ✅ **Raw IP never stored** — `SHA256(ip + salt).slice(0,16)` only
- ✅ Rate limiting works without exposing real IP addresses
- ✅ Server memory dump reveals no identifiable information

### ⏱️ Timestamp Jitter
- ✅ **±10 second random noise** added to all message timestamps
- ✅ Timing correlation attacks impossible
- ✅ Traffic analysis cannot determine exact send time

### 📊 Metadata Hardening
- ✅ **/health** — Stats removed (no rooms/keys count exposed publicly)
- ✅ **/metrics** — Localhost only (HTTP 403 for external requests)
- ✅ **MKSKIPPED limit** — Max 500 cached keys, oldest zeroed on overflow

---

## 🔒 Security Stack — 8 Layers

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

---

## 🔐 Security Comparison

| Feature | Signal | WhatsApp | Telegram | enc.chat v4.2 |
|---------|--------|----------|----------|----------------|
| Post-Quantum (ML-KEM) | ✅ | ❌ | ❌ | ✅ |
| E2EE Default | ✅ | ✅ | ❌ | ✅ |
| No Phone Number | ❌ | ❌ | ❌ | ✅ |
| No Account | ❌ | ❌ | ❌ | ✅ |
| Argon2id KDF | ❌ PBKDF2 | ❌ | ❌ | ✅ |
| Encryption Layers | 5 | 1 | 1 | **8** |
| Tor Support | Partial | ❌ | ❌ | ✅ |
| Zero-Knowledge Server | ✅ | ❌ | ❌ | ✅ |
| IP Never Stored | ❌ | ❌ | ❌ | ✅ SHA256 only |
| Room Name Private | — | — | — | ✅ client-side hash |
| Timestamp Jitter | ❌ | ❌ | ❌ | ✅ ±10 seconds |
| Key Zeroization | Partial | ❌ | ❌ | ✅ immediate |
| Rate Limiting | ✅ | ✅ | ✅ | ✅ |
| Metadata Protection | ❌ | ❌ | ❌ | ✅ |

---

## 🛡️ Threat Model

### ✅ Protected Against
- Passive Network Surveillance (E2EE)
- Active MITM Attacks (Fingerprint verification)
- Server Compromise (Zero-knowledge)
- Quantum Computer Attacks (ML-KEM-768)
- Traffic Analysis (Message padding + Timestamp jitter)
- DDoS Attacks (Rate limiting)
- Brute Force (Argon2id memory-hard)
- Replay Attacks (Message counters)
- **Room Name Disclosure** (Client-side SHA256 hashing) ✅ new
- **IP Tracking** (SHA256 hash only) ✅ new
- **Memory Forensics** (Key zeroization on tab close) ✅ new
- **Timing Correlation** (±10 second jitter) ✅ new

### ❌ Not Protected Against
- Endpoint Compromise (device hack/spyware)
- Malicious Room Members (anyone with password)
- Social Engineering
- Physical Access (during active session)
- State-Level Attackers (not independently audited yet)

---

## 📦 Quick Start

### Railway.app (Live Demo)
```
https://encchat.up.railway.app
```

### Docker
```bash
git clone https://github.com/matrixes47-max/encchat.git
cd encchat
docker-compose up -d encchat
```

### Manual
```bash
npm install
npm start
# Open http://localhost:3000
```

---

## ⚙️ Configuration

```bash
NODE_ENV=production
PORT=3000
TOR_ENABLED=false
TRUST_PROXY=false
RATE_LIMIT_MAX_REQUESTS=60
RATE_LIMIT_MESSAGE_MAX=20
```

---

## 🧅 Tor Hidden Service

```bash
# Docker method
docker-compose up -d encchat-tor
docker exec encchat-tor cat /var/lib/tor/encchat/hostname

# Manual
sudo apt install tor
# Add to /etc/tor/torrc:
# HiddenServiceDir /var/lib/tor/encchat/
# HiddenServicePort 80 127.0.0.1:3000
# HiddenServiceVersion 3
sudo systemctl restart tor
TOR_ENABLED=true npm start
```

---

## 🗺️ Roadmap

### v4.3 (Next)
- [ ] Dummy Traffic Generation (Chaffing)
- [ ] Custom Domain Support
- [ ] File Sharing (encrypted)
- [ ] Enhanced Padding Schemes

### v5.0 (Future)
- [ ] Native Mobile Apps (React Native)
- [ ] Voice/Video Calls
- [ ] Group Chat (3+ participants)
- [ ] **Independent Security Audit** ← most important

---

## ⚠️ Security Notice

**This is experimental software.** While it implements industry-standard cryptography:

- ✅ **Use for**: Private communications, learning, testing
- ❌ **Don't rely on for**: Life-threatening situations
- 🔍 **Status**: Not independently audited (yet)
- 🛡️ **Recommendation**: Tor Browser + strong password = maximum anonymity

---

<div align="center">

**enc.chat v4.2 — Security Hardened Edition**

ML-KEM-768 · X25519 · PQXDH · Argon2id · Double Ratchet · AES-256-GCM · ChaCha20

🔑 **Key Zeroization** · 🏠 **Room Hashing** · 🌐 **IP Hashing** · ⏱️ **Timestamp Jitter**

[GitHub](https://github.com/matrixes47-max/encchat) · [Demo](https://encchat.up.railway.app)

</div>
