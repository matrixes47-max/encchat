# Changelog

All notable changes to enc.chat will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [4.1.0] - 2025-03-09

### 🆕 Added

#### Security Enhancements
- **Rate Limiting** - DDoS protection with configurable limits
  - 60 requests/minute for general API endpoints
  - 20 messages/minute for message posting
  - Automatic cleanup of rate limit tracking
  - HTTP 429 responses with Retry-After headers
  
- **Enhanced Security Headers**
  - Permissions-Policy header to disable browser features
  - Stricter Content-Security-Policy
  - Cache-Control headers to prevent caching
  - Tor-friendly headers (X-Tor-Friendly)

- **Input Validation Hardening**
  - Base64 validation for cryptographic data
  - Strict type checking for all inputs
  - Integer bounds checking for counters
  - Length limits enforcement

#### Tor Integration
- **Tor Hidden Service Support**
  - Full .onion hosting capability
  - Configurable via TOR_ENABLED environment variable
  - IP obfuscation when Tor mode enabled
  - Docker image with integrated Tor daemon
  - Tor configuration examples

#### Operational Features
- **Health Monitoring**
  - `/health` endpoint with detailed stats
  - Memory usage monitoring
  - Active rooms/keys counting
  - Feature detection (post-quantum, rate-limiting, Tor)

- **Prometheus Metrics**
  - `/metrics` endpoint for monitoring tools
  - Memory, room, and key metrics
  - Prometheus-compatible format

- **Deployment Options**
  - systemd service file with security hardening
  - Docker multi-stage builds
  - docker-compose with multiple variants
  - Nginx reverse proxy configuration

#### Configuration
- **Environment Variables**
  - Configurable rate limits
  - Adjustable TTL min/max/default
  - Room and message size limits
  - Cleanup interval tuning
  - Trust proxy settings

- **Resource Limits**
  - Maximum messages per room (500)
  - Maximum keys per room (10)
  - Configurable message size (16KB)
  - Memory monitoring and warnings

### 🔧 Changed

#### Performance
- **Optimized Cleanup**
  - Faster background cleanup with metrics
  - Cleanup statistics logging
  - Memory usage warnings
  - Efficient Map operations

- **Better Error Handling**
  - Descriptive error messages
  - Proper HTTP status codes
  - Rate limit headers

#### Code Quality
- **Modular Configuration**
  - Centralized CONFIG object
  - Environment variable support
  - Sensible defaults

- **Validation Functions**
  - Reusable validation helpers
  - Type-safe checks
  - Consistent error handling

- **IP Detection**
  - Tor-compatible IP extraction
  - X-Forwarded-For support
  - Configurable proxy trust

### 📚 Documentation

- **README.md**
  - Comprehensive deployment guides
  - Tor setup instructions
  - Configuration reference
  - Troubleshooting section
  - Security comparison table

- **SECURITY.md**
  - Detailed threat model
  - Security best practices
  - Vulnerability reporting process
  - Known limitations

- **CHANGELOG.md** (this file)
  - Version history
  - Feature documentation

- **Deployment Guides**
  - Docker Compose examples
  - systemd service configuration
  - Nginx reverse proxy setup
  - Railway/Vercel instructions

### 🐛 Fixed

- **Rate Limit Memory Leaks** - Automatic cleanup of stale entries
- **Response Headers** - Consistent header application
- **Validation Edge Cases** - Better handling of malformed input

### 🔒 Security

- **Rate Limiting** prevents DDoS attacks
- **Enhanced CSP** prevents XSS attacks
- **Input Validation** prevents injection attacks
- **Memory Limits** prevent resource exhaustion
- **Tor Support** enhances anonymity

---

## [4.0.0] - 2025-03-01 (Original)

### Added

#### Post-Quantum Cryptography
- **ML-KEM-768** (CRYSTALS-Kyber) implementation
  - NIST FIPS 203 standard compliance
  - 1184-byte public keys
  - 1088-byte ciphertext
  - 32-byte shared secrets

- **PQXDH Protocol**
  - Hybrid key exchange (X25519 + ML-KEM-768)
  - Protection against classical and quantum computers
  - Signal Protocol 2023 compatibility

#### Security Features
- **Argon2id** password KDF (64MB memory, 3 iterations)
- **Double Ratchet** with forward/backward secrecy
- **Message Padding** (256-byte fixed)
- **Key Fingerprint** verification (12 hex characters)
- **ChaCha20** encryption (pure JavaScript)
- **AES-256-GCM** encryption (Web Crypto API)

#### Server Features
- **Zero-Knowledge** design
- **In-Memory Storage** (no database)
- **TTL-Based Expiry** (10s - 24h)
- **Room-Based Communication**
- **No Registration Required**

### Security
- 8-layer encryption stack
- Post-quantum resistant
- No IP logging
- No user identification

---

## [3.0.0] - Previous Version

### Added
- **Argon2id** replacing PBKDF2
- **X25519** replacing P-256
- **Message Padding** (256B)
- **Key Fingerprint** verification

---

## [2.0.0] - Previous Version

### Added
- **Double Ratchet** protocol
- **P-256 ECDH** key exchange
- **HKDF-SHA256** key derivation
- **HMAC-SHA256** for message keys

---

## [1.0.0] - Initial Release

### Added
- **AES-256-GCM** encryption
- **ChaCha20** encryption
- **PBKDF2** key derivation
- Basic chat functionality

---

## Upgrade Notes

### From v4.0 to v4.1

**No Breaking Changes** - v4.1 is fully backward compatible.

#### Migration Steps
1. Update `server.js` to v4.1
2. Copy `.env.example` and configure
3. Review rate limit settings
4. Enable Tor if desired
5. Update deployment configs (Docker/systemd)

#### New Environment Variables
```bash
# Optional - defaults will work
TOR_ENABLED=false
TRUST_PROXY=false
RATE_LIMIT_MAX_REQUESTS=60
RATE_LIMIT_MESSAGE_MAX=20
```

#### Docker Users
```bash
# Pull new image
docker-compose pull

# Rebuild
docker-compose build

# Deploy
docker-compose up -d
```

---

## Future Roadmap

### v4.2 (Planned)
- [ ] Dummy traffic generation (chaffing)
- [ ] Custom domain support
- [ ] Enhanced padding schemes
- [ ] Multi-device sync
- [ ] File sharing (encrypted)

### v5.0 (Future)
- [ ] Native mobile apps (React Native)
- [ ] Voice/Video calls
- [ ] Group chat (3+ participants)
- [ ] Independent security audit
- [ ] Formal verification

---

## Version Format

- **MAJOR**: Incompatible API/protocol changes
- **MINOR**: New features (backward compatible)
- **PATCH**: Bug fixes (backward compatible)

---

## Links

- [Repository](https://github.com/matrixes47-max/encchat)
- [Security Policy](SECURITY.md)
- [README](README.md)
