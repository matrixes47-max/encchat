# Security Policy

## 🔒 Security Overview

encchat v1.0 implements multiple layers of defense to protect user privacy and message confidentiality.

## 🛡️ Security Features

### Cryptographic Stack
1. **Argon2id** - Memory-hard password KDF (64MB memory, 3 iterations)
2. **PQXDH** - Post-quantum hybrid key exchange
   - **X25519** - Classical elliptic curve Diffie-Hellman
   - **ML-KEM-768** - Post-quantum KEM (NIST FIPS 203)
3. **HKDF-SHA256** - Key derivation for root and chain keys
4. **HMAC-SHA256** - Message key derivation (KDF_CK)
5. **Message Padding** - Fixed 256-byte padding to hide length
6. **ChaCha20** - First layer symmetric encryption
7. **AES-256-GCM** - Second layer authenticated encryption
8. **TLS/HTTPS** - Transport layer security

### Operational Security
- ✅ **Zero-Knowledge**: Server never sees plaintext
- ✅ **No Registration**: No accounts, emails, or phone numbers
- ✅ **No IP Logging**: Client IPs are not stored (especially in Tor mode)
- ✅ **In-Memory Storage**: No persistent database
- ✅ **Auto-Expiry**: Messages deleted after TTL (10s - 24h)
- ✅ **Forward Secrecy**: Past messages can't be decrypted
- ✅ **Break-in Recovery**: Future messages are secure even if current key compromised

### Application Security
- ✅ **Rate Limiting**: DDoS protection (60 req/min, 20 msg/min)
- ✅ **Input Validation**: Strict validation on all endpoints
- ✅ **CSP Headers**: Content Security Policy prevents XSS
- ✅ **CORS**: Restricted to same-origin
- ✅ **No Inline Scripts**: All JS in separate files
- ✅ **Resource Limits**: Memory and message caps

## 🔐 Threat Model

### Protected Against
✅ **Passive Network Surveillance** - End-to-end encryption  
✅ **Active Network Attacks** - MITM prevented by fingerprint verification  
✅ **Server Compromise** - Zero-knowledge design, no plaintext  
✅ **Quantum Computer Attacks** - ML-KEM-768 post-quantum protection  
✅ **Traffic Analysis** - Message padding hides length  
✅ **DDoS Attacks** - Rate limiting and memory caps  
✅ **Brute Force Attacks** - Argon2id memory-hard KDF  
✅ **Replay Attacks** - Message counters and timestamps  

### NOT Protected Against
❌ **Endpoint Compromise** - If your device is hacked, messages can be read  
❌ **Malicious Room Members** - Anyone with the room password can read messages  
❌ **Social Engineering** - User must verify fingerprints to prevent MITM  
❌ **Physical Access** - Browser memory contains decrypted messages  
❌ **State-Level Attackers** - Not independently audited, use with VPN+Tor  
❌ **Side-Channel Attacks** - JavaScript timing attacks theoretically possible  

## 🚨 Reporting Security Vulnerabilities

**Please report security issues responsibly.**

### How to Report
1. **GitHub Security Advisories** (preferred): [Private vulnerability reporting](https://github.com/matrixes47-max/encchat/security/advisories)
2. **Email**: Create an issue marked "Security" (we'll move to private discussion)
3. **DO NOT** disclose publicly before fix is released

### What to Include
- Description of vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

### Response Timeline
- **Initial Response**: Within 48 hours
- **Status Update**: Within 1 week
- **Fix Target**: Critical issues within 2 weeks

## 🔍 Known Limitations

### Auditing Status
⚠️ **Not Independently Audited** - This project has not undergone professional security audit.

### JavaScript Cryptography
⚠️ **JavaScript Crypto Risks**:
- No constant-time guarantees
- JIT compiler optimizations
- Memory not securely wiped
- Browser extension access

**Mitigation**: Using Web Crypto API where possible, pure JS implementations are well-tested

### Browser Storage
⚠️ **No Persistent Keys**: Keys are in memory only, lost on refresh.  
**Mitigation**: Intentional design for forward secrecy

## 🛡️ Security Best Practices for Users

### Essential
1. ✅ **Verify Fingerprints** - Always compare 🔑 fingerprints with your contact via another channel
2. ✅ **Use Strong Passwords** - Minimum 16+ random characters
3. ✅ **Use HTTPS** - Never use HTTP (app enforces this)
4. ✅ **Delete Room** - Use "Delete Room" button when done

### Recommended
1. 🔐 **Use Tor** - Access via .onion for maximum anonymity
2. 🔐 **Use VPN** - Add extra layer (VPN → Tor → encchat)
3. 🔐 **Incognito Mode** - Prevents browser history
4. 🔐 **Trusted Device** - Don't use on public/shared computers

### Advanced
1. 🔒 **Tails OS** - Use Tails/Whonix for extreme threat models
2. 🔒 **Multiple Hops** - Tor → VPN → Tor for extra paranoia
3. 🔒 **Air-Gapped Device** - For ultra-sensitive communications

## 🔬 Security Testing

### Automated
```bash
# Dependency vulnerabilities
npm audit

# Docker security
docker scan encchat:latest

# Static analysis
npm run lint
```

### Manual Testing Checklist
- [ ] CSP headers block inline scripts
- [ ] Rate limiting works (429 after limit)
- [ ] XSS attempts fail
- [ ] SQL injection N/A (no database)
- [ ] CSRF protection via CSP
- [ ] Fingerprint verification UI works
- [ ] Message padding consistent
- [ ] Keys cleared on room delete

### Penetration Testing
We welcome ethical security researchers to test the application. Please report findings responsibly.

## 📚 Security Resources

### Standards Compliance
- **NIST FIPS 203**: ML-KEM (Kyber) specification
- **RFC 7748**: X25519 elliptic curve
- **RFC 7539**: ChaCha20 cipher
- **RFC 9106**: Argon2 specification
- **Signal Protocol**: PQXDH design

### External Resources
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [Signal PQXDH Spec](https://signal.org/docs/specifications/pqxdh/)
- [NIST Post-Quantum](https://csrc.nist.gov/Projects/post-quantum-cryptography)

## 🔄 Security Updates

### Update Policy
- **Critical**: Immediate patch, version bump
- **High**: Fix within 1 week
- **Medium**: Fix within 1 month
- **Low**: Fix in next release

### Notification
Security updates announced via:
- GitHub Security Advisories
- README changelog
- GitHub Releases

## ⚖️ Responsible Disclosure

We follow industry-standard coordinated disclosure:
1. Report received
2. Confirm and assess
3. Develop fix
4. Release patch
5. Public disclosure (90 days or when fixed)

## 🏆 Security Hall of Fame

Contributors who responsibly disclose vulnerabilities will be credited here (with permission).

*No reports yet - be the first!*

---

## 📞 Contact

- **Security Issues**: GitHub Security Advisories
- **General Security Questions**: GitHub Discussions
- **Public Disclosure**: After fix is released

---

**Last Updated**: 2026-03-11  
**Version**: 1.0
