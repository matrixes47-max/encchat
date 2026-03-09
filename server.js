/**
 * enc.chat v4.1 — Enhanced Zero-Knowledge Encrypted Chat Server
 * Post-Quantum + Tor + Rate Limiting Edition
 *
 * NEW in v4.1:
 *  ✅ Rate Limiting (DDoS protection)
 *  ✅ Tor Hidden Service support
 *  ✅ Enhanced security headers
 *  ✅ Improved TTL management
 *  ✅ Request validation hardening
 *  ✅ Memory usage monitoring
 *
 * სერვერმა არ იცის:
 *  - შეტყობინებების შინაარსი (ChaCha20 + AES-256-GCM, client-side)
 *  - პაროლი (არასდროს გადმოდის)
 *  - ვინაობა (IP არ ინახება - Tor compatible)
 *  - ECDH private key-ები (მხოლოდ RAM-ში, client-side)
 */

const express = require("express");
const crypto  = require("crypto");
const path    = require("path");

const app  = express();
const PORT = process.env.PORT || 3000;

// ── Configuration ─────────────────────────────────────────────────
const CONFIG = {
  // Rate limiting
  RATE_LIMIT_WINDOW: 60 * 1000,      // 1 minute window
  RATE_LIMIT_MAX_REQUESTS: 60,       // 60 requests per minute per IP
  RATE_LIMIT_MESSAGE_MAX: 20,        // 20 messages per minute per IP
  
  // TTL limits
  MIN_TTL: 10,                       // Minimum 10 seconds
  MAX_TTL: 86400,                    // Maximum 24 hours
  DEFAULT_TTL: 300,                  // Default 5 minutes
  
  // Room limits
  MAX_MESSAGES_PER_ROOM: 500,
  MAX_KEYS_PER_ROOM: 10,
  
  // Cleanup intervals
  CLEANUP_INTERVAL: 30_000,          // 30 seconds
  RATE_LIMIT_CLEANUP: 120_000,       // 2 minutes
  
  // Size limits
  MAX_ROOM_LENGTH: 128,
  MAX_SID_LENGTH: 64,
  MAX_MESSAGE_SIZE: 16384,           // 16KB
  MAX_REQUEST_SIZE: "64kb",
  
  // Tor support
  TOR_ENABLED: process.env.TOR_ENABLED === "true",
  TRUST_PROXY: process.env.TRUST_PROXY === "true",
};

// ── In-memory stores ──────────────────────────────────────────────
const rooms = new Map();           // roomHash → Message[]
const keys  = new Map();           // roomHash → {sid, pub, expires}[]
const rateLimits = new Map();      // ip → {count, window, lastReset}

// ── Rate Limiting ─────────────────────────────────────────────────

/**
 * Get client IP (Tor-compatible)
 * If behind Tor or proxy, uses X-Forwarded-For (if trusted)
 * Otherwise uses connection IP
 */
function getClientIP(req) {
  let raw;
  if (CONFIG.TRUST_PROXY && req.headers["x-forwarded-for"]) {
    raw = req.headers["x-forwarded-for"].split(",")[0].trim();
  } else {
    raw = req.ip || req.connection.remoteAddress || "unknown";
  }
  // IP-ს არასოდეს ვინახავთ raw სახით — მხოლოდ ერთჯერადი hash
  return crypto.createHash("sha256").update(raw + "enc.chat-ratelimit-salt").digest("hex").slice(0, 16);
}

/**
 * Rate limiter middleware
 * Limits requests per IP to prevent DDoS
 */
function rateLimiter(maxRequests = CONFIG.RATE_LIMIT_MAX_REQUESTS) {
  return (req, res, next) => {
    const ip = getClientIP(req);
    const now = Date.now();
    
    // Get or create rate limit entry
    let entry = rateLimits.get(ip);
    
    if (!entry || now - entry.lastReset > CONFIG.RATE_LIMIT_WINDOW) {
      // New window
      entry = { count: 0, lastReset: now };
      rateLimits.set(ip, entry);
    }
    
    entry.count++;
    
    // Check if over limit
    if (entry.count > maxRequests) {
      return res.status(429).json({ 
        error: "rate limit exceeded",
        retryAfter: Math.ceil((entry.lastReset + CONFIG.RATE_LIMIT_WINDOW - now) / 1000)
      });
    }
    
    // Add rate limit headers
    res.setHeader("X-RateLimit-Limit", maxRequests);
    res.setHeader("X-RateLimit-Remaining", Math.max(0, maxRequests - entry.count));
    res.setHeader("X-RateLimit-Reset", Math.ceil((entry.lastReset + CONFIG.RATE_LIMIT_WINDOW) / 1000));
    
    next();
  };
}

// Clean up old rate limit entries
setInterval(() => {
  const now = Date.now();
  for (const [ip, entry] of rateLimits.entries()) {
    if (now - entry.lastReset > CONFIG.RATE_LIMIT_WINDOW * 2) {
      rateLimits.delete(ip);
    }
  }
}, CONFIG.RATE_LIMIT_CLEANUP);

// ── Enhanced Security Headers ─────────────────────────────────────
app.use((req, res, next) => {
  // Core security headers
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("X-XSS-Protection", "1; mode=block");
  res.setHeader("Referrer-Policy", "no-referrer");
  res.setHeader("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload");
  res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate, private");
  res.setHeader("Pragma", "no-cache");
  
  // Enhanced CSP with stricter rules
  res.setHeader(
    "Content-Security-Policy",
    [
      "default-src 'self'",
      "script-src 'self' https://cdn.jsdelivr.net 'wasm-unsafe-eval'",
      "style-src 'self' 'unsafe-inline'",
      "img-src 'self' data:",
      "font-src 'self'",
      "connect-src 'self'",
      "object-src 'none'",
      "base-uri 'self'",
      "form-action 'none'",
      "frame-ancestors 'none'",
      "upgrade-insecure-requests"
    ].join("; ")
  );
  
  // Permissions Policy (formerly Feature-Policy)
  res.setHeader(
    "Permissions-Policy",
    "geolocation=(), microphone=(), camera=(), payment=(), usb=(), magnetometer=(), gyroscope=()"
  );
  
  // Tor-specific: don't log real IPs
  if (CONFIG.TOR_ENABLED) {
    res.setHeader("X-Tor-Friendly", "true");
  }
  
  next();
});

// Trust proxy if configured (for Tor or reverse proxy)
if (CONFIG.TRUST_PROXY) {
  app.set("trust proxy", true);
}

app.use(express.json({ limit: CONFIG.MAX_REQUEST_SIZE }));
app.use(express.static(path.join(__dirname, "public")));

// ── Validation Helpers ────────────────────────────────────────────

function isValidString(str, maxLength) {
  return str && typeof str === "string" && str.length <= maxLength && str.trim().length > 0;
}

function isValidNumber(num, min, max) {
  return typeof num === "number" && num >= min && num <= max && Number.isInteger(num);
}

function isValidBase64(str, maxLength) {
  if (!isValidString(str, maxLength)) return false;
  try {
    // Basic base64 validation
    return /^[A-Za-z0-9+/]+=*$/.test(str);
  } catch {
    return false;
  }
}

// ── Helpers ───────────────────────────────────────────────────────

// room ID client-side არის hash-ებული — სერვერი პირდაპირ იყენებს
function getRoomHash(roomId) {
  return roomId; // უკვე hash-ია client-იდან
}

function purgeRoom(roomHash) {
  const msgs = rooms.get(roomHash);
  if (!msgs) return;
  const now   = Date.now();
  const alive = msgs.filter(m => m.expires > now);
  alive.length === 0 ? rooms.delete(roomHash) : rooms.set(roomHash, alive);
}

function purgeKeys(roomHash) {
  const ks = keys.get(roomHash);
  if (!ks) return;
  const now   = Date.now();
  const alive = ks.filter(k => k.expires > now);
  alive.length === 0 ? keys.delete(roomHash) : keys.set(roomHash, alive);
}

// Enhanced background cleanup with memory monitoring
setInterval(() => {
  const startTime = Date.now();
  let cleaned = { rooms: 0, keys: 0, messages: 0 };
  
  // Clean rooms and count
  for (const [rh, msgs] of rooms.entries()) {
    const before = msgs.length;
    purgeRoom(rh);
    const after = rooms.has(rh) ? rooms.get(rh).length : 0;
    cleaned.messages += (before - after);
    if (before > 0 && after === 0) cleaned.rooms++;
  }
  
  // Clean keys
  for (const rh of keys.keys()) {
    const before = keys.has(rh) ? keys.get(rh).length : 0;
    purgeKeys(rh);
    if (before > 0 && !keys.has(rh)) cleaned.keys++;
  }
  
  const duration = Date.now() - startTime;
  
  // Log if significant cleanup happened
  if (cleaned.rooms > 0 || cleaned.keys > 0 || cleaned.messages > 10) {
    console.log(`[CLEANUP] Purged ${cleaned.rooms} rooms, ${cleaned.keys} keysets, ${cleaned.messages} messages in ${duration}ms`);
  }
  
  // Memory monitoring
  const usage = process.memoryUsage();
  if (usage.heapUsed > 100 * 1024 * 1024) { // Over 100MB
    console.warn(`[MEMORY] High usage: ${Math.round(usage.heapUsed / 1024 / 1024)}MB heap, ${rooms.size} rooms, ${keys.size} keysets`);
  }
}, CONFIG.CLEANUP_INTERVAL);

// ══════════════════════════════════════════════════════════════════
// API — KEYS (PQXDH public key exchange)
// ══════════════════════════════════════════════════════════════════

/**
 * POST /api/keys
 * body: { room, sid, pub, mlkemPub?, pqct? }
 * pub — base64 X25519 public key
 * mlkemPub — base64 ML-KEM-768 public key (1184 bytes)
 * pqct — base64 ML-KEM-768 ciphertext (1088 bytes)
 */
app.post("/api/keys", rateLimiter(CONFIG.RATE_LIMIT_MAX_REQUESTS), (req, res) => {
  const { room, sid, pub, mlkemPub, pqct } = req.body;

  // Strict validation
  if (!isValidString(room, CONFIG.MAX_ROOM_LENGTH))
    return res.status(400).json({ error: "invalid room" });
  if (!isValidString(sid, CONFIG.MAX_SID_LENGTH))
    return res.status(400).json({ error: "invalid sid" });
  if (!isValidBase64(pub, 100))
    return res.status(400).json({ error: "invalid pub" });
  if (mlkemPub && !isValidBase64(mlkemPub, 1700))
    return res.status(400).json({ error: "invalid mlkemPub" });
  if (pqct && !isValidBase64(pqct, 1600))
    return res.status(400).json({ error: "invalid pqct" });

  const roomHash = getRoomHash(room);
  purgeKeys(roomHash);

  const ks = keys.get(roomHash) || [];
  
  // Limit keys per room
  if (ks.length >= CONFIG.MAX_KEYS_PER_ROOM && !ks.find(k => k.sid === sid)) {
    return res.status(429).json({ error: "room key limit reached" });
  }

  // Update if sid already exists, otherwise add
  const idx = ks.findIndex(k => k.sid === sid);
  const entry = { 
    sid, 
    pub, 
    mlkemPub: mlkemPub || null, 
    pqct: pqct || null, 
    expires: Date.now() + 24 * 3600 * 1000  // 24h expiry
  };
  
  if (idx >= 0) ks[idx] = entry;
  else          ks.push(entry);

  keys.set(roomHash, ks);
  res.json({ ok: true });
});

/**
 * GET /api/keys?room=X&sid=MY_SID
 * Returns all public keys in room EXCEPT own sid
 */
app.get("/api/keys", rateLimiter(CONFIG.RATE_LIMIT_MAX_REQUESTS), (req, res) => {
  const { room, sid } = req.query;

  if (!isValidString(room, CONFIG.MAX_ROOM_LENGTH)) 
    return res.json({ keys: [] });

  const roomHash = getRoomHash(room);
  purgeKeys(roomHash);

  const ks = (keys.get(roomHash) || []).filter(k => k.sid !== sid);
  res.json({ 
    keys: ks.map(k => ({ 
      sid: k.sid, 
      pub: k.pub, 
      mlkemPub: k.mlkemPub, 
      pqct: k.pqct 
    })) 
  });
});

// ══════════════════════════════════════════════════════════════════
// API — MESSAGES
// ══════════════════════════════════════════════════════════════════

/**
 * GET /api/messages?room=X
 */
app.get("/api/messages", rateLimiter(CONFIG.RATE_LIMIT_MAX_REQUESTS), (req, res) => {
  const roomId = req.query.room;
  
  if (!isValidString(roomId, CONFIG.MAX_ROOM_LENGTH)) 
    return res.json({ messages: [] });

  const roomHash = getRoomHash(roomId);
  purgeRoom(roomHash);

  res.json({ messages: rooms.get(roomHash) || [] });
});

/**
 * POST /api/messages
 * body: { room, enc, sid, dhPub, msgN, prevN, ttl }
 *
 * enc   — double-encrypted ciphertext blob (ChaCha20 + AES-256-GCM)
 * dhPub — sender's current X25519 public key (for Double Ratchet header)
 * msgN  — message index in current sending chain
 * prevN — previous sending chain length (PN)
 */
app.post("/api/messages", rateLimiter(CONFIG.RATE_LIMIT_MESSAGE_MAX), (req, res) => {
  const { room, enc, sid, dhPub, msgN, prevN, ttl } = req.body;

  // Strict validation
  if (!isValidString(room, CONFIG.MAX_ROOM_LENGTH))
    return res.status(400).json({ error: "invalid room" });
  if (!isValidBase64(enc, CONFIG.MAX_MESSAGE_SIZE))
    return res.status(400).json({ error: "invalid message" });
  if (!isValidString(sid, CONFIG.MAX_SID_LENGTH))
    return res.status(400).json({ error: "invalid session" });
  if (!isValidBase64(dhPub, 200))
    return res.status(400).json({ error: "invalid dhPub" });
  if (!isValidNumber(msgN, 0, 100000))
    return res.status(400).json({ error: "invalid msgN" });
  if (!isValidNumber(prevN, 0, 100000))
    return res.status(400).json({ error: "invalid prevN" });

  // TTL validation and clamping
  const ttlSecs = Math.min(
    Math.max(parseInt(ttl) || CONFIG.DEFAULT_TTL, CONFIG.MIN_TTL), 
    CONFIG.MAX_TTL
  );
  
  const roomHash = getRoomHash(room);

  purgeRoom(roomHash);
  const msgs = rooms.get(roomHash) || [];
  
  if (msgs.length >= CONFIG.MAX_MESSAGES_PER_ROOM) {
    return res.status(429).json({ error: "room full" });
  }

  const record = {
    id:      crypto.randomUUID(),
    enc,
    sid,
    dhPub,
    msgN,
    prevN,
    // ±10 წამის jitter — timing correlation attack-ის წინააღმდეგ
    ts:      Date.now() + Math.floor((Math.random() - 0.5) * 20_000),
    expires: Date.now() + ttlSecs * 1000
  };

  msgs.push(record);
  rooms.set(roomHash, msgs);
  
  res.json({ ok: true, id: record.id, ttl: ttlSecs });
});

/**
 * DELETE /api/room?room=X
 */
app.delete("/api/room", rateLimiter(CONFIG.RATE_LIMIT_MAX_REQUESTS), (req, res) => {
  const roomId = req.query.room;
  
  if (!isValidString(roomId, CONFIG.MAX_ROOM_LENGTH)) {
    return res.status(400).json({ error: "invalid room" });
  }
  
  const rh = getRoomHash(roomId);
  const hadRooms = rooms.has(rh);
  const hadKeys = keys.has(rh);
  
  rooms.delete(rh);
  keys.delete(rh);
  
  res.json({ ok: true, deleted: { rooms: hadRooms, keys: hadKeys } });
});

// ══════════════════════════════════════════════════════════════════
// Health & Monitoring
// ══════════════════════════════════════════════════════════════════

/**
 * GET /health
 * Returns server status and stats
 */
app.get("/health", (_, res) => {
  res.json({ 
    status: "ok", 
    version: "4.1-pq-enhanced",
    features: {
      postQuantum: true,
      rateLimiting: true,
      torSupport: CONFIG.TOR_ENABLED
    }
    // rooms/keys/memory count არ ვაჩვენებთ — metadata leak
  });
});

// /metrics — მხოლოდ localhost-იდან
app.get("/metrics", (req, res) => {
  const ip = req.ip || req.connection.remoteAddress || "";
  if (!["127.0.0.1", "::1", "::ffff:127.0.0.1"].includes(ip)) {
    return res.status(403).json({ error: "forbidden" });
  }
  const usage = process.memoryUsage();
  res.setHeader("Content-Type", "text/plain");
  res.send([
    `# HELP encchat_rooms_total Total number of active rooms`,
    `# TYPE encchat_rooms_total gauge`,
    `encchat_rooms_total ${rooms.size}`,
    ``,
    `# HELP encchat_keys_total Total number of active keysets`,
    `# TYPE encchat_keys_total gauge`,
    `encchat_keys_total ${keys.size}`,
    ``,
    `# HELP encchat_memory_bytes Memory usage in bytes`,
    `# TYPE encchat_memory_bytes gauge`,
    `encchat_memory_bytes{type="heap"} ${usage.heapUsed}`,
    `encchat_memory_bytes{type="rss"} ${usage.rss}`,
  ].join("\n"));
});

// ══════════════════════════════════════════════════════════════════
// Static Files & SPA Fallback
// ══════════════════════════════════════════════════════════════════

app.get("*", (_, res) =>
  res.sendFile(path.join(__dirname, "public", "index.html"))
);

// ══════════════════════════════════════════════════════════════════
// Server Start
// ══════════════════════════════════════════════════════════════════

app.listen(PORT, () => {
  console.log(`
╔════════════════════════════════════════════════════════════════════╗
║  enc.chat v4.1 — Post-Quantum Enhanced Edition                    ║
╠════════════════════════════════════════════════════════════════════╣
║  🔐 ML-KEM-768 + X25519 + Argon2id + Double Ratchet              ║
║  🛡️  Rate Limiting: ✅                                             ║
║  🧅 Tor Support: ${CONFIG.TOR_ENABLED ? '✅' : '❌ (set TOR_ENABLED=true)'}                           ║
║  📊 Monitoring: /health, /metrics                                 ║
╠════════════════════════════════════════════════════════════════════╣
║  Port: ${PORT.toString().padEnd(58)}║
║  Zero-knowledge: server cannot read messages                      ║
╚════════════════════════════════════════════════════════════════════╝
  `);
  
  if (CONFIG.TOR_ENABLED) {
    console.log("🧅 Tor mode enabled - IP addresses will not be logged");
  }
});
