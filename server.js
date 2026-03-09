/**
 * enc.chat v2 — Zero-Knowledge Encrypted Chat Server
 * Double Ratchet Edition
 *
 * სერვერმა არ იცის:
 *  - შეტყობინებების შინაარსი (ChaCha20 + AES-256-GCM, client-side)
 *  - პაროლი (არასდროს გადმოდის)
 *  - ვინაობა (IP არ ინახება)
 *  - ECDH private key-ები (მხოლოდ RAM-ში, client-side)
 */

const express = require("express");
const crypto  = require("crypto");
const path    = require("path");

const app  = express();
const PORT = process.env.PORT || 3000;

// ── In-memory stores ──────────────────────────────────────────────
const rooms = new Map();   // roomHash → Message[]
const keys  = new Map();   // roomHash → {sid, pub, expires}[]

// ── Security headers ──────────────────────────────────────────────
app.use((req, res, next) => {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("X-XSS-Protection", "1; mode=block");
  res.setHeader("Referrer-Policy", "no-referrer");
  res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate");
  res.setHeader(
    "Content-Security-Policy",
    "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; object-src 'none'; base-uri 'none'"
  );
  next();
});

app.use(express.json({ limit: "64kb" }));
app.use(express.static(path.join(__dirname, "public")));

// ── Helpers ───────────────────────────────────────────────────────
function hashRoom(roomId) {
  return crypto.createHash("sha256").update(roomId.toLowerCase().trim()).digest("hex");
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

// Background cleanup every 30s
setInterval(() => {
  for (const rh of rooms.keys()) purgeRoom(rh);
  for (const rh of keys.keys())  purgeKeys(rh);
}, 30_000);

// ══════════════════════════════════════════════════════════════════
// API — KEYS (Double Ratchet public key exchange)
// ══════════════════════════════════════════════════════════════════

/**
 * POST /api/keys
 * body: { room, sid, pub }
 * pub — base64 P-256 ECDH public key (65 bytes raw)
 * სერვერი ინახავს მხოლოდ public key-ს — private key client-ზეა
 */
app.post("/api/keys", (req, res) => {
  const { room, sid, pub } = req.body;

  if (!room || typeof room !== "string" || room.length > 128)
    return res.status(400).json({ error: "invalid room" });
  if (!sid  || typeof sid  !== "string" || sid.length  > 64)
    return res.status(400).json({ error: "invalid sid" });
  if (!pub  || typeof pub  !== "string" || pub.length  > 200)
    return res.status(400).json({ error: "invalid pub" });

  const roomHash = hashRoom(room);
  purgeKeys(roomHash);

  const ks = keys.get(roomHash) || [];

  // Update if sid already exists, otherwise add
  const idx = ks.findIndex(k => k.sid === sid);
  const entry = { sid, pub, expires: Date.now() + 24 * 3600 * 1000 };
  if (idx >= 0) ks[idx] = entry;
  else          ks.push(entry);

  keys.set(roomHash, ks);
  res.json({ ok: true });
});

/**
 * GET /api/keys?room=X&sid=MY_SID
 * Returns all public keys in room EXCEPT own sid
 */
app.get("/api/keys", (req, res) => {
  const { room, sid } = req.query;

  if (!room || room.length > 128) return res.json({ keys: [] });

  const roomHash = hashRoom(room);
  purgeKeys(roomHash);

  const ks = (keys.get(roomHash) || []).filter(k => k.sid !== sid);
  res.json({ keys: ks.map(k => ({ sid: k.sid, pub: k.pub })) });
});

// ══════════════════════════════════════════════════════════════════
// API — MESSAGES
// ══════════════════════════════════════════════════════════════════

/**
 * GET /api/messages?room=X
 */
app.get("/api/messages", (req, res) => {
  const roomId = req.query.room;
  if (!roomId || roomId.length > 128) return res.json({ messages: [] });

  const roomHash = hashRoom(roomId);
  purgeRoom(roomHash);

  res.json({ messages: rooms.get(roomHash) || [] });
});

/**
 * POST /api/messages
 * body: { room, enc, sid, dhPub, msgN, prevN, ttl }
 *
 * enc   — double-encrypted ciphertext blob (ChaCha20 + AES-256-GCM)
 * dhPub — sender's current ECDH public key (for Double Ratchet header)
 * msgN  — message index in current sending chain
 * prevN — previous sending chain length (PN)
 */
app.post("/api/messages", (req, res) => {
  const { room, enc, sid, dhPub, msgN, prevN, ttl } = req.body;

  if (!room  || typeof room  !== "string" || room.length  > 128)
    return res.status(400).json({ error: "invalid room" });
  if (!enc   || typeof enc   !== "string" || enc.length   > 16384)
    return res.status(400).json({ error: "invalid message" });
  if (!sid   || typeof sid   !== "string" || sid.length   > 64)
    return res.status(400).json({ error: "invalid session" });
  if (!dhPub || typeof dhPub !== "string" || dhPub.length > 200)
    return res.status(400).json({ error: "invalid dhPub" });
  if (typeof msgN  !== "number" || msgN  < 0 || msgN  > 100000)
    return res.status(400).json({ error: "invalid msgN" });
  if (typeof prevN !== "number" || prevN < 0 || prevN > 100000)
    return res.status(400).json({ error: "invalid prevN" });

  const ttlSecs  = Math.min(Math.max(parseInt(ttl) || 300, 10), 86400);
  const roomHash = hashRoom(room);

  purgeRoom(roomHash);
  const msgs = rooms.get(roomHash) || [];
  if (msgs.length >= 500) return res.status(429).json({ error: "room full" });

  const record = {
    id:      crypto.randomUUID(),
    enc,
    sid,
    dhPub,           // Double Ratchet header — sender's current DH public key
    msgN,            // message counter in chain
    prevN,           // previous chain length
    ts:      Date.now(),
    expires: Date.now() + ttlSecs * 1000
  };

  msgs.push(record);
  rooms.set(roomHash, msgs);
  res.json({ ok: true, id: record.id });
});

/**
 * DELETE /api/room?room=X
 */
app.delete("/api/room", (req, res) => {
  const roomId = req.query.room;
  if (!roomId) return res.status(400).json({ error: "invalid room" });
  const rh = hashRoom(roomId);
  rooms.delete(rh);
  keys.delete(rh);
  res.json({ ok: true });
});

// ── Health ────────────────────────────────────────────────────────
app.get("/health", (_, res) => res.json({ status: "ok", version: "2.0-dr" }));

app.get("*", (_, res) =>
  res.sendFile(path.join(__dirname, "public", "index.html"))
);

app.listen(PORT, () => {
  console.log(`enc.chat v2 (Double Ratchet) on port ${PORT}`);
  console.log("Zero-knowledge: server cannot read messages.");
});
