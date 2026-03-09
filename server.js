/**
 * enc.chat — Zero-Knowledge Encrypted Chat Server
 *
 * რაც ამ სერვერმა არ იცის:
 *  - შეტყობინებების შინაარსი (ყველაფერი AES-256-GCM-ით დაშიფრულია client-ზე)
 *  - პაროლი (არასდროს გადმოდის client-დან)
 *  - მომხმარებლის ვინაობა (IP არ ინახება, სახელი არ ინახება)
 */

const express = require("express");
const crypto  = require("crypto");
const path    = require("path");

const app  = express();
const PORT = process.env.PORT || 3000;

// ── In-memory store (გამოყენება: Map<roomHash, Message[]>) ──
// არ ვიყენებთ DB-ს — მეხსიერება სერვერის გადატვირთვისას სრულად ქრება
const rooms = new Map();

// ── Security headers ──────────────────────────────────────
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
  // IP არ ვინახავთ — request log გამორთულია
  next();
});

app.use(express.json({ limit: "64kb" }));
app.use(express.static(path.join(__dirname, "public")));

// ── Room ID hash (რომ სერვერმა ოთახის სახელი არ იცოდეს) ─
function hashRoom(roomId) {
  return crypto.createHash("sha256").update(roomId.toLowerCase().trim()).digest("hex");
}

// ── Purge expired messages ────────────────────────────────
function purgeRoom(roomHash) {
  const msgs = rooms.get(roomHash);
  if (!msgs) return;
  const now = Date.now();
  const alive = msgs.filter(m => m.expires > now);
  if (alive.length === 0) {
    rooms.delete(roomHash); // ოთახი სრულად იშლება
  } else {
    rooms.set(roomHash, alive);
  }
}

// ── Background cleanup (ყოველ 30 წამში) ─────────────────
setInterval(() => {
  for (const roomHash of rooms.keys()) {
    purgeRoom(roomHash);
  }
}, 30_000);

// ══════════════════════════════════════════════════════════
// API ROUTES
// ══════════════════════════════════════════════════════════

/**
 * GET /api/messages?room=<roomId>
 * დაბრუნება: დაშიფრული blob-ების სია (სერვერმა შინაარსი არ იცის)
 */
app.get("/api/messages", (req, res) => {
  const roomId = req.query.room;
  if (!roomId || roomId.length > 128) return res.json({ messages: [] });

  const roomHash = hashRoom(roomId);
  purgeRoom(roomHash);

  const msgs = rooms.get(roomHash) || [];
  // client-ს ვუგზავნით მხოლოდ: id, enc (blob), sid, ts, expires
  res.json({ messages: msgs });
});

/**
 * POST /api/messages
 * body: { room, enc, sid, ttl }
 * enc — AES-256-GCM დაშიფრული blob (სერვერს ვერ გაშიფრავს)
 * sid — session id (anonymous, client-side generated)
 * ttl — seconds until deletion
 */
app.post("/api/messages", (req, res) => {
  const { room, enc, sid, ttl } = req.body;

  // ── Validation ──
  if (!room || typeof room !== "string" || room.length > 128)
    return res.status(400).json({ error: "invalid room" });
  if (!enc || typeof enc !== "string" || enc.length > 8192)
    return res.status(400).json({ error: "invalid message" });
  if (!sid || typeof sid !== "string" || sid.length > 64)
    return res.status(400).json({ error: "invalid session" });

  const ttlSecs = Math.min(Math.max(parseInt(ttl) || 300, 10), 86400);
  const roomHash = hashRoom(room);

  purgeRoom(roomHash);

  const msgs = rooms.get(roomHash) || [];

  // Max 500 messages per room
  if (msgs.length >= 500)
    return res.status(429).json({ error: "room full" });

  const record = {
    id:      crypto.randomUUID(),
    enc,                              // მხოლოდ დაშიფრული blob
    sid,                              // anonymous session id
    ts:      Date.now(),
    expires: Date.now() + ttlSecs * 1000
    // IP არ ინახება!
  };

  msgs.push(record);
  rooms.set(roomHash, msgs);

  res.json({ ok: true, id: record.id });
});

/**
 * DELETE /api/room?room=<roomId>
 * ოთახის ყველა შეტყობინება სამუდამოდ იშლება
 */
app.delete("/api/room", (req, res) => {
  const roomId = req.query.room;
  if (!roomId) return res.status(400).json({ error: "invalid room" });
  rooms.delete(hashRoom(roomId));
  res.json({ ok: true });
});

// ── Health check ──────────────────────────────────────────
app.get("/health", (req, res) => res.json({ status: "ok" }));

// ── 404 → index.html ─────────────────────────────────────
app.get("*", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

app.listen(PORT, () => {
  console.log(`enc.chat server running on port ${PORT}`);
  console.log("Zero-knowledge mode: server cannot read messages.");
});
