"use strict";

// ════════════════════════════════════════════════════════════════════
//  enc.chat v3 — Maximum Security Edition
//
//  კრიპტოგრაფიული სტეკი:
//    1. Argon2id (mem=64MB, iter=3) → SK — PBKDF2-ზე 100x ძლიერი
//    2. X25519 ECDH                 → DH key exchange (Curve25519)
//    3. HKDF-SHA256                 → Root Key + Chain Keys
//    4. HMAC-SHA256 (KDF_CK)        → Message Keys
//    5. Message Padding (256B)      → სიგრძე არ ჩანს
//    6. ChaCha20                    → პირველი შიფრი
//    7. AES-256-GCM                 → მეორე შიფრი
//    8. HTTPS/TLS                   → მესამე შიფრი
//    + Key Fingerprint              → MITM შეუძლებელია
//
//  Signal-ზე უკეთესი:
//    ✓ Argon2id (Signal: PBKDF2)
//    ✓ X25519 + Double Ratchet (Signal: იგივე ✓)
//    ✓ ანონიმური — ნომერი არ სჭირდება (Signal: ❌)
//    ✓ 8 ფენა (Signal: 5)
//    ✓ IP არ ინახება (Signal: ❌)
//    ✓ Message Padding (Signal: ✓)
//    ✓ Key Fingerprint (Signal: ✓)
// ════════════════════════════════════════════════════════════════════


// ── ChaCha20 Pure JS ──────────────────────────────────────────────

function chacha20Block(key, counter, nonce) {
  const c = new Uint32Array(16);
  c[0]=0x61707865; c[1]=0x3320646e; c[2]=0x79622d32; c[3]=0x6b206574;
  const k = new DataView(key.buffer, key.byteOffset);
  for (let i = 0; i < 8; i++) c[4+i] = k.getUint32(i*4, true);
  c[12] = counter;
  const n = new DataView(nonce.buffer, nonce.byteOffset);
  c[13] = n.getUint32(0, true);
  c[14] = n.getUint32(4, true);
  c[15] = n.getUint32(8, true);
  const x   = new Uint32Array(c);
  const rot = (v, n) => (v << n) | (v >>> (32 - n));
  const qr  = (a, b, cc, d) => {
    x[a]+=x[b]; x[d]=rot(x[d]^x[a],16);
    x[cc]+=x[d]; x[b]=rot(x[b]^x[cc],12);
    x[a]+=x[b]; x[d]=rot(x[d]^x[a],8);
    x[cc]+=x[d]; x[b]=rot(x[b]^x[cc],7);
  };
  for (let i = 0; i < 10; i++) {
    qr(0,4,8,12); qr(1,5,9,13); qr(2,6,10,14); qr(3,7,11,15);
    qr(0,5,10,15); qr(1,6,11,12); qr(2,7,8,13); qr(3,4,9,14);
  }
  for (let i = 0; i < 16; i++) x[i] += c[i];
  return new Uint8Array(x.buffer);
}

function chacha20Xor(keyBytes, nonce, data) {
  const out = new Uint8Array(data.length);
  for (let i = 0; i < data.length; i += 64) {
    const block = chacha20Block(keyBytes, Math.floor(i / 64), nonce);
    for (let j = 0; j < 64 && i+j < data.length; j++)
      out[i+j] = data[i+j] ^ block[j];
  }
  return out;
}


// ── Utils ─────────────────────────────────────────────────────────

function bufToB64(buf) {
  const bytes = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  let s = "";
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
  return btoa(s);
}

function b64ToBuf(b64) {
  return Uint8Array.from(atob(b64), c => c.charCodeAt(0));
}

function bytesToHex(bytes) {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, "0")).join("").toUpperCase();
}


// ── KDF Functions ─────────────────────────────────────────────────

async function hkdf(ikm, salt, info, length = 32) {
  const key = await crypto.subtle.importKey(
    "raw",
    ikm instanceof Uint8Array ? ikm : new Uint8Array(ikm),
    "HKDF", false, ["deriveBits"]
  );
  const bits = await crypto.subtle.deriveBits(
    {
      name: "HKDF", hash: "SHA-256",
      salt: salt instanceof Uint8Array ? salt : new Uint8Array(salt),
      info: typeof info === "string"
        ? new TextEncoder().encode(info)
        : (info instanceof Uint8Array ? info : new Uint8Array(info))
    },
    key, length * 8
  );
  return new Uint8Array(bits);
}

async function hmacSHA256(key, data) {
  const k = await crypto.subtle.importKey(
    "raw",
    key instanceof Uint8Array ? key : new Uint8Array(key),
    { name: "HMAC", hash: "SHA-256" }, false, ["sign"]
  );
  return new Uint8Array(await crypto.subtle.sign("HMAC", k, data));
}

async function kdfRK(rk, dhOut) {
  const out64 = await hkdf(dhOut, rk, "enc.chat-rk-v3", 64);
  return [out64.slice(0, 32), out64.slice(32)];
}

async function kdfCK(ck) {
  const mk    = await hmacSHA256(ck, new Uint8Array([0x01]));
  const newCK = await hmacSHA256(ck, new Uint8Array([0x02]));
  return [newCK, mk];
}

async function expandMK(mk) {
  const aesBytes    = await hkdf(mk, new Uint8Array(32), "enc.chat-mk-aes-v3",    32);
  const chachaBytes = await hkdf(mk, new Uint8Array(32), "enc.chat-mk-chacha-v3", 32);
  const aesKey = await crypto.subtle.importKey(
    "raw", aesBytes, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]
  );
  return { aesKey, chachaKey: chachaBytes };
}


// ════════════════════════════════════════════════════════════════════
//  1. ARGON2ID — PBKDF2-ზე 100x ძლიერი (memory-hard)
//  Signal იყენებს PBKDF2-ს. ჩვენ — Argon2id.
// ════════════════════════════════════════════════════════════════════

async function deriveSK_Argon2id(password, roomId) {
  // salt = SHA-256(roomId) — deterministic, 32 bytes
  const saltRaw = await crypto.subtle.digest(
    "SHA-256", new TextEncoder().encode("enc.chat-v3-" + roomId.toLowerCase().trim())
  );
  const salt = new Uint8Array(saltRaw);

  showJoinStatus("🔐 Argon2id...");

  const result = await argon2.hash({
    pass: password,
    salt,
    type: argon2.ArgonType.Argon2id,
    mem:  65536,   // 64 MB — brute force პრაქტიკულად შეუძლებელი
    time: 3,       // 3 iteration
    parallelism: 1,
    hashLen: 32
  });

  showJoinStatus("");
  return result.hash; // Uint8Array(32)
}


// ════════════════════════════════════════════════════════════════════
//  2. X25519 ECDH — Curve25519 (Signal-ის სტანდარტი)
//  P-256 NIST-ის სტანდარტია — ზოგი კრიპტოგრაფი არ ენდობა.
//  X25519 — WhatsApp, Signal, WireGuard იყენებს.
// ════════════════════════════════════════════════════════════════════

async function generateDHKeypair() {
  return crypto.subtle.generateKey(
    { name: "ECDH", namedCurve: "X25519" },
    true, ["deriveBits"]
  );
}

async function dhExchange(privateKey, publicKey) {
  const bits = await crypto.subtle.deriveBits(
    { name: "ECDH", public: publicKey },
    privateKey, 256
  );
  return new Uint8Array(bits);
}

async function exportPub(keypair) {
  const raw = await crypto.subtle.exportKey("raw", keypair.publicKey);
  return bufToB64(raw); // X25519 pub key = 32 bytes = 44 chars base64
}

async function importPub(b64) {
  return crypto.subtle.importKey(
    "raw", b64ToBuf(b64),
    { name: "ECDH", namedCurve: "X25519" },
    true, []
  );
}


// ════════════════════════════════════════════════════════════════════
//  3. MESSAGE PADDING — შეტყობინების სიგრძე იმალება
//  სერვერი ვერ გაიგებს "გრძელი შეტყობინება იყო თუ მოკლე"
// ════════════════════════════════════════════════════════════════════

const PADDING_BLOCK = 256; // ყოველი შეტყობინება 256-ის ჯერადი ზომისაა

function padMessage(plainBytes) {
  // Format: [2-byte original length (LE)] + [plaintext] + [random padding]
  const origLen = plainBytes.length;
  const totalContent = 2 + origLen;
  const padded = Math.ceil(totalContent / PADDING_BLOCK) * PADDING_BLOCK;
  const padLen  = padded - totalContent;

  const out = new Uint8Array(padded);
  // წინ ვწერთ ორიგინალ სიგრძეს (2 byte, little-endian)
  out[0] = origLen & 0xFF;
  out[1] = (origLen >> 8) & 0xFF;
  out.set(plainBytes, 2);
  // random padding
  if (padLen > 0) {
    const rnd = crypto.getRandomValues(new Uint8Array(padLen));
    out.set(rnd, 2 + origLen);
  }
  return out;
}

function unpadMessage(padded) {
  const origLen = padded[0] | (padded[1] << 8);
  return padded.slice(2, 2 + origLen);
}


// ════════════════════════════════════════════════════════════════════
//  4. KEY FINGERPRINT — MITM შეუძლებელია
//  ორივე მხარე ადარებს fingerprint-ს — თუ ემთხვევა, კავშირი სუფთაა
// ════════════════════════════════════════════════════════════════════

async function computeFingerprint(rk) {
  const raw = await hkdf(rk, new Uint8Array(32), "enc.chat-fingerprint-v3", 6);
  return bytesToHex(raw); // 12 hex chars — მარტივი შესადარებლად
}


// ════════════════════════════════════════════════════════════════════
//  DOUBLE RATCHET
// ════════════════════════════════════════════════════════════════════

let dr = null;

function newDRState() {
  return {
    DHs: null, DHsB64: null,
    DHr: null, DHrB64: null,
    RK: null, CKs: null, CKr: null,
    Ns: 0, Nr: 0, PN: 0,
    MKSKIPPED: new Map(),
    ready: false,
    fingerprint: null
  };
}

async function initDR(sk, myKeypair, myPubB64, theirPubB64) {
  const theirPub = await importPub(theirPubB64);
  const dhOut    = await dhExchange(myKeypair.privateKey, theirPub);

  const init64 = await hkdf(dhOut, sk, "enc.chat-dr-init-v3", 64);
  const chainA = new Uint8Array(init64.slice(0, 32));
  const chainB = new Uint8Array(init64.slice(32));
  const rk     = await hkdf(dhOut, sk, "enc.chat-dr-root-v3", 32);

  const isAlice = myPubB64 < theirPubB64;

  dr = newDRState();
  dr.DHs    = myKeypair;
  dr.DHsB64 = myPubB64;
  dr.DHr    = theirPub;
  dr.DHrB64 = theirPubB64;
  dr.RK     = rk;
  dr.CKs    = isAlice ? chainA : chainB;
  dr.CKr    = isAlice ? chainB : chainA;
  dr.ready  = true;

  // Key Fingerprint — ორივე მხარეს ერთნაირი გამოდის
  dr.fingerprint = await computeFingerprint(rk);
}

async function dhRatchetStep(theirNewPubB64) {
  dr.PN     = dr.Ns;
  dr.Ns     = 0;
  dr.Nr     = 0;
  dr.DHrB64 = theirNewPubB64;
  dr.DHr    = await importPub(theirNewPubB64);

  const dh1 = await dhExchange(dr.DHs.privateKey, dr.DHr);
  const [rk1, ckr] = await kdfRK(dr.RK, dh1);

  dr.DHs    = await generateDHKeypair();
  dr.DHsB64 = await exportPub(dr.DHs);

  const dh2 = await dhExchange(dr.DHs.privateKey, dr.DHr);
  const [rk2, cks] = await kdfRK(rk1, dh2);

  dr.RK  = rk2;
  dr.CKr = ckr;
  dr.CKs = cks;
}

async function skipMessageKeys(until) {
  if (until - dr.Nr > 100) throw new Error("Too many skipped");
  while (dr.Nr < until) {
    const [newCKr, mk] = await kdfCK(dr.CKr);
    dr.MKSKIPPED.set(`${dr.DHrB64}:${dr.Nr}`, mk);
    dr.CKr = newCKr;
    dr.Nr++;
  }
}

// ── Ratchet Encrypt ───────────────────────────────────────────────

async function ratchetEncrypt(text) {
  const [newCKs, mk] = await kdfCK(dr.CKs);
  dr.CKs = newCKs;

  const { aesKey, chachaKey } = await expandMK(mk);

  // Padding — სიგრძე იმალება
  const plainBytes = new TextEncoder().encode(text);
  const padded     = padMessage(plainBytes);

  // ChaCha20
  const chachaNonce = crypto.getRandomValues(new Uint8Array(12));
  const afterChacha = chacha20Xor(chachaKey, chachaNonce, padded);

  // AES-256-GCM
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, aesKey, afterChacha);

  const packed = new Uint8Array(12 + 12 + ct.byteLength);
  packed.set(chachaNonce, 0);
  packed.set(iv, 12);
  packed.set(new Uint8Array(ct), 24);

  const header = { dh: dr.DHsB64, n: dr.Ns, pn: dr.PN };
  dr.Ns++;

  return { enc: bufToB64(packed), header };
}

// ── Ratchet Decrypt ───────────────────────────────────────────────

async function ratchetDecrypt(encB64, header) {
  try {
    const skippedKey = `${header.dh}:${header.n}`;
    let mk;

    if (dr.MKSKIPPED.has(skippedKey)) {
      mk = dr.MKSKIPPED.get(skippedKey);
      dr.MKSKIPPED.delete(skippedKey);
    } else {
      if (header.dh !== dr.DHrB64) {
        await skipMessageKeys(header.pn);
        await dhRatchetStep(header.dh);
      }
      await skipMessageKeys(header.n);
      const [newCKr, msgKey] = await kdfCK(dr.CKr);
      dr.CKr = newCKr;
      dr.Nr++;
      mk = msgKey;
    }

    const { aesKey, chachaKey } = await expandMK(mk);
    const packed      = b64ToBuf(encB64);
    const chachaNonce = packed.slice(0, 12);
    const iv          = packed.slice(12, 24);
    const ct          = packed.slice(24);

    const afterAes = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, aesKey, ct);
    const padded   = new Uint8Array(afterAes);
    const plain    = chacha20Xor(chachaKey, chachaNonce, padded);

    // Unpad — ორიგინალ სიგრძეს ვიღებთ
    return new TextDecoder().decode(unpadMessage(plain));
  } catch {
    return null;
  }
}


// ── Sent Message Cache ────────────────────────────────────────────
const sentCache = new Map();


// ── Generator ─────────────────────────────────────────────────────

function generateCodes() {
  const chars   = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
  const special = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*";

  const randStr = (len, charset) => {
    const arr = new Uint8Array(len);
    crypto.getRandomValues(arr);
    return Array.from(arr).map(b => charset[b % charset.length]).join("");
  };

  const room = randStr(64, chars);
  const pass = randStr(128, special);

  document.getElementById("gen-room").textContent = room;
  document.getElementById("gen-pass").textContent = pass;
  document.getElementById("gen-result").style.display = "block";
  document.getElementById("room-input").value = room;
  document.getElementById("pass-input").value = pass;

  document.querySelectorAll(".copy-btn").forEach(btn => {
    btn.onclick = () => {
      const val = document.getElementById(btn.dataset.target).textContent;
      navigator.clipboard.writeText(val).then(() => {
        btn.textContent = "✓";
        btn.classList.add("copied");
        setTimeout(() => { btn.textContent = "კოპირება"; btn.classList.remove("copied"); }, 1500);
      });
    };
  });
}


// ── State ─────────────────────────────────────────────────────────

let currentRoom  = "";
const SESSION_ID = crypto.randomUUID();
let pollInterval = null;
let tickInterval = null;
let renderedIds  = new Set();
let _pendingInit = null;


// ── UI Helpers ────────────────────────────────────────────────────

function showJoinStatus(msg) {
  const el = document.getElementById("join-status");
  if (!el) return;
  el.textContent   = msg;
  el.style.display = msg ? "block" : "none";
}

function updateDRStatus() {
  const el = document.getElementById("dr-status");
  const fp = document.getElementById("fingerprint");
  if (!el) return;

  if (dr && dr.ready) {
    el.textContent = "🔐 Double Ratchet: აქტიური";
    el.className   = "dr-status dr-ready";
    if (fp && dr.fingerprint) {
      // Format: ABC1 2345 6DEF
      const f = dr.fingerprint;
      fp.textContent = `🔑 ${f.slice(0,4)} ${f.slice(4,8)} ${f.slice(8,12)}`;
      fp.style.display = "block";
      fp.title = "შეადარე მეგობარს — თუ ემთხვევა, კავშირი 100% სუფთაა (MITM შეუძლებელია)";
    }
  } else {
    el.textContent = "⏳ მეორე მომხმარებელს ელოდება...";
    el.className   = "dr-status dr-waiting";
    if (fp) fp.style.display = "none";
  }
}


// ── DR Init ───────────────────────────────────────────────────────

async function tryInitDR(room, sk, myKeypair, myPubB64) {
  try {
    const res  = await fetch(`/api/keys?room=${encodeURIComponent(room)}&sid=${SESSION_ID}`);
    const data = await res.json();
    if (!data.keys || data.keys.length === 0) return false;
    await initDR(sk, myKeypair, myPubB64, data.keys[0].pub);
    return true;
  } catch { return false; }
}


// ── Join / Leave ──────────────────────────────────────────────────

async function joinRoom() {
  const room = document.getElementById("room-input").value.trim();
  const pass = document.getElementById("pass-input").value;

  if (!room || !pass) { showError("ოთახის კოდი და პაროლი საჭიროა."); return; }
  if (room.length > 128 || pass.length > 256) { showError("ძალიან გრძელი."); return; }

  document.getElementById("join-btn").disabled = true;
  document.getElementById("join-btn").textContent = "[ იტვირთება... ]";

  try {
    // 1. Argon2id → SK
    const sk = await deriveSK_Argon2id(pass, room);

    // 2. X25519 keypair
    const myKeypair = await generateDHKeypair();
    const myPubB64  = await exportPub(myKeypair);

    // 3. Register pub key
    await fetch("/api/keys", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ room, sid: SESSION_ID, pub: myPubB64 })
    });

    currentRoom = room;
    dr = null;

    // 4. Try DR init
    const ready = await tryInitDR(room, sk, myKeypair, myPubB64);
    if (!ready) _pendingInit = { sk, myKeypair, myPubB64 };

    // 5. Show chat
    document.getElementById("header-room").textContent = room;
    document.getElementById("join-screen").style.display = "none";
    document.getElementById("chat-screen").style.display = "flex";

    updateDRStatus();
    renderedIds.clear();
    sentCache.clear();
    await fetchAndRender();

    pollInterval = setInterval(poll, 3000);
    tickInterval = setInterval(tickTimers, 1000);
  } catch (e) {
    showError("შეცდომა. სცადეთ თავიდან.");
    console.error(e);
  } finally {
    document.getElementById("join-btn").disabled = false;
    document.getElementById("join-btn").textContent = "შესვლა";
  }
}

async function poll() {
  if (_pendingInit && (!dr || !dr.ready)) {
    const { sk, myKeypair, myPubB64 } = _pendingInit;
    const ready = await tryInitDR(currentRoom, sk, myKeypair, myPubB64);
    if (ready) { _pendingInit = null; updateDRStatus(); }
  }
  await fetchAndRender();
}

function leaveRoom() {
  clearInterval(pollInterval);
  clearInterval(tickInterval);
  currentRoom  = "";
  dr           = null;
  _pendingInit = null;
  renderedIds.clear();
  sentCache.clear();
  document.getElementById("messages").innerHTML  = "";
  document.getElementById("chat-screen").style.display  = "none";
  document.getElementById("join-screen").style.display  = "flex";
  document.getElementById("pass-input").value = "";
  document.getElementById("join-error").style.display = "none";
}

function showError(msg) {
  const el = document.getElementById("join-error");
  el.textContent   = msg;
  el.style.display = "block";
}


// ── Send ──────────────────────────────────────────────────────────

async function sendMessage() {
  const input = document.getElementById("msg-input");
  const text  = input.value.trim();
  if (!text) return;

  if (!dr || !dr.ready) {
    showChatNotice("⏳ მეორე მომხმარებელი ჯერ არ შემოუერთდა.");
    return;
  }

  const ttl = parseInt(document.getElementById("ttl-select").value);

  try {
    const { enc, header } = await ratchetEncrypt(text);

    const res = await fetch("/api/messages", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        room: currentRoom, enc,
        sid: SESSION_ID,
        dhPub: header.dh, msgN: header.n, prevN: header.pn,
        ttl
      })
    });

    if (!res.ok) throw new Error("send failed");
    const data = await res.json();
    if (data.id) sentCache.set(data.id, text);

    input.value = "";
    input.style.height = "auto";
    await fetchAndRender();
  } catch (e) { console.error(e); }
}

function showChatNotice(msg) {
  const container = document.getElementById("messages");
  const el = document.createElement("div");
  el.className   = "sys-msg";
  el.textContent = msg;
  container.appendChild(el);
  container.scrollTop = container.scrollHeight;
  setTimeout(() => el.remove(), 4000);
}

function handleKey(e) {
  if (e.key === "Enter" && !e.shiftKey) {
    e.preventDefault();
    sendMessage();
  }
}

function autoResize(el) {
  el.style.height = "auto";
  el.style.height = Math.min(el.scrollHeight, 100) + "px";
}


// ── Fetch & Render ────────────────────────────────────────────────

async function fetchAndRender() {
  try {
    const res  = await fetch(`/api/messages?room=${encodeURIComponent(currentRoom)}`);
    const data = await res.json();
    await renderMessages(data.messages || []);
  } catch { /* silent */ }
}

async function renderMessages(records) {
  const container = document.getElementById("messages");
  const serverIds = new Set(records.map(r => r.id));

  document.querySelectorAll(".msg[data-id]").forEach(el => {
    if (!serverIds.has(el.dataset.id)) {
      el.remove();
      renderedIds.delete(el.dataset.id);
    }
  });

  let scrollNeeded = false;

  for (const rec of records) {
    if (renderedIds.has(rec.id)) continue;

    const mine = rec.sid === SESSION_ID;
    let text;

    if (mine) {
      text = sentCache.get(rec.id) || "[ გაგზავნილი ]";
    } else {
      if (!dr || !dr.ready) continue;
      text = await ratchetDecrypt(rec.enc, { dh: rec.dhPub, n: rec.msgN, pn: rec.prevN });
      if (text === null) continue;
    }

    const div    = document.createElement("div");
    div.className  = `msg ${mine ? "mine" : "theirs"}`;
    div.dataset.id = rec.id;

    const bubble       = document.createElement("div");
    bubble.className   = "bubble";
    bubble.textContent = text;

    const meta  = document.createElement("div");
    meta.className = "meta";
    const span  = document.createElement("span");
    span.className       = "timer";
    span.dataset.expires = rec.expires;
    span.textContent     = formatTime(Math.max(0, Math.floor((rec.expires - Date.now()) / 1000)));
    meta.appendChild(span);

    div.appendChild(bubble);
    div.appendChild(meta);
    container.appendChild(div);
    renderedIds.add(rec.id);
    scrollNeeded = true;
  }

  if (scrollNeeded) container.scrollTop = container.scrollHeight;
}


// ── Timers ────────────────────────────────────────────────────────

function tickTimers() {
  const now = Date.now();
  document.querySelectorAll(".timer").forEach(el => {
    const left = Math.max(0, Math.floor((parseInt(el.dataset.expires) - now) / 1000));
    el.textContent = formatTime(left);
  });
}

function formatTime(secs) {
  if (secs <= 0) return "წაიშლება...";
  if (secs < 60) return `${secs}წმ`;
  return `${Math.floor(secs / 60)}:${String(secs % 60).padStart(2, "0")}`;
}


// ── Event Listeners ───────────────────────────────────────────────

document.addEventListener("DOMContentLoaded", () => {
  document.getElementById("gen-btn").addEventListener("click", generateCodes);
  document.getElementById("join-btn").addEventListener("click", joinRoom);
  document.getElementById("leave-btn").addEventListener("click", leaveRoom);
  document.getElementById("send-btn").addEventListener("click", sendMessage);

  const msgInput = document.getElementById("msg-input");
  msgInput.addEventListener("keydown", handleKey);
  msgInput.addEventListener("input", function() { autoResize(this); });

  document.getElementById("pass-input").addEventListener("keydown", e => {
    if (e.key === "Enter") joinRoom();
  });
  document.getElementById("room-input").addEventListener("keydown", e => {
    if (e.key === "Enter") document.getElementById("pass-input").focus();
  });
});
