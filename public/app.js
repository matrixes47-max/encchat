"use strict";

// ════════════════════════════════════════════════════════════════════
//  enc.chat v2 — Double Ratchet + AES-256-GCM + ChaCha20
//
//  კრიპტოგრაფიული სტეკი:
//    1. PBKDF2-SHA256 (100k iter) → საერთო საიდუმლო (SK)
//    2. P-256 ECDH                → DH key exchange
//    3. HKDF-SHA256               → Root Key + Chain Keys
//    4. HMAC-SHA256               → Message Keys (KDF_CK)
//    5. ChaCha20                  → პირველი შიფრი
//    6. AES-256-GCM               → მეორე შიფრი
//    7. HTTPS/TLS                 → მესამე შიფრი (ტრანსპორტი)
//
//  Double Ratchet იძლევა:
//    ✓ Forward Secrecy  — გასული გასაღებები იშლება
//    ✓ Break-in Recovery — მომავალი შეტყობინებები დაცულია
//    ✓ ყოველ შეტყობინებას უნიკალური გასაღები
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
    for (let j = 0; j < 64 && i+j < data.length; j++) {
      out[i+j] = data[i+j] ^ block[j];
    }
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


// ── KDF Functions ─────────────────────────────────────────────────

// HKDF-SHA256: ikm + salt + info → length bytes
async function hkdf(ikm, salt, info, length = 32) {
  const key = await crypto.subtle.importKey(
    "raw",
    ikm instanceof Uint8Array ? ikm : new Uint8Array(ikm),
    "HKDF",
    false,
    ["deriveBits"]
  );
  const bits = await crypto.subtle.deriveBits(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: salt instanceof Uint8Array ? salt : new Uint8Array(salt),
      info: typeof info === "string"
        ? new TextEncoder().encode(info)
        : (info instanceof Uint8Array ? info : new Uint8Array(info))
    },
    key,
    length * 8
  );
  return new Uint8Array(bits);
}

// HMAC-SHA256
async function hmacSHA256(key, data) {
  const k = await crypto.subtle.importKey(
    "raw",
    key instanceof Uint8Array ? key : new Uint8Array(key),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  return new Uint8Array(await crypto.subtle.sign("HMAC", k, data));
}

// KDF_RK — Double Ratchet root key ratchet
// (rk, dh_output) → (new_rk, chain_key)   [HKDF-based]
async function kdfRK(rk, dhOut) {
  const out64 = await hkdf(dhOut, rk, "enc.chat-rk-v2", 64);
  return [out64.slice(0, 32), out64.slice(32)];
}

// KDF_CK — Double Ratchet chain key ratchet
// ck → (new_ck, message_key)   [HMAC-SHA256, Signal-style]
async function kdfCK(ck) {
  const mk    = await hmacSHA256(ck, new Uint8Array([0x01]));
  const newCK = await hmacSHA256(ck, new Uint8Array([0x02]));
  return [newCK, mk];
}

// Expand 32-byte message key → AES-256 CryptoKey + ChaCha20 32-byte key
async function expandMK(mk) {
  const aesBytes    = await hkdf(mk, new Uint8Array(32), "enc.chat-mk-aes-v2",    32);
  const chachaBytes = await hkdf(mk, new Uint8Array(32), "enc.chat-mk-chacha-v2", 32);
  const aesKey = await crypto.subtle.importKey(
    "raw", aesBytes, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]
  );
  return { aesKey, chachaKey: chachaBytes };
}


// ── ECDH P-256 ────────────────────────────────────────────────────

async function generateDHKeypair() {
  return crypto.subtle.generateKey(
    { name: "ECDH", namedCurve: "P-256" },
    true,
    ["deriveBits"]
  );
}

async function dhExchange(privateKey, publicKey) {
  const bits = await crypto.subtle.deriveBits(
    { name: "ECDH", public: publicKey },
    privateKey,
    256
  );
  return new Uint8Array(bits);
}

async function exportPub(keypair) {
  const raw = await crypto.subtle.exportKey("raw", keypair.publicKey);
  return bufToB64(raw);
}

async function importPub(b64) {
  return crypto.subtle.importKey(
    "raw",
    b64ToBuf(b64),
    { name: "ECDH", namedCurve: "P-256" },
    true,
    []
  );
}


// ── Initial Shared Secret from password ───────────────────────────

async function deriveSK(password, roomId) {
  const enc = new TextEncoder();
  const raw = await crypto.subtle.importKey(
    "raw", enc.encode(password), "PBKDF2", false, ["deriveBits"]
  );
  const bits = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      salt: enc.encode("enc.chat-dr-sk-" + roomId.toLowerCase().trim()),
      iterations: 100_000,
      hash: "SHA-256"
    },
    raw,
    256
  );
  return new Uint8Array(bits);
}


// ════════════════════════════════════════════════════════════════════
//  DOUBLE RATCHET
// ════════════════════════════════════════════════════════════════════

let dr = null;

function newDRState() {
  return {
    DHs:       null,          // CryptoKeyPair  (ჩვენი sending keypair)
    DHsB64:    null,          // string         (ჩვენი pub key, base64)
    DHr:       null,          // CryptoKey      (მათი pub key)
    DHrB64:    null,          // string
    RK:        null,          // Uint8Array(32) — root key
    CKs:       null,          // Uint8Array(32) — sending chain key
    CKr:       null,          // Uint8Array(32) — receiving chain key
    Ns:        0,             // გაგზავნილი შეტყობინებების რაოდენობა
    Nr:        0,             // მიღებული შეტყობინებების რაოდენობა
    PN:        0,             // წინა chain-ის სიგრძე
    MKSKIPPED: new Map(),     // `dhPubB64:n` → Uint8Array(32)
    ready:     false
  };
}

// ── DR Initialization ─────────────────────────────────────────────
//
// ორივე მხარე:
//   1. PBKDF2-ით გამოიყვანს SK-ს (პაროლი + ოთახი)
//   2. P-256 keypair-ს გენერირებს, სერვერს აგზავნის pub key-ს
//   3. მეორე მხარის pub key-ს ელოდება
//   4. ECDH DH exchange: dh_out = ECDH(my_priv, their_pub)
//   5. HKDF(dh_out, SK) → RK + chainA + chainB
//   6. Lexicographic ordering: პატარა pub key = "Alice" (CKs=chainA)
//
async function initDR(sk, myKeypair, myPubB64, theirPubB64) {
  const theirPub = await importPub(theirPubB64);
  const dhOut    = await dhExchange(myKeypair.privateKey, theirPub);

  // 64 bytes: first half = chainA, second half = chainB
  const init64 = await hkdf(dhOut, sk, "enc.chat-dr-init-v2", 64);
  const chainA = new Uint8Array(init64.slice(0, 32));
  const chainB = new Uint8Array(init64.slice(32));

  // Root key
  const rk = await hkdf(dhOut, sk, "enc.chat-dr-root-v2", 32);

  // Alice = lexicographically smaller pub key → sends with chainA
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
}

// ── DH Ratchet Step ───────────────────────────────────────────────
// ახალი DH pub key-ის მიღებისას:
//   1. Receiving ratchet: ECDH(my_old_priv, their_new_pub) → new CKr
//   2. ახალი sending keypair-ის გენერაცია
//   3. Sending ratchet:  ECDH(my_new_priv, their_new_pub) → new CKs
//
async function dhRatchetStep(theirNewPubB64) {
  dr.PN     = dr.Ns;
  dr.Ns     = 0;
  dr.Nr     = 0;
  dr.DHrB64 = theirNewPubB64;
  dr.DHr    = await importPub(theirNewPubB64);

  // Receiving ratchet
  const dh1 = await dhExchange(dr.DHs.privateKey, dr.DHr);
  const [rk1, ckr] = await kdfRK(dr.RK, dh1);

  // ახალი sending keypair (ძველი private key-ი იშლება)
  dr.DHs    = await generateDHKeypair();
  dr.DHsB64 = await exportPub(dr.DHs);

  // Sending ratchet
  const dh2 = await dhExchange(dr.DHs.privateKey, dr.DHr);
  const [rk2, cks] = await kdfRK(rk1, dh2);

  dr.RK  = rk2;
  dr.CKr = ckr;
  dr.CKs = cks;
}

// ── Skip Message Keys (for out-of-order messages) ─────────────────
async function skipMessageKeys(until) {
  if (until - dr.Nr > 100) throw new Error("Too many skipped messages");
  while (dr.Nr < until) {
    const [newCKr, mk] = await kdfCK(dr.CKr);
    dr.MKSKIPPED.set(`${dr.DHrB64}:${dr.Nr}`, mk);
    dr.CKr = newCKr;
    dr.Nr++;
  }
}

// ── Ratchet Encrypt ───────────────────────────────────────────────
async function ratchetEncrypt(text) {
  // Chain key ratchet → message key
  const [newCKs, mk] = await kdfCK(dr.CKs);
  dr.CKs = newCKs;

  // Expand message key → AES + ChaCha20 keys
  const { aesKey, chachaKey } = await expandMK(mk);

  const plainBytes = new TextEncoder().encode(text);

  // Layer 1: ChaCha20
  const chachaNonce = crypto.getRandomValues(new Uint8Array(12));
  const afterChacha = chacha20Xor(chachaKey, chachaNonce, plainBytes);

  // Layer 2: AES-256-GCM
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, aesKey, afterChacha);

  // Pack: chachaNonce(12) + iv(12) + ciphertext
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
      // out-of-order: skipped key-ი უკვე გვაქვს
      mk = dr.MKSKIPPED.get(skippedKey);
      dr.MKSKIPPED.delete(skippedKey);
    } else {
      if (header.dh !== dr.DHrB64) {
        // ახალი DH public key → ratchet step
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

    // Layer 1: AES-256-GCM decrypt
    const afterAes = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, aesKey, ct);

    // Layer 2: ChaCha20 decrypt
    const plain = chacha20Xor(chachaKey, chachaNonce, new Uint8Array(afterAes));
    return new TextDecoder().decode(plain);
  } catch {
    return null;
  }
}


// ── Sent Message Cache ────────────────────────────────────────────
// DR-ით გაგზავნილი შეტყობინებების გასაღები სამუდამოდ იშლება —
// plain text-ს ვინახავთ RAM-ში (გვერდის დახურვამდე)
const sentCache = new Map(); // msgId → plaintext


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


// ── Session State ─────────────────────────────────────────────────
let currentRoom    = "";
const SESSION_ID   = crypto.randomUUID();
let pollInterval   = null;
let tickInterval   = null;
let renderedIds    = new Set();
let _pendingInit   = null;  // { sk, myKeypair, myPubB64 } — DR init pending


// ── DR init helpers ───────────────────────────────────────────────

async function tryInitDR(room, sk, myKeypair, myPubB64) {
  try {
    const res  = await fetch(`/api/keys?room=${encodeURIComponent(room)}&sid=${SESSION_ID}`);
    const data = await res.json();
    if (!data.keys || data.keys.length === 0) return false;

    const theirPubB64 = data.keys[0].pub;
    await initDR(sk, myKeypair, myPubB64, theirPubB64);
    return true;
  } catch {
    return false;
  }
}

function updateDRStatus() {
  const el = document.getElementById("dr-status");
  if (!el) return;
  if (dr && dr.ready) {
    el.textContent = "🔐 Double Ratchet: აქტიური";
    el.className   = "dr-status dr-ready";
  } else {
    el.textContent = "⏳ მეორე მომხმარებელს ელოდება...";
    el.className   = "dr-status dr-waiting";
  }
}


// ── Join / Leave ──────────────────────────────────────────────────

async function joinRoom() {
  const room = document.getElementById("room-input").value.trim();
  const pass = document.getElementById("pass-input").value;

  if (!room || !pass) { showError("ოთახის კოდი და პაროლი საჭიროა."); return; }
  if (room.length > 128 || pass.length > 256) { showError("ძალიან გრძელი."); return; }

  try {
    // 1. Shared secret from password
    const sk = await deriveSK(pass, room);

    // 2. Generate our ECDH keypair
    const myKeypair = await generateDHKeypair();
    const myPubB64  = await exportPub(myKeypair);

    // 3. Register our public key on server
    await fetch("/api/keys", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ room, sid: SESSION_ID, pub: myPubB64 })
    });

    currentRoom = room;
    dr = null;

    // 4. Try to initialize DR immediately
    const ready = await tryInitDR(room, sk, myKeypair, myPubB64);
    if (!ready) {
      _pendingInit = { sk, myKeypair, myPubB64 };
    }

    // 5. Show chat screen
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
  }
}

async function poll() {
  // Try to complete DR init if pending
  if (_pendingInit && (!dr || !dr.ready)) {
    const { sk, myKeypair, myPubB64 } = _pendingInit;
    const ready = await tryInitDR(currentRoom, sk, myKeypair, myPubB64);
    if (ready) {
      _pendingInit = null;
      updateDRStatus();
    }
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
  document.getElementById("chat-screen").style.display = "none";
  document.getElementById("join-screen").style.display = "flex";
  document.getElementById("pass-input").value = "";
}

function showError(msg) {
  const el = document.getElementById("join-error");
  el.textContent    = msg;
  el.style.display  = "block";
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
        room:  currentRoom,
        enc,
        sid:   SESSION_ID,
        dhPub: header.dh,
        msgN:  header.n,
        prevN: header.pn,
        ttl
      })
    });

    if (!res.ok) throw new Error("send failed");
    const data = await res.json();

    // Cache plaintext (our own messages can't be re-decrypted with DR)
    if (data.id) sentCache.set(data.id, text);

    input.value = "";
    input.style.height = "auto";
    await fetchAndRender();
  } catch (e) {
    console.error("Send error:", e);
  }
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

  // Remove expired messages from DOM
  document.querySelectorAll(".msg, .sys-msg[data-id]").forEach(el => {
    if (el.dataset.id && !serverIds.has(el.dataset.id)) {
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
      // ჩვენი შეტყობინება — cache-დან
      text = sentCache.get(rec.id) || "[ გაგზავნილი შეტყობინება ]";
    } else {
      // მათი შეტყობინება — ratchet decrypt
      if (!dr || !dr.ready) continue;
      const header = { dh: rec.dhPub, n: rec.msgN, pn: rec.prevN };
      text = await ratchetDecrypt(rec.enc, header);
      if (text === null) continue;
    }

    const div    = document.createElement("div");
    div.className  = `msg ${mine ? "mine" : "theirs"}`;
    div.dataset.id = rec.id;

    const bubble       = document.createElement("div");
    bubble.className   = "bubble";
    bubble.textContent = text;

    const meta = document.createElement("div");
    meta.className = "meta";

    const span = document.createElement("span");
    span.className          = "timer";
    span.dataset.expires    = rec.expires;
    span.textContent        = formatTime(Math.max(0, Math.floor((rec.expires - Date.now()) / 1000)));
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
  msgInput.addEventListener("input", function () { autoResize(this); });

  document.getElementById("pass-input").addEventListener("keydown", e => {
    if (e.key === "Enter") joinRoom();
  });
  document.getElementById("room-input").addEventListener("keydown", e => {
    if (e.key === "Enter") document.getElementById("pass-input").focus();
  });
});
