"use strict";

// ══════════════════════════════════════════════════════
// CHACHA20 — Pure JS implementation (Web Crypto არ იცნობს)
// ══════════════════════════════════════════════════════

function chacha20Block(key, counter, nonce) {
  const c = new Uint32Array(16);
  // constants
  c[0]=0x61707865; c[1]=0x3320646e; c[2]=0x79622d32; c[3]=0x6b206574;
  // key (8 x 32bit)
  const k = new DataView(key.buffer, key.byteOffset);
  for (let i=0;i<8;i++) c[4+i] = k.getUint32(i*4, true);
  // counter + nonce
  c[12] = counter;
  const n = new DataView(nonce.buffer, nonce.byteOffset);
  c[13] = n.getUint32(0, true);
  c[14] = n.getUint32(4, true);
  c[15] = n.getUint32(8, true);

  const x = new Uint32Array(c);
  const rot = (v,n) => (v<<n)|(v>>>(32-n));
  const qr = (a,b,cc,d) => {
    x[a]+=x[b]; x[d]=rot(x[d]^x[a],16);
    x[cc]+=x[d]; x[b]=rot(x[b]^x[cc],12);
    x[a]+=x[b]; x[d]=rot(x[d]^x[a],8);
    x[cc]+=x[d]; x[b]=rot(x[b]^x[cc],7);
  };
  for (let i=0;i<10;i++) {
    qr(0,4,8,12); qr(1,5,9,13); qr(2,6,10,14); qr(3,7,11,15);
    qr(0,5,10,15); qr(1,6,11,12); qr(2,7,8,13); qr(3,4,9,14);
  }
  for (let i=0;i<16;i++) x[i]+=c[i];
  return new Uint8Array(x.buffer);
}

function chacha20Xor(keyBytes, nonce, data) {
  const out = new Uint8Array(data.length);
  for (let i=0; i<data.length; i+=64) {
    const block = chacha20Block(keyBytes, Math.floor(i/64), nonce);
    for (let j=0; j<64 && i+j<data.length; j++) {
      out[i+j] = data[i+j] ^ block[j];
    }
  }
  return out;
}

// ══════════════════════════════════════════════════════
// CRYPTO — AES-256-GCM + ChaCha20 ორმაგი შიფრი
// ══════════════════════════════════════════════════════

async function deriveKey(password, roomId) {
  const enc = new TextEncoder();
  const raw = await crypto.subtle.importKey(
    "raw", enc.encode(password), "PBKDF2", false, ["deriveKey"]
  );
  return crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt: enc.encode(roomId.toLowerCase().trim()),
      iterations: 100000,
      hash: "SHA-256"
    },
    raw,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

// ChaCha20 გასაღები პაროლიდან (32 byte)
async function deriveChaChaKey(password, roomId) {
  const enc = new TextEncoder();
  const raw = await crypto.subtle.importKey(
    "raw", enc.encode(password), "PBKDF2", false, ["deriveBits"]
  );
  const bits = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      salt: enc.encode("chacha20-" + roomId.toLowerCase().trim()),
      iterations: 100000,
      hash: "SHA-256"
    },
    raw, 256
  );
  return new Uint8Array(bits);
}

// პაროლი და roomId globally ვინახავთ ChaCha20-სთვის
let _chachaKey = null;

async function encryptMsg(text, aesKey) {
  const enc = new TextEncoder();
  const plainBytes = enc.encode(text);

  // ── ეტაპი 1: ChaCha20 ──
  const chachaNonce = crypto.getRandomValues(new Uint8Array(12));
  const afterChacha = chacha20Xor(_chachaKey, chachaNonce, plainBytes);

  // ── ეტაპი 2: AES-256-GCM ──
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, aesKey, afterChacha);

  // ── შეფუთვა: chachaNonce(12) + iv(12) + ciphertext ──
  const buf = new Uint8Array(12 + 12 + ct.byteLength);
  buf.set(chachaNonce, 0);
  buf.set(iv, 12);
  buf.set(new Uint8Array(ct), 24);
  return btoa(String.fromCharCode(...buf));
}

async function decryptMsg(b64, aesKey) {
  try {
    const buf = Uint8Array.from(atob(b64), c => c.charCodeAt(0));
    const chachaNonce = buf.slice(0, 12);
    const iv          = buf.slice(12, 24);
    const ct          = buf.slice(24);

    // ── ეტაპი 1: AES-256-GCM გაშიფვრა ──
    const afterAes = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, aesKey, ct);

    // ── ეტაპი 2: ChaCha20 გაშიფვრა ──
    const plain = chacha20Xor(_chachaKey, chachaNonce, new Uint8Array(afterAes));
    return new TextDecoder().decode(plain);
  } catch { return null; }
}

// ══════════════════════════════════════════════════════
// GENERATOR
// ══════════════════════════════════════════════════════

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

// ══════════════════════════════════════════════════════
// STATE
// ══════════════════════════════════════════════════════

let currentKey  = null;
let currentRoom = "";
const SESSION_ID = crypto.randomUUID();

let pollInterval = null;
let tickInterval = null;
let renderedIds  = new Set();

// ══════════════════════════════════════════════════════
// JOIN / LEAVE
// ══════════════════════════════════════════════════════

async function joinRoom() {
  const room = document.getElementById("room-input").value.trim();
  const pass = document.getElementById("pass-input").value;

  if (!room || !pass) { showError("ოთახის კოდი და პაროლი საჭიროა."); return; }
  if (room.length > 128 || pass.length > 256) { showError("ძალიან გრძელი."); return; }

  try {
    currentKey  = await deriveKey(pass, room);
    _chachaKey  = await deriveChaChaKey(pass, room);
    currentRoom = room;

    document.getElementById("header-room").textContent = room;
    document.getElementById("join-screen").style.display = "none";
    document.getElementById("chat-screen").style.display = "flex";

    renderedIds.clear();
    await fetchAndRender();

    pollInterval = setInterval(fetchAndRender, 3000);
    tickInterval = setInterval(tickTimers, 1000);
  } catch {
    showError("შეცდომა. სცადეთ თავიდან.");
  }
}

function leaveRoom() {
  clearInterval(pollInterval);
  clearInterval(tickInterval);
  currentKey  = null;
  currentRoom = "";
  renderedIds.clear();
  document.getElementById("messages").innerHTML = "";
  document.getElementById("chat-screen").style.display = "none";
  document.getElementById("join-screen").style.display = "flex";
  document.getElementById("pass-input").value = "";
}

function showError(msg) {
  const el = document.getElementById("join-error");
  el.textContent = msg;
  el.style.display = "block";
}

// ══════════════════════════════════════════════════════
// SEND
// ══════════════════════════════════════════════════════

async function sendMessage() {
  const input = document.getElementById("msg-input");
  const text  = input.value.trim();
  if (!text || !currentKey) return;

  const ttl = parseInt(document.getElementById("ttl-select").value);
  const enc = await encryptMsg(text, currentKey);

  try {
    const res = await fetch("/api/messages", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ room: currentRoom, enc, sid: SESSION_ID, ttl })
    });
    if (!res.ok) throw new Error("send failed");
    input.value = "";
    input.style.height = "auto";
    await fetchAndRender();
  } catch { /* silent */ }
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

// ══════════════════════════════════════════════════════
// FETCH & RENDER
// ══════════════════════════════════════════════════════

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

  document.querySelectorAll(".msg, .sys-msg").forEach(el => {
    if (el.dataset.id && !serverIds.has(el.dataset.id)) {
      el.remove();
      renderedIds.delete(el.dataset.id);
    }
  });

  let scrollNeeded = false;

  for (const rec of records) {
    if (renderedIds.has(rec.id)) continue;
    const text = await decryptMsg(rec.enc, currentKey);
    if (text === null) continue;

    const mine   = rec.sid === SESSION_ID;
    const div    = document.createElement("div");
    div.className = `msg ${mine ? "mine" : "theirs"}`;
    div.dataset.id = rec.id;

    const bubble = document.createElement("div");
    bubble.className = "bubble";
    bubble.textContent = text;

    const meta = document.createElement("div");
    meta.className = "meta";
    const secsLeft = Math.max(0, Math.floor((rec.expires - Date.now()) / 1000));
    const span = document.createElement("span");
    span.className = "timer";
    span.dataset.expires = rec.expires;
    span.textContent = formatTime(secsLeft);
    meta.appendChild(span);

    div.appendChild(bubble);
    div.appendChild(meta);
    container.appendChild(div);
    renderedIds.add(rec.id);
    scrollNeeded = true;
  }

  if (scrollNeeded) container.scrollTop = container.scrollHeight;
}

// ══════════════════════════════════════════════════════
// TIMERS
// ══════════════════════════════════════════════════════

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

// ══════════════════════════════════════════════════════
// EVENT LISTENERS (no inline handlers needed)
// ══════════════════════════════════════════════════════

document.addEventListener("DOMContentLoaded", () => {
  document.getElementById("gen-btn").addEventListener("click", generateCodes);
  document.getElementById("join-btn").addEventListener("click", joinRoom);
  document.getElementById("leave-btn").addEventListener("click", leaveRoom);
  document.getElementById("send-btn").addEventListener("click", sendMessage);

  document.getElementById("msg-input").addEventListener("keydown", handleKey);
  document.getElementById("msg-input").addEventListener("input", function() { autoResize(this); });

  // Enter on join screen
  document.getElementById("pass-input").addEventListener("keydown", e => {
    if (e.key === "Enter") joinRoom();
  });
  document.getElementById("room-input").addEventListener("keydown", e => {
    if (e.key === "Enter") document.getElementById("pass-input").focus();
  });
});
