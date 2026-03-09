"use strict";

// ══════════════════════════════════════════════════════
// CRYPTO — ყველაფერი client-ზე, სერვერი ვერაფერს ხედავს
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

async function encryptMsg(text, key) {
  const enc = new TextEncoder();
  const iv  = crypto.getRandomValues(new Uint8Array(12));
  const ct  = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, enc.encode(text));
  const buf = new Uint8Array(12 + ct.byteLength);
  buf.set(iv);
  buf.set(new Uint8Array(ct), 12);
  return btoa(String.fromCharCode(...buf));
}

async function decryptMsg(b64, key) {
  try {
    const buf   = Uint8Array.from(atob(b64), c => c.charCodeAt(0));
    const plain = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: buf.slice(0, 12) },
      key,
      buf.slice(12)
    );
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

  const room = randStr(24, chars);
  const pass = randStr(32, special);

  document.getElementById("gen-room").textContent = room;
  document.getElementById("gen-pass").textContent = pass;
  document.getElementById("gen-result").style.display = "block";

  // ავტომატურად შეიყვანე ველებში
  document.getElementById("room-input").value = room;
  document.getElementById("pass-input").value = pass;
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

  document.querySelectorAll(".copy-btn").forEach(btn => {
    btn.addEventListener("click", () => {
      const val = document.getElementById(btn.dataset.target).textContent;
      navigator.clipboard.writeText(val).then(() => {
        btn.textContent = "✓";
        btn.classList.add("copied");
        setTimeout(() => { btn.textContent = "კოპირება"; btn.classList.remove("copied"); }, 1500);
      });
    });
  });

  document.getElementById("join-screen").querySelector("button:not(#gen-btn):not(.copy-btn)").addEventListener("click", joinRoom);
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
