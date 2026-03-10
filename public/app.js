"use strict";

// ════════════════════════════════════════════════════════════════════
//  enc.chat v4 — Post-Quantum Maximum Security Edition
//
//  კრიპტოგრაფიული სტეკი:
//    1. Argon2id (mem=64MB, iter=3) → SK
//    2. PQXDH Hybrid Key Exchange:
//         X25519 ECDH              → კლასიკური DH
//         ML-KEM-768 (Kyber)       → კვანტური KEM
//         SK = HKDF(x25519_dh ‖ mlkem_ss) → ორივე გარე ერთდროულად
//    3. HKDF-SHA256                → Root Key + Chain Keys
//    4. HMAC-SHA256 (KDF_CK)       → Message Keys
//    5. Message Padding (256B)     → სიგრძე არ ჩანს
//    6. ChaCha20                   → პირველი შიფრი
//    7. AES-256-GCM                → მეორე შიფრი
//    8. HTTPS/TLS                  → მესამე შიფრი
//    + Key Fingerprint             → MITM შეუძლებელია
//
//  კვანტური კომპიუტერი ვერ გატეხს — ML-KEM-768 NIST 2024 სტანდარტი
//  Signal PQXDH-ს 2023-ში დაამატა — ჩვენ ახლა ვამატებთ
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

function concatBuffers(...arrays) {
  const total = arrays.reduce((n, a) => n + a.length, 0);
  const out   = new Uint8Array(total);
  let offset  = 0;
  for (const a of arrays) { out.set(a, offset); offset += a.length; }
  return out;
}


// ── Room ID Hashing ───────────────────────────────────────────────
// სერვერი room-ის სახელს არასოდეს ხედავს — მხოლოდ hash-ს ვაგზავნით
async function hashRoomId(roomId) {
  const data = new TextEncoder().encode("enc.chat-room-v4:" + roomId.toLowerCase().trim());
  const digest = await crypto.subtle.digest("SHA-256", data);
  return bufToB64(new Uint8Array(digest));
}

// ── KDF ───────────────────────────────────────────────────────────

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
  const out64 = await hkdf(dhOut, rk, "enc.chat-rk-v4", 64);
  return [out64.slice(0, 32), out64.slice(32)];
}

async function kdfCK(ck) {
  const mk    = await hmacSHA256(ck, new Uint8Array([0x01]));
  const newCK = await hmacSHA256(ck, new Uint8Array([0x02]));
  return [newCK, mk];
}

async function expandMK(mk) {
  const aesBytes    = await hkdf(mk, new Uint8Array(32), "enc.chat-mk-aes-v4",    32);
  const chachaBytes = await hkdf(mk, new Uint8Array(32), "enc.chat-mk-chacha-v4", 32);
  const aesKey = await crypto.subtle.importKey(
    "raw", aesBytes, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]
  );
  return { aesKey, chachaKey: chachaBytes };
}


// ════════════════════════════════════════════════════════════════════
//  ARGON2ID
// ════════════════════════════════════════════════════════════════════

async function deriveSK_Argon2id(password, roomId) {
  const saltRaw = await crypto.subtle.digest(
    "SHA-256", new TextEncoder().encode("enc.chat-v4-" + roomId.toLowerCase().trim())
  );
  const salt = new Uint8Array(saltRaw);
  showJoinStatus("🔐 Argon2id — 3-5 წამი...");
  const result = await argon2.hash({
    pass: password, salt,
    type: argon2.ArgonType.Argon2id,
    mem: 65536, time: 3, parallelism: 1, hashLen: 32
  });
  showJoinStatus("");
  return result.hash;
}


// ════════════════════════════════════════════════════════════════════
//  X25519 ECDH
// ════════════════════════════════════════════════════════════════════

async function generateX25519() {
  return crypto.subtle.generateKey({ name: "ECDH", namedCurve: "X25519" }, true, ["deriveBits"]);
}

async function x25519DH(privateKey, publicKey) {
  const bits = await crypto.subtle.deriveBits({ name: "ECDH", public: publicKey }, privateKey, 256);
  return new Uint8Array(bits);
}

async function exportX25519Pub(keypair) {
  return bufToB64(new Uint8Array(await crypto.subtle.exportKey("raw", keypair.publicKey)));
}

async function importX25519Pub(b64) {
  return crypto.subtle.importKey("raw", b64ToBuf(b64), { name: "ECDH", namedCurve: "X25519" }, true, []);
}


// ════════════════════════════════════════════════════════════════════
//  ML-KEM-768 (CRYSTALS-Kyber) — Post-Quantum KEM
//  კვანტური კომპიუტერი ვერ გატეხს
//  NIST FIPS 203 — 2024 სტანდარტი
// ════════════════════════════════════════════════════════════════════

function mlkemKeyGen() {
  // crystals-kyber-js: Kyber768.KeyGen() → { publicKey: Uint8Array(1184), privateKey: Uint8Array(2400) }
  return Kyber768.KeyGen();
}

function mlkemEncapsulate(theirPublicKey) {
  // Kyber768.Encrypt(pk) → { cipherText: Uint8Array(1088), sharedSecret: Uint8Array(32) }
  return Kyber768.Encrypt(theirPublicKey);
}

function mlkemDecapsulate(myPrivateKey, cipherText) {
  // Kyber768.Decrypt(sk, ct) → Uint8Array(32)
  return Kyber768.Decrypt(myPrivateKey, cipherText);
}


// ════════════════════════════════════════════════════════════════════
//  PQXDH — Hybrid Key Exchange
//
//  alice = პირველი შემომსვლელი (mlkem keypair-ს აქვს)
//  bob   = მეორე შემომსვლელი (encapsulate alice-ის mlkem pub-ზე)
//
//  Flow:
//    alice → server: { x25519_pub, mlkem_pub }
//    bob   ← server: alice-ის x25519_pub, mlkem_pub
//    bob   → server: { x25519_pub, mlkem_pub, pqct = KEM.encaps(alice_mlkem_pub).ct }
//    alice ← server: bob-ის x25519_pub, pqct
//
//    bob's SK   = HKDF(x25519_dh(bob_priv, alice_pub)  ‖ mlkem_ss_encaps)
//    alice's SK = HKDF(x25519_dh(alice_priv, bob_pub)  ‖ mlkem_ss_decaps)
//    → ორივეს ერთნაირი SK
// ════════════════════════════════════════════════════════════════════

async function pqxdhCombine(x25519DhOutput, mlkemSharedSecret, argon2SK) {
  // Combine classical + post-quantum + password KDF
  const combined = concatBuffers(x25519DhOutput, mlkemSharedSecret, argon2SK);
  return hkdf(combined, new Uint8Array(32), "enc.chat-pqxdh-v4", 32);
}


// ── Message Padding ───────────────────────────────────────────────

const PADDING_BLOCK = 256;

function padMessage(plainBytes) {
  const origLen = plainBytes.length;
  const total   = 2 + origLen;
  const padded  = Math.ceil(total / PADDING_BLOCK) * PADDING_BLOCK;
  const out     = new Uint8Array(padded);
  out[0] = origLen & 0xFF;
  out[1] = (origLen >> 8) & 0xFF;
  out.set(plainBytes, 2);
  if (padded - total > 0)
    out.set(crypto.getRandomValues(new Uint8Array(padded - total)), 2 + origLen);
  return out;
}

function unpadMessage(padded) {
  const origLen = padded[0] | (padded[1] << 8);
  return padded.slice(2, 2 + origLen);
}


// ── Key Fingerprint ───────────────────────────────────────────────

async function computeFingerprint(rk) {
  const raw = await hkdf(rk, new Uint8Array(32), "enc.chat-fingerprint-v4", 6);
  return bytesToHex(raw);
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

async function initDR(sk, myX25519Keypair, myX25519B64, theirX25519B64) {
  const theirPub = await importX25519Pub(theirX25519B64);
  const dhOut    = await x25519DH(myX25519Keypair.privateKey, theirPub);

  // FIX: ერთი 96-byte HKDF call — ორი ცალკე call-ის მაგივრად (იგივე security, ნახევარი სამუშაო)
  const derived96 = await hkdf(dhOut, sk, "enc.chat-dr-init-v4", 96);
  const init64    = derived96.slice(0, 64);
  const rk        = derived96.slice(64, 96);
  const isAlice   = myX25519B64 < theirX25519B64;

  dr = newDRState();
  dr.DHs    = myX25519Keypair;
  dr.DHsB64 = myX25519B64;
  dr.DHr    = theirPub;
  dr.DHrB64 = theirX25519B64;
  dr.RK     = rk;
  dr.CKs    = isAlice ? new Uint8Array(init64.slice(0, 32)) : new Uint8Array(init64.slice(32));
  dr.CKr    = isAlice ? new Uint8Array(init64.slice(32))    : new Uint8Array(init64.slice(0, 32));
  dr.ready  = true;
  dr.fingerprint = await computeFingerprint(rk);
}

async function dhRatchetStep(theirNewPubB64) {
  dr.PN = dr.Ns; dr.Ns = 0; dr.Nr = 0;
  dr.DHrB64 = theirNewPubB64;
  dr.DHr    = await importX25519Pub(theirNewPubB64);

  const dh1 = await x25519DH(dr.DHs.privateKey, dr.DHr);
  const [rk1, ckr] = await kdfRK(dr.RK, dh1);

  dr.DHs    = await generateX25519();
  dr.DHsB64 = await exportX25519Pub(dr.DHs);

  const dh2 = await x25519DH(dr.DHs.privateKey, dr.DHr);
  const [rk2, cks] = await kdfRK(rk1, dh2);

  dr.RK = rk2; dr.CKr = ckr; dr.CKs = cks;
}

const MAX_SKIP        = 100;  // ერთ ratchet step-ში მაქსიმუმი
const MAX_MKSKIPPED   = 500;  // სულ cached key-ების ლიმიტი

async function skipMessageKeys(until) {
  if (until - dr.Nr > MAX_SKIP) throw new Error("Too many skipped");
  while (dr.Nr < until) {
    // cache ზედმეტად არ გაიზარდოს — ძველ key-ებს ვწმენდთ
    if (dr.MKSKIPPED.size >= MAX_MKSKIPPED) {
      const oldest = dr.MKSKIPPED.keys().next().value;
      zeroBytes(dr.MKSKIPPED.get(oldest));
      dr.MKSKIPPED.delete(oldest);
    }
    const [newCKr, mk] = await kdfCK(dr.CKr);
    dr.MKSKIPPED.set(`${dr.DHrB64}:${dr.Nr}`, mk);
    dr.CKr = newCKr; dr.Nr++;
  }
}

async function ratchetEncrypt(text) {
  const [newCKs, mk] = await kdfCK(dr.CKs);
  dr.CKs = newCKs;
  const { aesKey, chachaKey } = await expandMK(mk);

  const padded      = padMessage(new TextEncoder().encode(text));
  const chachaNonce = crypto.getRandomValues(new Uint8Array(12));
  const afterChacha = chacha20Xor(chachaKey, chachaNonce, padded);
  const iv          = crypto.getRandomValues(new Uint8Array(12));
  const ct          = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, aesKey, afterChacha);

  const packed = new Uint8Array(12 + 12 + ct.byteLength);
  packed.set(chachaNonce, 0); packed.set(iv, 12);
  packed.set(new Uint8Array(ct), 24);

  const header = { dh: dr.DHsB64, n: dr.Ns, pn: dr.PN };
  dr.Ns++;
  return { enc: bufToB64(packed), header };
}

async function ratchetDecrypt(encB64, header) {
  try {
    const skKey = `${header.dh}:${header.n}`;
    let mk;
    if (dr.MKSKIPPED.has(skKey)) {
      mk = dr.MKSKIPPED.get(skKey);
      dr.MKSKIPPED.delete(skKey);
    } else {
      if (header.dh !== dr.DHrB64) {
        await skipMessageKeys(header.pn);
        await dhRatchetStep(header.dh);
      }
      await skipMessageKeys(header.n);
      const [newCKr, msgKey] = await kdfCK(dr.CKr);
      dr.CKr = newCKr; dr.Nr++; mk = msgKey;
    }

    const { aesKey, chachaKey } = await expandMK(mk);
    const packed      = b64ToBuf(encB64);
    const chachaNonce = packed.slice(0, 12);
    const iv          = packed.slice(12, 24);
    const ct          = packed.slice(24);
    const afterAes    = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, aesKey, ct);
    const plain       = chacha20Xor(chachaKey, chachaNonce, new Uint8Array(afterAes));
    return new TextDecoder().decode(unpadMessage(plain));
  } catch (e) {
    // FIX: შეცდომა ჩანს console-ში — silent fail-ის მაგივრად
    console.warn("[ratchetDecrypt] failed:", e?.message || e);
    return null;
  }
}


// ── Sent Cache ────────────────────────────────────────────────────
const sentCache = new Map();


// ── Generator ─────────────────────────────────────────────────────

function generateCodes() {
  const chars   = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
  const special = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*";

  // FIX: rejection sampling — modulo bias ამოღებულია
  // cs.length-ის ჯერადი ზღვარი: ბაიტები ამ ზღვარს ზემოთ უგულვებელყოფება
  const randStr = (len, cs) => {
    const limit = 256 - (256 % cs.length); // e.g. 62→248, 70→210
    const out = [];
    while (out.length < len) {
      const buf = new Uint8Array(len * 2);
      crypto.getRandomValues(buf);
      for (const b of buf) {
        if (out.length >= len) break;
        if (b < limit) out.push(cs[b % cs.length]);
      }
    }
    return out.join("");
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
      navigator.clipboard.writeText(document.getElementById(btn.dataset.target).textContent)
        .then(() => {
          btn.textContent = "✓"; btn.classList.add("copied");
          setTimeout(() => { btn.textContent = "კოპირება"; btn.classList.remove("copied"); }, 1500);
        });
    };
  });
}


// ── State ─────────────────────────────────────────────────────────

let currentRoom    = "";
const SESSION_ID   = crypto.randomUUID();
let pollInterval   = null;
let tickInterval   = null;
let renderedIds    = new Set();
let _pendingInit   = null;
// Store our keys for PQXDH
let _myX25519      = null;
let _myX25519B64   = null;
let _myMlkemPriv   = null;
let _myMlkemPub    = null;
let _argon2SK      = null;


// ── UI ────────────────────────────────────────────────────────────

function showJoinStatus(msg) {
  const el = document.getElementById("join-status");
  if (!el) return;
  el.textContent = msg; el.style.display = msg ? "block" : "none";
}

function updateDRStatus() {
  const el = document.getElementById("dr-status");
  const fp = document.getElementById("fingerprint");
  if (!el) return;
  if (dr && dr.ready) {
    el.textContent = "🔐 PQXDH + Double Ratchet: აქტიური";
    el.className   = "dr-status dr-ready";
    if (fp && dr.fingerprint) {
      const f = dr.fingerprint;
      fp.textContent   = `🔑 ${f.slice(0,4)} ${f.slice(4,8)} ${f.slice(8,12)}`;
      fp.style.display = "block";
      fp.title = "შეადარე მეგობარს — MITM შეუძლებელია";
    }
  } else {
    el.textContent = "⏳ მეორე მომხმარებელს ელოდება...";
    el.className   = "dr-status dr-waiting";
    if (fp) fp.style.display = "none";
  }
}


// ── PQXDH Init ───────────────────────────────────────────────────

async function tryInitPQXDH() {
  try {
    const roomHash = await hashRoomId(currentRoom);
    const res  = await fetch(`/api/keys?room=${encodeURIComponent(roomHash)}&sid=${SESSION_ID}`);
    const data = await res.json();
    if (!data.keys || data.keys.length === 0) return false;

    const them = data.keys[0];

    // X25519 DH
    const theirX25519 = await importX25519Pub(them.pub);
    const dhOut       = await x25519DH(_myX25519.privateKey, theirX25519);

    let mlkemSS;

    if (them.pqct) {
      // They already encapsulated to our ML-KEM pub — we decapsulate
      mlkemSS = await mlkemDecapsulate(_myMlkemPriv, b64ToBuf(them.pqct));
    } else {
      // We encapsulate to their ML-KEM pub — they will decapsulate
      showJoinStatus("🔮 ML-KEM-768...");
      const { cipherText, sharedSecret } = await mlkemEncapsulate(b64ToBuf(them.mlkemPub));
      mlkemSS = sharedSecret;

      // Upload our pqct so they can decapsulate
      // FIX: roomHash გამოვიყენოთ — currentRoom (plain) კი არა
      const pqctRoomHash = await hashRoomId(currentRoom);
      await fetch("/api/keys", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          room:      pqctRoomHash,
          sid:       SESSION_ID,
          pub:       _myX25519B64,
          mlkemPub:  bufToB64(_myMlkemPub),
          pqct:      bufToB64(cipherText)
        })
      });
      showJoinStatus("");
    }

    // PQXDH: combine X25519 + ML-KEM + Argon2id
    const sk = await pqxdhCombine(dhOut, mlkemSS, _argon2SK);

    // Init Double Ratchet with combined SK
    await initDR(sk, _myX25519, _myX25519B64, them.pub);
    return true;
  } catch (e) {
    console.error("PQXDH init error:", e);
    return false;
  }
}


// ── Join / Leave ──────────────────────────────────────────────────

async function joinRoom() {
  const room = document.getElementById("room-input").value.trim();
  const pass = document.getElementById("pass-input").value.trim(); // FIX: trailing spaces პაროლს ვარღვევდა
  if (!room || !pass)          { showError("ოთახის კოდი და პაროლი საჭიროა."); return; }
  if (room.length > 128 || pass.length > 256) { showError("ძალიან გრძელი."); return; }

  // FIX: წინა intervals-ების გასუფთავება — error path-ზე leak-ის წინააღმდეგ
  clearInterval(pollInterval);
  clearInterval(tickInterval);

  document.getElementById("join-btn").disabled    = true;
  document.getElementById("join-btn").textContent = "[ იტვირთება... ]";

  try {
    // 1. Argon2id → SK (additional layer)
    _argon2SK = await deriveSK_Argon2id(pass, room);

    // 2. X25519 keypair
    showJoinStatus("🔑 გასაღებები...");
    _myX25519    = await generateX25519();
    _myX25519B64 = await exportX25519Pub(_myX25519);

    // 3. ML-KEM-768 keypair
    showJoinStatus("🔮 ML-KEM-768 გასაღებები...");
    const mlkemKeys = await mlkemKeyGen();
    _myMlkemPriv = mlkemKeys.privateKey;
    _myMlkemPub  = mlkemKeys.publicKey;
    showJoinStatus("");

    // 4. Register both public keys — room hash-ი, სახელი არ გადაიცემა
    const roomHash = await hashRoomId(room);
    await fetch("/api/keys", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        room:     roomHash,
        sid:      SESSION_ID,
        pub:      _myX25519B64,
        mlkemPub: bufToB64(_myMlkemPub)
      })
    });

    currentRoom = room;
    dr = null;

    // 5. Try PQXDH init
    const ready = await tryInitPQXDH();
    if (!ready) _pendingInit = true;

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
    document.getElementById("join-btn").disabled    = false;
    document.getElementById("join-btn").textContent = "შესვლა";
  }
}

async function poll() {
  if (_pendingInit && (!dr || !dr.ready)) {
    const ready = await tryInitPQXDH();
    if (ready) { _pendingInit = false; updateDRStatus(); }
  }
  await fetchAndRender();
}

// ── Secure Key Wipe ───────────────────────────────────────────────
// null-ის მინიჭება GC-ს ელოდება; ჩვენ ბუფერს ნულებით ვავსებთ პირველ
function zeroBytes(buf) {
  if (buf instanceof Uint8Array) buf.fill(0);
}

function wipeDR() {
  if (!dr) return;
  zeroBytes(dr.RK);  zeroBytes(dr.CKs); zeroBytes(dr.CKr);
  dr.MKSKIPPED.forEach(mk => zeroBytes(mk));
  dr.MKSKIPPED.clear();
  dr = null;
}

function wipeSessionKeys() {
  zeroBytes(_argon2SK);
  if (_myMlkemPriv instanceof Uint8Array) zeroBytes(_myMlkemPriv);
  // ⚠️ Web Crypto API შეზღუდვა: X25519 CryptoKey object-ების raw bytes
  // პირდაპირ მიუწვდომელია JS-იდან — browser secure memory-შია.
  // reference-ის null-ად ქცევა GC-ს გადასცემს კონტროლს.
  // სრული zeroing შეუძლებელია ბრაუზერის sandbox-ის გარეთ.
  _myX25519 = null; _myX25519B64 = null;
  _myMlkemPriv = null; _myMlkemPub = null; _argon2SK = null;
}

async function leaveRoom() {
  clearInterval(pollInterval);
  clearInterval(tickInterval);
  // სერვერს ვატყობინებთ — sid proof of membership
  if (currentRoom) {
    try {
      const roomHash = await hashRoomId(currentRoom);
      await fetch(`/api/room?room=${encodeURIComponent(roomHash)}&sid=${SESSION_ID}`, {
        method: "DELETE"
      });
    } catch { /* silent — wipe happens regardless */ }
  }
  wipeDR();
  wipeSessionKeys();
  currentRoom = ""; _pendingInit = null;
  renderedIds.clear(); sentCache.clear();
  document.getElementById("messages").innerHTML        = "";
  document.getElementById("chat-screen").style.display = "none";
  document.getElementById("join-screen").style.display = "flex";
  document.getElementById("pass-input").value          = "";
  document.getElementById("join-error").style.display  = "none";
}

function showError(msg) {
  const el = document.getElementById("join-error");
  el.textContent = msg; el.style.display = "block";
}


// ── Send ──────────────────────────────────────────────────────────

async function sendMessage() {
  const input = document.getElementById("msg-input");
  const text  = input.value.trim();
  if (!text) return;
  if (!dr || !dr.ready) { showChatNotice("⏳ მეორე მომხმარებელი ჯერ არ შემოუერთდა."); return; }

  const ttl = parseInt(document.getElementById("ttl-select").value);
  try {
    const { enc, header } = await ratchetEncrypt(text);
    const roomHash = await hashRoomId(currentRoom);
    const res = await fetch("/api/messages", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        room: roomHash, enc, sid: SESSION_ID,
        dhPub: header.dh, msgN: header.n, prevN: header.pn, ttl
      })
    });
    if (!res.ok) throw new Error("send failed");
    const data = await res.json();
    if (data.id) sentCache.set(data.id, text);
    input.value = ""; input.style.height = "auto";
    await fetchAndRender();
  } catch (e) { console.error(e); }
}

function showChatNotice(msg) {
  const c  = document.getElementById("messages");
  const el = document.createElement("div");
  el.className = "sys-msg"; el.textContent = msg;
  c.appendChild(el); c.scrollTop = c.scrollHeight;
  setTimeout(() => el.remove(), 4000);
}

function handleKey(e) {
  if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); sendMessage(); }
}

function autoResize(el) {
  el.style.height = "auto";
  el.style.height = Math.min(el.scrollHeight, 100) + "px";
}


// ── Fetch & Render ────────────────────────────────────────────────

async function fetchAndRender() {
  try {
    const roomHash = await hashRoomId(currentRoom);
    const res  = await fetch(`/api/messages?room=${encodeURIComponent(roomHash)}`);
    const data = await res.json();
    await renderMessages(data.messages || []);
  } catch { /* silent */ }
}

async function renderMessages(records) {
  const container = document.getElementById("messages");
  const serverIds = new Set(records.map(r => r.id));

  document.querySelectorAll(".msg[data-id]").forEach(el => {
    if (!serverIds.has(el.dataset.id)) {
      // FIX: DOM-თან ერთად sentCache-იდანაც ვშლით — memory leak-ის წინააღმდეგ
      sentCache.delete(el.dataset.id);
      renderedIds.delete(el.dataset.id);
      el.remove();
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

    const div = document.createElement("div");
    div.className = `msg ${mine ? "mine" : "theirs"}`;
    div.dataset.id = rec.id;

    const bubble = document.createElement("div");
    bubble.className = "bubble"; bubble.textContent = text;

    const meta  = document.createElement("div");
    meta.className  = "meta";
    const span  = document.createElement("span");
    span.className  = "timer"; span.dataset.expires = rec.expires;
    span.textContent = formatTime(Math.max(0, Math.floor((rec.expires - Date.now()) / 1000)));
    meta.appendChild(span);

    div.appendChild(bubble); div.appendChild(meta);
    container.appendChild(div);
    renderedIds.add(rec.id); scrollNeeded = true;
  }
  if (scrollNeeded) container.scrollTop = container.scrollHeight;
}


// ── Timers ────────────────────────────────────────────────────────

function tickTimers() {
  const now = Date.now();
  document.querySelectorAll(".timer").forEach(el => {
    el.textContent = formatTime(Math.max(0, Math.floor((parseInt(el.dataset.expires) - now) / 1000)));
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
  const mi = document.getElementById("msg-input");
  mi.addEventListener("keydown", handleKey);
  mi.addEventListener("input", function() { autoResize(this); });
  document.getElementById("pass-input").addEventListener("keydown", e => { if (e.key === "Enter") joinRoom(); });
  document.getElementById("room-input").addEventListener("keydown", e => { if (e.key === "Enter") document.getElementById("pass-input").focus(); });
});

// tab დახურვა / ჩანართის შეცვლა → გასაღებები დაუყოვნებლივ იწმინდება
window.addEventListener("beforeunload", () => {
  wipeDR();
  wipeSessionKeys();
});

// tab background-ში გადავიდა → გასაღებები ვინახავთ (UX),
// მხოლოდ beforeunload-ზე ვწმენდთ სრულად.
// visibilitychange-ზე poll-ს ვაჩერებთ მხოლოდ, არ ვწმენდთ keys.
document.addEventListener("visibilitychange", () => {
  if (document.visibilityState === "hidden" && currentRoom) {
    // poll-ს ვაჩერებთ — battery + bandwidth
    clearInterval(pollInterval);
  } else if (document.visibilityState === "visible" && currentRoom) {
    // tab-ი დაბრუნდა — poll-ს ვუბრუნებთ
    clearInterval(pollInterval);
    pollInterval = setInterval(poll, 3000);
    poll();
  }
});
