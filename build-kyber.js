const { execSync } = require("child_process");
const fs   = require("fs");
const path = require("path");

async function main() {
  const pubDir = path.join(__dirname, "public");
  if (!fs.existsSync(pubDir)) fs.mkdirSync(pubDir, { recursive: true });

  // ── argon2 via hash-wasm ──────────────────────────────────────
  // hash-wasm: No Worker, no blob URL, WASM inline, CSP-friendly.
  // argon2-browser used a blob Worker which was blocked by strict CSP.
  // hash-wasm runs in the main thread — works everywhere.
  //
  // Exposes window.argon2 with same API app.js expects:
  //   argon2.hash({ pass, salt, type, mem, time, parallelism, hashLen })
  //   → { hash: Uint8Array }
  {
    const argonEntry = path.join(__dirname, "_argon2_entry.mjs");
    fs.writeFileSync(argonEntry, `
import { argon2id } from "hash-wasm";

window.argon2 = {
  ArgonType: { Argon2d: 0, Argon2i: 1, Argon2id: 2 },
  hash: async ({ pass, salt, type, mem, time, parallelism, hashLen }) => {
    const hash = await argon2id({
      password: pass,
      salt: salt,
      iterations: time       || 3,
      memorySize: mem        || 65536,
      hashLength: hashLen    || 32,
      parallelism: parallelism || 1,
      outputType: "binary"
    });
    return { hash };
  }
};
`);
    const argonOut = path.join(pubDir, "argon2.min.js");
    execSync(
      `./node_modules/.bin/esbuild ${argonEntry} --bundle --minify --format=iife --loader:.wasm=binary --outfile=${argonOut}`,
      { stdio: "inherit" }
    );
    fs.unlinkSync(argonEntry);
    console.log(`✅ argon2-bundled.min.js via hash-wasm (${(fs.statSync(argonOut).size/1024).toFixed(1)}KB)`);
  }

  // ── x25519 via @noble/curves ──────────────────────────────────
  // WebCrypto X25519 (namedCurve:"X25519") is not supported on older
  // Android browsers. @noble/curves is pure JS, works everywhere.
  // Exposes window._x25519 with: generatePrivateKey, getPublicKey, getSharedSecret
  {
    const x25519Entry = path.join(__dirname, "_x25519_entry.mjs");
    fs.writeFileSync(x25519Entry, `
import { x25519 } from "@noble/curves/ed25519";
window._x25519 = {
  generatePrivateKey: () => x25519.utils.randomPrivateKey(),
  getPublicKey:       (priv) => x25519.getPublicKey(priv),
  getSharedSecret:    (priv, pub) => x25519.getSharedSecret(priv, pub),
};
`);
    const x25519Out = path.join(pubDir, "x25519.min.js");
    execSync(
      `./node_modules/.bin/esbuild ${x25519Entry} --bundle --minify --format=iife --outfile=${x25519Out}`,
      { stdio: "inherit" }
    );
    fs.unlinkSync(x25519Entry);
    console.log(`✅ x25519.min.js via @noble/curves (${(fs.statSync(x25519Out).size/1024).toFixed(1)}KB)`);
  }

  // ── kyber: detect API ─────────────────────────────────────────
  const lib = await import("crystals-kyber-js");
  const inst = new lib.Kyber768();

  // ყველა property - own + proto
  const all = new Set();
  let o = inst;
  while (o && o !== Object.prototype) {
    Object.getOwnPropertyNames(o).forEach(k => all.add(k));
    o = Object.getPrototypeOf(o);
  }
  console.log("ALL PROPS:", [...all].join(", "));

  // ── keyGen detection ──────────────────────────────────────────
  const keyGenNames = ["generateKeyPair","keyGen","keygen","KeyGen","generate"];
  let kg = null;
  for (const n of keyGenNames) {
    if (typeof inst[n] === "function") {
      console.log("✅ keyGen method found:", n);
      kg = n;
      break;
    }
  }

  if (!kg) {
    console.error("❌ keyGen not found! props:", [...all].join(", "));
    process.exit(1);
  }

  // ── detect return format of keyGen ───────────────────────────
  const kpRaw = await inst[kg]();
  // crystals-kyber-js v1.0.0 returns [pk, sk] array (not object)
  const kpIsArray = Array.isArray(kpRaw);
  console.log("keyGen returns array:", kpIsArray, "| keys:", Object.keys(kpRaw));

  // ── enc/dec method detection ──────────────────────────────────
  // FIX: Added "encap"/"decap" — actual method names in crystals-kyber-js v1.0.0
  const enc = ["encap","encapsulate","encrypt","Encrypt"].find(n => typeof inst[n] === "function");
  const dec = ["decap","decapsulate","decrypt","Decrypt"].find(n => typeof inst[n] === "function");
  console.log("enc method:", enc, "| dec method:", dec);

  if (!enc || !dec) {
    console.error("❌ enc/dec not found! props:", [...all].join(", "));
    process.exit(1);
  }

  // ── detect return format of encap ────────────────────────────
  const testPk = kpIsArray ? kpRaw[0] : kpRaw.publicKey;
  const encRaw = await inst[enc](testPk);
  const encIsArray = Array.isArray(encRaw);
  console.log("encap returns array:", encIsArray, "| keys:", Object.keys(encRaw));

  // ── build wrappers matching app.js expected API ───────────────
  //
  // app.js expects:
  //   Kyber768.KeyGen()       → { publicKey, privateKey }
  //   Kyber768.Encrypt(pk)    → { cipherText, sharedSecret }
  //   Kyber768.Decrypt(sk,ct) → sharedSecret (Uint8Array)
  //
  // crystals-kyber-js v1.0.0 actual:
  //   generateKeyPair()  → [pk, sk]   (array)
  //   encap(pk)          → [ct, ss]   (array)
  //   decap(ct, sk)      → ss         (Uint8Array)

  const keyGenWrapper = kpIsArray
    ? `async () => { const [pk,sk] = await _inst["${kg}"](); return { publicKey: pk, privateKey: sk }; }`
    : `async () => await _inst["${kg}"]()`;

  const encWrapper = encIsArray
    ? `async (pk) => { const [ct,ss] = await _inst["${enc}"](pk); return { cipherText: ct, sharedSecret: ss }; }`
    : `async (pk) => await _inst["${enc}"](pk)`;

  const decWrapper = `async (sk, ct) => await _inst["${dec}"](ct, sk)`;

  // ── bundle ─────────────────────────────────────────────────────
  const entry = path.join(__dirname, "_kyber_entry.mjs");
  fs.writeFileSync(entry, `
import { Kyber768 } from "crystals-kyber-js";
const _inst = new Kyber768();
window.Kyber768 = {
  KeyGen:  ${keyGenWrapper},
  Encrypt: ${encWrapper},
  Decrypt: ${decWrapper},
};
`);

  const out = path.join(pubDir, "kyber.min.js");
  execSync(`./node_modules/.bin/esbuild ${entry} --bundle --minify --format=iife --loader:.wasm=binary --outfile=${out}`, { stdio: "inherit" });
  fs.unlinkSync(entry);
  console.log(`✅ kyber.min.js (${(fs.statSync(out).size/1024).toFixed(1)}KB)`);
}

main().catch(e => { console.error("❌", e.message); process.exit(1); });
