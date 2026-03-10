/**
 * build-kyber.js — kyber.min.js + argon2 builder
 */
const { execSync } = require("child_process");
const fs   = require("fs");
const path = require("path");

async function main() {
  const pubDir = path.join(__dirname, "public");
  if (!fs.existsSync(pubDir)) fs.mkdirSync(pubDir, { recursive: true });

  // ── 1. argon2 copy ─────────────────────────────────────────────
  try {
    const wasmDir = path.join(__dirname, "node_modules/argon2-browser/dist");
    const argonJs  = path.join(wasmDir, "argon2.min.js");
    if (fs.existsSync(argonJs)) {
      fs.copyFileSync(argonJs, path.join(pubDir, "argon2.min.js"));
      for (const f of fs.readdirSync(wasmDir)) {
        if (f.endsWith(".wasm")) fs.copyFileSync(path.join(wasmDir, f), path.join(pubDir, f));
      }
      console.log("✅ argon2.min.js copied");
    }
  } catch(e) { console.error("❌ argon2:", e.message); }

  // ── 2. kyber API detection ─────────────────────────────────────
  const lib = await import("crystals-kyber-js");
  const inst = new lib.Kyber768();

  // მეთოდები შეიძლება instance-ის own properties იყოს (არა prototype-ზე)
  const ownProps  = Object.getOwnPropertyNames(inst).filter(m => typeof inst[m] === "function" && m !== "constructor");
  let protoProps = [];
  let proto = Object.getPrototypeOf(inst);
  while (proto && proto !== Object.prototype) {
    protoProps.push(...Object.getOwnPropertyNames(proto).filter(m => m !== "constructor"));
    proto = Object.getPrototypeOf(proto);
  }
  const allMethods = [...new Set([...ownProps, ...protoProps])];
  console.log("own methods:", ownProps);
  console.log("proto methods:", protoProps);
  console.log("all methods:", allMethods);

  // მეთოდების სახელები — ვცდით რამდენიმე ვარიანტს
  const kgName  = allMethods.find(m => /keyPair|keygen|keyGen/i.test(m));
  const encName = allMethods.find(m => /encapsulat|encrypt/i.test(m));
  const decName = allMethods.find(m => /decapsulat|decrypt/i.test(m));

  console.log(`keyGen=${kgName}, enc=${encName}, dec=${decName}`);

  if (!kgName || !encName || !decName) {
    // fallback: პირდაპირ ვცდით ცნობილ სახელებს
    console.log("⚠️  methods not found by name, trying known names...");
    const candidates = ["generateKeyPair","keyGen","keygen","KeyGen"];
    for (const c of candidates) {
      try {
        const r = await inst[c]();
        if (r && r.publicKey) {
          console.log(`✅ found working keyGen: ${c}`);
          break;
        }
      } catch(e) {}
    }
  }

  // ── 3. bundle ──────────────────────────────────────────────────
  const kg  = kgName  || "generateKeyPair";
  const enc = encName || "encapsulate";
  const dec = decName || "decapsulate";

  const entry = path.join(__dirname, "_kyber_entry.mjs");
  fs.writeFileSync(entry, `
import { Kyber768 } from "crystals-kyber-js";

// instance ვქმნით — class-ია
const _inst = new Kyber768();

window.Kyber768 = {
  KeyGen: async () => {
    return await _inst["${kg}"]();
  },
  Encrypt: async (pk) => {
    return await _inst["${enc}"](pk);
  },
  Decrypt: async (sk, ct) => {
    // crystals-kyber-js: decapsulate(cipherText, secretKey)
    return await _inst["${dec}"](ct, sk);
  }
};
console.log("[kyber] Kyber768 ready, methods: ${kg}/${enc}/${dec}");
`);

  try {
    const out = path.join(pubDir, "kyber.min.js");
    execSync(
      `./node_modules/.bin/esbuild ${entry} --bundle --minify --format=iife --outfile=${out}`,
      { stdio: "inherit" }
    );
    fs.unlinkSync(entry);
    console.log(`✅ kyber.min.js built (${(fs.statSync(out).size/1024).toFixed(1)}KB)`);
  } catch(e) {
    if (fs.existsSync(entry)) fs.unlinkSync(entry);
    console.error("❌ bundle failed:", e.message);
    process.exit(1);
  }

  console.log("✅ Build complete!\n");
}

main().catch(e => { console.error("❌", e.message); process.exit(1); });
