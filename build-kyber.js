/**
 * build-kyber.js — kyber.min.js + argon2 ასაწყობი სკრიპტი
 * postinstall-ში გაიშვება ავტომატურად
 */

const { execSync } = require("child_process");
const fs   = require("fs");
const path = require("path");

async function main() {
  const pubDir = path.join(__dirname, "public");
  if (!fs.existsSync(pubDir)) fs.mkdirSync(pubDir, { recursive: true });

  // ── 1. argon2 კოპირება ─────────────────────────────────────────
  try {
    const wasmDir = path.join(__dirname, "node_modules/argon2-browser/dist");
    const argonJs  = path.join(wasmDir, "argon2.min.js");
    if (fs.existsSync(argonJs)) {
      fs.copyFileSync(argonJs, path.join(pubDir, "argon2.min.js"));
      for (const f of fs.readdirSync(wasmDir)) {
        if (f.endsWith(".wasm")) fs.copyFileSync(path.join(wasmDir, f), path.join(pubDir, f));
      }
      console.log("✅ argon2.min.js + wasm copied to public/");
    } else {
      console.error("❌ argon2-browser not found at", argonJs);
    }
  } catch(e) { console.error("❌ argon2 copy:", e.message); }

  // ── 2. kyber bundle ────────────────────────────────────────────
  // crystals-kyber-js v1.0.0: Kyber768 class-ს აქვს:
  //   generateKeyPair() → { publicKey: Uint8Array, privateKey: Uint8Array }
  //   encapsulate(pk)   → { cipherText: Uint8Array, sharedSecret: Uint8Array }
  //   decapsulate(ct,sk) → Uint8Array (sharedSecret)

  const entry = path.join(__dirname, "_kyber_entry.mjs");
  fs.writeFileSync(entry, `
import { Kyber768 } from "crystals-kyber-js";

const _inst = new Kyber768();

window.Kyber768 = {
  KeyGen: async () => {
    const result = await _inst.generateKeyPair();
    return result;
  },
  Encrypt: async (pk) => {
    const result = await _inst.encapsulate(pk);
    return result;
  },
  Decrypt: async (sk, ct) => {
    const result = await _inst.decapsulate(ct, sk);
    return result;
  }
};
console.log("[kyber] Kyber768 ready ✅");
`);

  try {
    console.log("📦 kyber bundle...");
    const out = path.join(pubDir, "kyber.min.js");
    execSync(
      `./node_modules/.bin/esbuild ${entry} --bundle --minify --format=iife --outfile=${out}`,
      { stdio: "inherit" }
    );
    fs.unlinkSync(entry);
    console.log(`✅ public/kyber.min.js (${(fs.statSync(out).size/1024).toFixed(1)}KB)`);
  } catch(e) {
    if (fs.existsSync(entry)) fs.unlinkSync(entry);
    console.error("❌ kyber bundle failed:", e.message);
    process.exit(1);
  }

  console.log("\n✅ Build complete — ready to deploy!\n");
}

main().catch(e => { console.error("❌", e.message); process.exit(1); });
