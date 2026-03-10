const { execSync } = require("child_process");
const fs   = require("fs");
const path = require("path");

async function main() {
  const pubDir = path.join(__dirname, "public");
  if (!fs.existsSync(pubDir)) fs.mkdirSync(pubDir, { recursive: true });

  // ── argon2 ─────────────────────────────────────────────────────
  try {
    const wasmDir = path.join(__dirname, "node_modules/argon2-browser/dist");
    if (fs.existsSync(wasmDir)) {
      for (const f of fs.readdirSync(wasmDir)) {
        if (f.endsWith(".js") || f.endsWith(".wasm")) {
          fs.copyFileSync(path.join(wasmDir, f), path.join(pubDir, f));
        }
      }
      console.log("✅ argon2 copied");
    }
  } catch(e) { console.error("❌ argon2:", e.message); }

  // ── kyber: ყველა method name ვცდით ─────────────────────────────
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

  // ვცდით სახელებს პირდაპირ
  const tryNames = async (names) => {
    for (const n of names) {
      if (typeof inst[n] === "function") {
        try {
          const r = await inst[n]();
          if (r) { console.log("✅ works:", n); return n; }
        } catch(e) {}
      }
    }
    return null;
  };

  const kg  = await tryNames(["generateKeyPair","keyGen","keygen","KeyGen","generate"]);
  console.log("keyGen method:", kg);

  let enc = null, dec = null;
  if (kg) {
    const kp = await inst[kg]();
    console.log("keyPair keys:", Object.keys(kp));
    enc = ["encapsulate","encrypt","Encrypt"].find(n => typeof inst[n] === "function");
    dec = ["decapsulate","decrypt","Decrypt"].find(n => typeof inst[n] === "function");
    console.log("enc:", enc, "dec:", dec);
  }

  if (!kg || !enc || !dec) {
    console.error("❌ methods not found! all props:", [...all].join(", "));
    process.exit(1);
  }

  // ── bundle ─────────────────────────────────────────────────────
  const entry = path.join(__dirname, "_kyber_entry.mjs");
  fs.writeFileSync(entry, `
import { Kyber768 } from "crystals-kyber-js";
const _inst = new Kyber768();
window.Kyber768 = {
  KeyGen:  async ()       => await _inst["${kg}"](),
  Encrypt: async (pk)     => await _inst["${enc}"](pk),
  Decrypt: async (sk, ct) => await _inst["${dec}"](ct, sk),
};
console.log("[kyber] ready: ${kg}/${enc}/${dec}");
`);

  const out = path.join(pubDir, "kyber.min.js");
  execSync(`./node_modules/.bin/esbuild ${entry} --bundle --minify --format=iife --outfile=${out}`, { stdio: "inherit" });
  fs.unlinkSync(entry);
  console.log(`✅ kyber.min.js (${(fs.statSync(out).size/1024).toFixed(1)}KB)`);
}

main().catch(e => { console.error("❌", e.message); process.exit(1); });
