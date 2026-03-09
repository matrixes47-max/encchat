/**
 * build-kyber.js — kyber.min.js-ის ასაწყობი სკრიპტი
 *
 * გაუშვი encchat-main/ ფოლდერში:
 *   node build-kyber.js
 *
 * შედეგი: public/kyber.min.js
 * შემდეგ: git add public/kyber.min.js && git commit -m "add kyber.min.js" && git push
 */

const { execSync } = require("child_process");
const fs   = require("fs");
const path = require("path");

async function main() {

  // 1. esbuild install
  console.log("📦 esbuild-ს ვაყენებ...");
  execSync("npm install --save-dev esbuild", { stdio: "inherit" });

  // 2. API შემოწმება
  console.log("\n🔍 crystals-kyber-js API-ს ვამოწმებ...");
  const lib = await import("crystals-kyber-js");
  const inst = new lib.Kyber768();

  const methods = [];
  let proto = Object.getPrototypeOf(inst);
  while (proto && proto !== Object.prototype) {
    methods.push(...Object.getOwnPropertyNames(proto).filter(m => m !== "constructor"));
    proto = Object.getPrototypeOf(proto);
  }
  console.log("methods:", methods);

  const kgName  = methods.find(m => /keyPair|keygen|KeyGen/i.test(m)) || methods[0];
  const encName = methods.find(m => /encapsulat|encrypt/i.test(m))    || methods[1];
  const decName = methods.find(m => /decapsulat|decrypt/i.test(m))    || methods[2];

  if (!kgName) { console.error("❌ method ვერ ვიპოვეთ"); process.exit(1); }

  const testKg = await inst[kgName]();
  console.log(`✅ ${kgName}() მუშაობს! pub:${testKg.publicKey?.length}B`);

  // 3. entry file
  const entry = path.join(__dirname, "_kyber_entry.mjs");
  fs.writeFileSync(entry, `
import { Kyber768 } from "crystals-kyber-js";

const _inst = new Kyber768();
const _ready = (async () => { await _inst["${kgName}"](); })().catch(()=>{});

window.Kyber768 = {
  KeyGen:  async () => {
    await _ready;
    return await _inst["${kgName}"]();
  },
  Encrypt: async (pk) => {
    await _ready;
    return await _inst["${encName}"](pk);
  },
  Decrypt: async (sk, ct) => {
    await _ready;
    return await _inst["${decName}"](ct, sk);
  }
};
console.log("[kyber] Kyber768 ready ✅");
`);

  // 4. bundle
  console.log("\n📦 bundle...");
  const out = path.join(__dirname, "public", "kyber.min.js");
  execSync(`./node_modules/.bin/esbuild ${entry} --bundle --minify --format=iife --outfile=${out}`, { stdio: "inherit" });
  fs.unlinkSync(entry);

  console.log(`\n✅ public/kyber.min.js (${(fs.statSync(out).size/1024).toFixed(1)}KB)`);
  console.log("\n⚠️  app.js-შიც ცვლილება სჭირდება — Kyber768 ახლა async-ია.");
  console.log("   ამ სკრიპტის გაშვების შემდეგ გამომიგზავნე და app.js-საც გავასწორებ.\n");
  console.log("👉 git add public/kyber.min.js && git commit -m 'kyber bundle' && git push");
}

main().catch(e => { console.error("❌", e.message); process.exit(1); });
