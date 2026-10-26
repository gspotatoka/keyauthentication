// Run once:  node scripts/gen-keypair.js
const crypto = require("crypto");
const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
const seed = privateKey.export({ format: "der", type: "pkcs8" }).subarray(-32).toString("hex");
const pub = publicKey.export({ format: "der", type: "spki" }).subarray(-32).toString("hex");
console.log("\nLICENSE_PRIVATE_SEED (Vercel env var, SECRET):\n" + seed);
console.log("\nLICENSE_PUBLIC_KEY (paste into the Python client):\n" + pub + "\n");
