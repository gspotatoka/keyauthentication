const crypto = require("crypto");

const PKCS8_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");

function privateKey() {
  const seed = process.env.LICENSE_PRIVATE_SEED;
  if (!seed || seed.length !== 64) throw new Error("LICENSE_PRIVATE_SEED missing/invalid (run npm run keypair)");
  return crypto.createPrivateKey({
    key: Buffer.concat([PKCS8_PREFIX, Buffer.from(seed, "hex")]),
    format: "der",
    type: "pkcs8",
  });
}

// The client rebuilds this exact string and verifies the signature over it.
function buildMessage({ status, nonce, hwid, exp, ts }) {
  return `v1|${status}|${nonce}|${hwid}|${exp}|${ts}`;
}

function signResponse(fields) {
  const msg = buildMessage(fields);
  const sig = crypto.sign(null, Buffer.from(msg, "utf8"), privateKey()).toString("hex");
  return { ...fields, sig };
}

function sha256(s) {
  return crypto.createHash("sha256").update(s).digest("hex");
}

function genKey() {
  const A = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  const bytes = crypto.randomBytes(16);
  let s = "";
  for (const b of bytes) s += A[b % A.length];
  return "GHST-" + [0, 4, 8, 12].map((i) => s.slice(i, i + 4)).join("-");
}

function safeEqual(a, b) {
  const x = Buffer.from(String(a));
  const y = Buffer.from(String(b));
  return x.length === y.length && crypto.timingSafeEqual(x, y);
}

module.exports = { signResponse, sha256, genKey, safeEqual };
