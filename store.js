// Tiny Upstash/Vercel-KV REST client (no dependencies).
const URL_ = process.env.KV_REST_API_URL || process.env.UPSTASH_REDIS_REST_URL;
const TOKEN = process.env.KV_REST_API_TOKEN || process.env.UPSTASH_REDIS_REST_TOKEN;

async function cmd(...args) {
  if (!URL_ || !TOKEN) throw new Error("Redis store not configured (KV_REST_API_URL / KV_REST_API_TOKEN)");
  const r = await fetch(URL_, {
    method: "POST",
    headers: { Authorization: `Bearer ${TOKEN}`, "Content-Type": "application/json" },
    body: JSON.stringify(args.map(String)),
  });
  const j = await r.json();
  if (j.error) throw new Error(j.error);
  return j.result;
}

const recKey = (hash) => `lic:${hash}`;

async function getLicense(hash) {
  const raw = await cmd("GET", recKey(hash));
  return raw ? JSON.parse(raw) : null;
}
async function saveLicense(hash, rec) {
  await cmd("SET", recKey(hash), JSON.stringify(rec));
  await cmd("SADD", "lics", hash);
}
async function deleteLicense(hash) {
  await cmd("DEL", recKey(hash));
  await cmd("SREM", "lics", hash);
}
async function listLicenses() {
  const hashes = (await cmd("SMEMBERS", "lics")) || [];
  if (!hashes.length) return [];
  const vals = await cmd("MGET", ...hashes.map(recKey));
  return vals
    .map((v, i) => (v ? { id: hashes[i], ...JSON.parse(v) } : null))
    .filter(Boolean)
    .sort((a, b) => b.created - a.created);
}
// Fixed-window rate limit. Returns true if allowed.
async function rateLimit(id, limit, windowSec) {
  const k = `rl:${id}:${Math.floor(Date.now() / 1000 / windowSec)}`;
  const n = await cmd("INCR", k);
  if (n === 1) await cmd("EXPIRE", k, windowSec * 2);
  return n <= limit;
}

module.exports = { getLicense, saveLicense, deleteLicense, listLicenses, rateLimit };
