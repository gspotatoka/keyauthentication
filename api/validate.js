// POST /api/validate  { key, hwid, nonce }   (also used as the app's heartbeat)
const store = require("../lib/store");
const { signResponse, sha256 } = require("../lib/sign");

const DAY = 86400000;

module.exports = async (req, res) => {
  res.setHeader("Cache-Control", "no-store");
  if (req.method !== "POST") return res.status(405).json({ error: "POST only" });

  try {
    const ip = (req.headers["x-forwarded-for"] || "").split(",")[0].trim() || "unknown";
    if (!(await store.rateLimit(`v:${ip}`, 120, 60))) {
      return res.status(429).json({ error: "rate_limited" });
    }

    const body = typeof req.body === "string" ? JSON.parse(req.body || "{}") : req.body || {};
    const key = String(body.key || "").trim().toUpperCase();
    const hwid = String(body.hwid || "").slice(0, 128);
    const nonce = String(body.nonce || "").slice(0, 64);
    if (!key || key.length > 64 || !hwid || !/^[A-Za-z0-9]{8,64}$/.test(nonce)) {
      return res.status(400).json({ error: "bad_request" });
    }

    const out = (status, exp = 0) =>
      res.status(200).json(signResponse({ status, nonce, hwid, exp, ts: Math.floor(Date.now() / 1000) }));

    const id = sha256(key);
    const rec = await store.getLicense(id);
    if (!rec) return out("invalid_key");
    if (rec.revoked) return out("revoked");

    const now = Date.now();
    const dur = rec.durationMs != null ? rec.durationMs : (rec.days || 0) * DAY; // 0 = lifetime

    // Expiry clock starts at first activation.
    if (!rec.exp && dur > 0) rec.exp = now + dur;
    if (!rec.activated) rec.activated = now;
    if (rec.exp && now > rec.exp) {
      await store.saveLicense(id, rec);
      return out("expired", Math.floor(rec.exp / 1000));
    }

    rec.devices = rec.devices || [];
    rec.seen = rec.seen || {};
    if (!rec.devices.includes(hwid)) {
      if (rec.hwidLock !== false && rec.devices.length >= (rec.maxDevices || 1)) return out("device_limit");
      if (rec.devices.length < 200) rec.devices.push(hwid);
    }
    rec.seen[hwid] = { t: now, ip };
    rec.lastSeen = now;
    rec.lastIp = ip;
    await store.saveLicense(id, rec);

    return out("ok", rec.exp ? Math.floor(rec.exp / 1000) : 0);
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: "server_error" });
  }
};
