// POST /api/validate  { key, hwid, nonce }
const store = require("../lib/store");
const { signResponse, sha256 } = require("../lib/sign");

const DAY = 86400000;

module.exports = async (req, res) => {
  res.setHeader("Cache-Control", "no-store");
  if (req.method !== "POST") return res.status(405).json({ error: "POST only" });

  try {
    const ip = (req.headers["x-forwarded-for"] || "").split(",")[0].trim() || "unknown";
    if (!(await store.rateLimit(`v:${ip}`, 30, 60))) {
      return res.status(429).json({ error: "rate_limited" });
    }

    const body = typeof req.body === "string" ? JSON.parse(req.body || "{}") : req.body || {};
    const key = String(body.key || "").trim().toUpperCase();
    const hwid = String(body.hwid || "").slice(0, 128);
    const nonce = String(body.nonce || "").slice(0, 64);
    if (!key || !hwid || !/^[A-Za-z0-9]{8,64}$/.test(nonce)) {
      return res.status(400).json({ error: "bad_request" });
    }

    const out = (status, exp = 0) =>
      res.status(200).json(signResponse({ status, nonce, hwid, exp, ts: Math.floor(Date.now() / 1000) }));

    const id = sha256(key);
    const rec = await store.getLicense(id);
    if (!rec) return out("invalid_key");
    if (rec.revoked) return out("revoked");

    const now = Date.now();

    // Expiry clock starts at first activation.
    if (!rec.exp && rec.days > 0) {
      rec.exp = now + rec.days * DAY;
      rec.activated = now;
    }
    if (rec.exp && now > rec.exp) {
      await store.saveLicense(id, rec);
      return out("expired", Math.floor(rec.exp / 1000));
    }

    rec.devices = rec.devices || [];
    if (!rec.devices.includes(hwid)) {
      if (rec.devices.length >= (rec.maxDevices || 1)) return out("device_limit");
      rec.devices.push(hwid);
    }
    rec.lastSeen = now;
    rec.lastIp = ip;
    await store.saveLicense(id, rec);

    return out("ok", rec.exp ? Math.floor(rec.exp / 1000) : 0);
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: "server_error" });
  }
};
