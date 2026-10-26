// POST /api/admin   Authorization: Bearer <ADMIN_TOKEN>
// body: { action: "create"|"list"|"revoke"|"unrevoke"|"reset_devices"|"delete", ... }
const store = require("../lib/store");
const { genKey, sha256, safeEqual } = require("../lib/sign");

module.exports = async (req, res) => {
  res.setHeader("Cache-Control", "no-store");
  if (req.method !== "POST") return res.status(405).json({ error: "POST only" });

  const admin = process.env.ADMIN_TOKEN || "";
  const auth = (req.headers.authorization || "").replace(/^Bearer\s+/i, "");
  const ip = (req.headers["x-forwarded-for"] || "").split(",")[0].trim() || "unknown";

  try {
    if (!(await store.rateLimit(`a:${ip}`, 60, 60))) return res.status(429).json({ error: "rate_limited" });
    if (admin.length < 16 || !safeEqual(auth, admin)) return res.status(401).json({ error: "unauthorized" });

    const b = typeof req.body === "string" ? JSON.parse(req.body || "{}") : req.body || {};

    switch (b.action) {
      case "create": {
        const count = Math.min(Math.max(parseInt(b.count) || 1, 1), 100);
        const days = Math.max(parseInt(b.days) || 0, 0); // 0 = lifetime
        const maxDevices = Math.min(Math.max(parseInt(b.maxDevices) || 1, 1), 50);
        const note = String(b.note || "").slice(0, 120);
        const keys = [];
        for (let i = 0; i < count; i++) {
          const key = genKey();
          await store.saveLicense(sha256(key), {
            key, note, days, maxDevices, exp: 0, devices: [], revoked: false, created: Date.now(),
          });
          keys.push(key);
        }
        return res.json({ ok: true, keys });
      }
      case "list":
        return res.json({ ok: true, licenses: await store.listLicenses() });
      case "revoke":
      case "unrevoke":
      case "reset_devices":
      case "delete": {
        const id = String(b.id || "");
        const rec = await store.getLicense(id);
        if (!rec) return res.status(404).json({ error: "not_found" });
        if (b.action === "delete") await store.deleteLicense(id);
        else {
          if (b.action === "revoke") rec.revoked = true;
          if (b.action === "unrevoke") rec.revoked = false;
          if (b.action === "reset_devices") rec.devices = [];
          await store.saveLicense(id, rec);
        }
        return res.json({ ok: true });
      }
      default:
        return res.status(400).json({ error: "unknown_action" });
    }
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: "server_error" });
  }
};
