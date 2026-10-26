// POST /api/admin   Authorization: Bearer <ADMIN_TOKEN>
const store = require("../lib/store");
const { genKey, sha256, safeEqual } = require("../lib/sign");

const UNIT = { minutes: 60000, hours: 3600000, days: 86400000 };
const ONLINE_MS = 10 * 60 * 1000; // "online" = heard from within 10 minutes (app pings every 5)

function parseBody(req) {
  return typeof req.body === "string" ? JSON.parse(req.body || "{}") : req.body || {};
}

function statusOf(l, now) {
  if (l.revoked) return "revoked";
  if (l.exp && now > l.exp) return "expired";
  if (!l.activated) return "unused";
  return "active";
}

module.exports = async (req, res) => {
  res.setHeader("Cache-Control", "no-store");
  if (req.method !== "POST") return res.status(405).json({ error: "POST only" });

  const admin = process.env.ADMIN_TOKEN || "";
  const auth = (req.headers.authorization || "").replace(/^Bearer\s+/i, "");
  const ip = (req.headers["x-forwarded-for"] || "").split(",")[0].trim() || "unknown";

  try {
    if (!(await store.rateLimit(`a:${ip}`, 120, 60))) return res.status(429).json({ error: "rate_limited" });
    if (admin.length < 16 || !safeEqual(auth, admin)) return res.status(401).json({ error: "unauthorized" });

    const b = parseBody(req);

    switch (b.action) {
      case "create": {
        const custom = String(b.customKey || "").trim().toUpperCase();
        if (custom && !/^[A-Z0-9][A-Z0-9_-]{5,63}$/.test(custom))
          return res.status(400).json({ error: "bad_custom_key (6-64 chars: A-Z 0-9 - _)" });
        const count = custom ? 1 : Math.min(Math.max(parseInt(b.count) || 1, 1), 100);

        let durationMs = 0; // lifetime
        if (b.unit && b.unit !== "lifetime") {
          const mul = UNIT[b.unit];
          const amt = Math.max(parseInt(b.amount) || 0, 0);
          if (!mul || amt < 1) return res.status(400).json({ error: "bad_duration" });
          durationMs = amt * mul;
        }
        const hwidLock = b.hwidLock !== false;
        const maxDevices = Math.min(Math.max(parseInt(b.maxDevices) || 1, 1), 50);
        const presetHwid = String(b.hwid || "").trim().slice(0, 128);
        const note = String(b.note || "").slice(0, 120);

        const keys = [];
        for (let i = 0; i < count; i++) {
          const key = custom || genKey();
          const id = sha256(key);
          if (await store.getLicense(id)) return res.status(409).json({ error: "key_exists" });
          await store.saveLicense(id, {
            key, note, durationMs, hwidLock, maxDevices, exp: 0, activated: 0,
            devices: presetHwid ? [presetHwid] : [], seen: {}, revoked: false, created: Date.now(),
          });
          keys.push(key);
        }
        await store.incrBy("stat:generated", keys.length);
        return res.json({ ok: true, keys });
      }

      case "list": {
        const now = Date.now();
        const licenses = await store.listLicenses();
        const stats = { generated: await store.getNum("stat:generated"), stored: licenses.length,
          active: 0, unused: 0, expired: 0, revoked: 0, online: 0, devices: 0 };
        const online = [];
        for (const l of licenses) {
          l.status = statusOf(l, now);
          stats[l.status]++;
          stats.devices += (l.devices || []).length;
          for (const [h, s] of Object.entries(l.seen || {})) {
            if (now - s.t <= ONLINE_MS && l.status === "active") {
              online.push({ id: l.id, key: l.key, note: l.note, hwid: h, ip: s.ip, t: s.t });
            }
          }
        }
        online.sort((a, c) => c.t - a.t);
        stats.online = online.length;
        stats.generated = Math.max(stats.generated, licenses.length);
        return res.json({ ok: true, now, onlineWindowMs: ONLINE_MS, stats, online, licenses });
      }

      case "revoke": case "unrevoke": case "reset_devices": case "remove_device":
      case "toggle_lock": case "extend": case "delete": {
        const id = String(b.id || "");
        const rec = await store.getLicense(id);
        if (!rec) return res.status(404).json({ error: "not_found" });
        if (b.action === "delete") { await store.deleteLicense(id); return res.json({ ok: true }); }

        if (b.action === "revoke") rec.revoked = true;
        if (b.action === "unrevoke") rec.revoked = false;
        if (b.action === "reset_devices") { rec.devices = []; rec.seen = {}; }
        if (b.action === "remove_device") {
          const h = String(b.hwid || "");
          rec.devices = (rec.devices || []).filter((x) => x !== h);
          if (rec.seen) delete rec.seen[h];
        }
        if (b.action === "toggle_lock") rec.hwidLock = rec.hwidLock === false;
        if (b.action === "extend") {
          const mul = UNIT[b.unit];
          const amt = parseInt(b.amount) || 0;
          if (!mul || amt < 1) return res.status(400).json({ error: "bad_duration" });
          const add = amt * mul;
          if (rec.exp) rec.exp = Math.max(rec.exp, Date.now()) + add;
          else if ((rec.durationMs || 0) > 0 || (rec.days || 0) > 0)
            rec.durationMs = (rec.durationMs != null ? rec.durationMs : rec.days * 86400000) + add;
          else return res.status(400).json({ error: "lifetime_key" });
        }
        await store.saveLicense(id, rec);
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
