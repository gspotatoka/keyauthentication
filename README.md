# GhostScript license server (Vercel)

Key authenticator for the Night Spawner. Keys are stored in Upstash Redis, replies are
signed with Ed25519 so a fake server / edited reply is rejected by the client.

## Deploy (about 5 minutes)
1. `npm run keypair`  -> prints LICENSE_PRIVATE_SEED (secret) and LICENSE_PUBLIC_KEY.
2. Push this folder to a GitHub repo, then on vercel.com: **Add New > Project > import it**
   (or run `npx vercel` in this folder).
3. In the Vercel project: **Storage / Marketplace > Upstash Redis > Create**, connect it to
   the project (adds KV_REST_API_URL / KV_REST_API_TOKEN automatically).
4. **Settings > Environment Variables**, add:
   - `ADMIN_TOKEN`  = a long random string (16+ chars) - your /admin password
   - `LICENSE_PRIVATE_SEED` = the seed from step 1
5. **Redeploy** (env vars only apply to new deployments).
6. Open `https://YOUR-PROJECT.vercel.app/admin`, enter the admin token, generate keys.

## Client
In `scum_night_spawner_licensed.py` set at the top of the licensing block:
```
LICENSE_SERVER_URL = "https://YOUR-PROJECT.vercel.app"
LICENSE_PUBLIC_KEY = "<LICENSE_PUBLIC_KEY from step 1>"
```
Then build as usual with Nuitka. Key is saved in `license.json` next to the exe.
CLI: `--license-key KEY` or env `NIGHT_SPAWNER_KEY`.

## Rules
- Days = 0 is a lifetime key; otherwise the clock starts at first activation.
- Max devices = how many different PCs may use one key (Reset devices in /admin frees them).
- Works offline for 72 h after the last successful check.
- Never share LICENSE_PRIVATE_SEED or ADMIN_TOKEN; the public key is safe to ship.

## API
- `POST /api/validate` `{key, hwid, nonce}` -> signed `{status, nonce, hwid, exp, ts, sig}`
- `POST /api/admin` (Bearer ADMIN_TOKEN) `{action: create|list|revoke|unrevoke|reset_devices|delete}`
