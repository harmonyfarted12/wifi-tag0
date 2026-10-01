import crypto from "node:crypto";

const MAX_AGE_MS = 5 * 60 * 1000;

function nonceIsValid(nonce) {
  const parts = nonce.split(".");
  if (parts.length !== 3) return false;
  const [ts, rand, sig] = parts;
  const expected = crypto
    .createHmac("sha256", process.env.NONCE_SECRET)
    .update(`${ts}.${rand}`)
    .digest("hex");
  const sigOk =
    sig.length === expected.length &&
    crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected));
  return sigOk && Date.now() - Number(ts) < MAX_AGE_MS;
}

export default async function handler(req, res) {
  if (req.method !== "POST") return res.status(405).end();
  const { token, nonce } = req.body ?? {};
  if (!token || !nonce || !nonceIsValid(nonce)) {
    return res.status(400).json({ ok: false, reason: "bad_request" });
  }

  const url =
    "https://graph.oculus.com/platform_integrity/verify" +
    `?token=${encodeURIComponent(token)}` +
    `&access_token=${encodeURIComponent(process.env.META_ACCESS_TOKEN)}`;

  const metaRes = await fetch(url);
  if (!metaRes.ok) return res.status(403).json({ ok: false, reason: "verify_failed" });

  const body = await metaRes.json();
  console.log("attestation response", body); // inspect once, then adjust below

  // Meta returns a Base64URL-encoded token. Decode its payload and read
  // device_state / app_state (device_integrity_state, app_integrity_state, unique_id).
  // TODO: also confirm the nonce inside the token matches the one you issued.

  return res.status(200).json({ ok: true });
}
