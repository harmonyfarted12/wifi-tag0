import crypto from "node:crypto";

const sign = (data) =>
  crypto.createHmac("sha256", process.env.NONCE_SECRET).update(data).digest("hex");

export default function handler(req, res) {
  const payload = `${Date.now()}.${crypto.randomBytes(16).toString("hex")}`;
  res.status(200).json({ nonce: `${payload}.${sign(payload)}` });
}
