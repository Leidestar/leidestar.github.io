import { createPrivateKey, createPublicKey, sign, verify } from "node:crypto";
import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";

const U = "https://api.leidestar.com/v1/license";
const P = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEcvWI+2gBUj5JAsxgCPAyXJOVOAWxikwez2nES3dcm17Moh/xxevGzd2UQWiB/t3oZXcKBh9f8bouuoN2L4OFFg==";
const I = "84c39719f4483841b17f4ca0";
const N = 3;
const W = 20000;
const T = 10000;
const z = (ms) => new Promise((r) => setTimeout(r, ms));

export async function a(f = fetch, p = P) {
  try {
    const r = await f(U, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ install: I, app: "leidestar", versionCode: 999999 }),
      signal: AbortSignal.timeout(T),
    });
    if (r.status !== 200) return [0, r.status];
    const x = String((await r.json()).license ?? "").split(".");
    if (x.length !== 2) return [0, 1];
    const k = createPublicKey({ key: Buffer.from(p, "base64"), format: "der", type: "spki" });
    if (!verify("sha256", Buffer.from(x[0], "ascii"), { key: k, dsaEncoding: "ieee-p1363" }, Buffer.from(x[1], "base64url"))) return [0, 2];
    const j = JSON.parse(Buffer.from(x[0], "base64url").toString("utf8"));
    if (j.sub !== I || j.app !== "leidestar") return [0, 3];
    return [1, 0];
  } catch {
    return [0, 4];
  }
}

export function b(s, t, q) {
  const k = createPrivateKey({ key: Buffer.from(q, "base64"), format: "der", type: "pkcs8" });
  const h = Buffer.from(JSON.stringify({ v: 2, k: "1", s, t }), "utf8").toString("base64url");
  return h + "." + sign("sha256", Buffer.from(h, "ascii"), { key: k, dsaEncoding: "ieee-p1363" }).toString("base64url");
}

async function main() {
  const o = process.argv[2];
  const q = process.env.K ?? "";
  if (!o || !q) process.exit(2);
  let r = [0, 5];
  for (let i = 1; i <= N; i++) {
    r = await a();
    console.log(i, r[0], r[1]);
    if (r[0]) break;
    if (i < N) await z(W);
  }
  mkdirSync(o, { recursive: true });
  writeFileSync(join(o, "s.txt"), b(r[0], Math.floor(Date.now() / 1000), q) + "\n");
}

if (import.meta.url === `file://${process.argv[1]}`) await main();
