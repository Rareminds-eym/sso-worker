import { SignJWT, jwtVerify, importPKCS8, importSPKI } from "jose";
import type { Env, AccessTokenPayload } from "../types";
import { JWT_ISSUER, JWT_AUDIENCE } from "./constants";

const ALG = "RS256";
const ACCESS_TOKEN_TTL = "15m";

// ─── Key Cache ─────────────────────────────────────────────────
let cachedPrivateKey: { pem: string; key: any } | null = null;
let cachedPublicKey: { pem: string; key: any } | null = null;

async function getPrivateKey(env: Env): Promise<any> {
  if (!cachedPrivateKey || cachedPrivateKey.pem !== env.JWT_PRIVATE_KEY) {
    cachedPrivateKey = {
      pem: env.JWT_PRIVATE_KEY,
      key: await importPKCS8(env.JWT_PRIVATE_KEY, "RS256"),
    };
  }
  return cachedPrivateKey.key;
}

async function getPublicKey(env: Env): Promise<any> {
  if (cachedPublicKey?.pem === env.JWT_PUBLIC_KEY) return cachedPublicKey.key;
  const key = await importSPKI(env.JWT_PUBLIC_KEY, ALG);
  cachedPublicKey = { pem: env.JWT_PUBLIC_KEY, key };
  return key;
}

/** Sign an access token with the rich RBAC payload */
export async function signAccessToken(
  payload: AccessTokenPayload,
  env: Env,
): Promise<string> {
  const privateKey = await getPrivateKey(env);

  return new SignJWT(payload as unknown as Record<string, unknown>)
    .setProtectedHeader({ alg: ALG, kid: env.JWT_KID, typ: "JWT" })
    .setIssuedAt()
    .setExpirationTime(ACCESS_TOKEN_TTL)
    .setIssuer(JWT_ISSUER)
    .setAudience(JWT_AUDIENCE)
    .sign(privateKey);
}

/** Verify an access token with the cached public key */
export async function verifyAccessToken(
  token: string,
  env: Env,
): Promise<AccessTokenPayload> {
  const publicKey = await getPublicKey(env);

  const { payload } = await jwtVerify(token, publicKey, {
    algorithms: [ALG],
    issuer: JWT_ISSUER,
    audience: JWT_AUDIENCE,
  });

  return payload as unknown as AccessTokenPayload;
}

/** Export the public key as a JWK for the JWKS endpoint */
export async function getPublicJWK(env: Env) {
  return exportPemAsJwk(env.JWT_PUBLIC_KEY, env.JWT_KID);
}

/** Export any PEM public key as a JWK with the given kid */
export async function exportPemAsJwk(pem: string, kid: string) {
  const pemBody = pem
    .replace(/-----BEGIN PUBLIC KEY-----/, "")
    .replace(/-----END PUBLIC KEY-----/, "")
    .replace(/\s/g, "");
  const binaryDer = Uint8Array.from(atob(pemBody), (c) => c.charCodeAt(0));

  const cryptoKey = await crypto.subtle.importKey(
    "spki",
    binaryDer,
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    true,
    ["verify"],
  );

  const jwk = await crypto.subtle.exportKey("jwk", cryptoKey);

  return {
    ...jwk,
    kid,
    alg: ALG,
    use: "sig",
  };
}
