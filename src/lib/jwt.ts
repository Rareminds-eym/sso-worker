import { SignJWT, jwtVerify, importPKCS8, importSPKI, exportJWK, type KeyLike } from "jose";
import type { Env, AccessTokenPayload } from "../types";

const ALG = "RS256";
const ACCESS_TOKEN_TTL = "15m";

// ─── Key Cache ─────────────────────────────────────────────────
// Workers reuse isolates across requests. Caching the imported
// key avoids re-parsing the PEM on every request (~1-2ms saved).
let cachedPrivateKey: { pem: string; key: KeyLike } | null = null;
let cachedPublicKey: { pem: string; key: KeyLike } | null = null;

async function getPrivateKey(env: Env): Promise<KeyLike> {
  if (cachedPrivateKey?.pem === env.JWT_PRIVATE_KEY) return cachedPrivateKey.key;
  const key = await importPKCS8(env.JWT_PRIVATE_KEY, ALG);
  cachedPrivateKey = { pem: env.JWT_PRIVATE_KEY, key };
  return key;
}

async function getPublicKey(env: Env): Promise<KeyLike> {
  if (cachedPublicKey?.pem === env.JWT_PUBLIC_KEY) return cachedPublicKey.key;
  const key = await importSPKI(env.JWT_PUBLIC_KEY, ALG);
  cachedPublicKey = { pem: env.JWT_PUBLIC_KEY, key };
  return key;
}

/** Sign an access token with the cached private key */
export async function signAccessToken(
  payload: AccessTokenPayload,
  env: Env,
): Promise<string> {
  const privateKey = await getPrivateKey(env);

  return new SignJWT(payload as unknown as Record<string, unknown>)
    .setProtectedHeader({ alg: ALG, kid: env.JWT_KID, typ: "JWT" })
    .setIssuedAt()
    .setExpirationTime(ACCESS_TOKEN_TTL)
    .setIssuer("sso-api")
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
    issuer: "sso-api",
  });

  return payload as unknown as AccessTokenPayload;
}

/** Export the public key as a JWK for the JWKS endpoint */
export async function getPublicJWK(env: Env) {
  const publicKey = await getPublicKey(env);
  const jwk = await exportJWK(publicKey);

  return {
    ...jwk,
    kid: env.JWT_KID,
    alg: ALG,
    use: "sig",
  };
}
