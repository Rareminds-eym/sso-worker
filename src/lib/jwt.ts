import { SignJWT, importPKCS8, importSPKI, jwtVerify } from "jose";
import type { AccessTokenPayload, Env } from "../types";
import { JWT_AUDIENCE, JWT_ISSUER } from "./constants";

const ALG = "RS256";
const ACCESS_TOKEN_TTL = "15m";

// ─── Key Cache ─────────────────────────────────────────────────
let cachedPrivateKey: { pem: string; key: any } | null = null;
let cachedPublicKey: { pem: string; key: any } | null = null;

async function getPrivateKey(env: Env): Promise<any> {
  if (!cachedPrivateKey || cachedPrivateKey.pem !== env.JWT_PRIVATE_KEY) {
    if (!env.JWT_PRIVATE_KEY) throw new Error("JWT_PRIVATE_KEY is missing from environment");

    // Handle both literal string '\n' (from .dev.vars) and actual newlines
    let formattedKey = env.JWT_PRIVATE_KEY;
    if (typeof formattedKey === 'string' && formattedKey.includes('\\n')) {
      formattedKey = formattedKey.split('\\n').join('\n');
    }

    try {
      const key = await importPKCS8(formattedKey, "RS256");
      cachedPrivateKey = {
        pem: env.JWT_PRIVATE_KEY,
        key: key,
      };
    } catch (err: any) {
      throw new Error(`Failed to import JWT_PRIVATE_KEY (PKCS8). Key length: ${formattedKey.length}, Starts with: ${formattedKey.substring(0, 30)}. Error: ${err.message}`);
    }
  }
  return cachedPrivateKey.key;
}

async function getPublicKey(env: Env): Promise<any> {
  if (cachedPublicKey?.pem === env.JWT_PUBLIC_KEY) return cachedPublicKey.key;
  if (!env.JWT_PUBLIC_KEY) throw new Error("JWT_PUBLIC_KEY is missing from environment");

  let formattedKey = env.JWT_PUBLIC_KEY;
  if (typeof formattedKey === 'string' && formattedKey.includes('\\n')) {
    formattedKey = formattedKey.split('\\n').join('\n');
  }

  try {
    const key = await importSPKI(formattedKey, ALG);
    cachedPublicKey = { pem: env.JWT_PUBLIC_KEY, key };
    return key;
  } catch (err: any) {
    throw new Error(`Failed to import JWT_PUBLIC_KEY (SPKI). Key length: ${formattedKey.length}, Starts with: ${formattedKey.substring(0, 30)}. Error: ${err.message}`);
  }
}

/** Sign an access token with the rich RBAC payload */
export async function signAccessToken(
  payload: AccessTokenPayload,
  env: Env,
): Promise<string> {
  if (!env.JWT_PRIVATE_KEY) {
    throw new Error("JWT_PRIVATE_KEY environment variable not set");
  }
  if (!env.JWT_KID) {
    throw new Error("JWT_KID environment variable not set");
  }

  const privateKey = await getPrivateKey(env);

  const token = await new SignJWT(payload as unknown as Record<string, unknown>)
    .setProtectedHeader({ alg: ALG, kid: env.JWT_KID, typ: "JWT" })
    .setIssuedAt()
    // Every issuance is a distinct credential even when identical claims are signed in the same second.
    .setJti(crypto.randomUUID())
    .setExpirationTime(ACCESS_TOKEN_TTL)
    .setIssuer(JWT_ISSUER)
    .setAudience(JWT_AUDIENCE)
    .sign(privateKey);

  if (!token) {
    throw new Error("JWT signing returned empty token");
  }

  return token;
}

/** Verify an access token with the cached public key */
export async function verifyAccessToken(
  token: string,
  env: Env,
): Promise<AccessTokenPayload> {
  const publicKey = await getPublicKey(env);

  const { payload, protectedHeader } = await jwtVerify(token, publicKey, {
    algorithms: [ALG],
    issuer: JWT_ISSUER,
    audience: JWT_AUDIENCE,
  });

  if (protectedHeader.typ !== "JWT") {
    throw new Error("Invalid token type");
  }

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
