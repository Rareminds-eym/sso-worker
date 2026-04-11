import bcrypt from "bcryptjs";

const SALT_ROUNDS = 12;

/** Hash a plaintext password with bcrypt */
export async function hashPassword(password: string): Promise<string> {
  return bcrypt.hash(password, SALT_ROUNDS);
}

/** Verify a plaintext password against a bcrypt hash */
export async function verifyPassword(password: string, hash: string): Promise<boolean> {
  return bcrypt.compare(password, hash);
}

/** SHA-256 hash a refresh token (for DB storage) — uses Web Crypto API */
export async function hashToken(token: string): Promise<string> {
  const encoded = new TextEncoder().encode(token);
  const digest = await crypto.subtle.digest("SHA-256", encoded);
  return Array.from(new Uint8Array(digest))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

/** Generate a cryptographically random refresh token */
export function generateRefreshToken(): string {
  return crypto.randomUUID() + crypto.randomUUID();
}
