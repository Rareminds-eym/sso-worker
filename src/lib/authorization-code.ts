import type { Env } from "../types";
import type { AuthorizationCodeStore } from "../durable-objects/AuthorizationCodeStore";
import type { TargetApp } from "../types/sso-code";

const AUTH_CODE_TTL_MS = 60_000;
const TOKEN_BYTES = 32;


export interface GeneratedAuthorizationCode {
  code: string;
  state: string;
  codeHash: string;
  stateHash: string;
  expiresAt: string;
  redirectUrl: string;
}

export async function createAuthorizationCode(
  redirectUri: string,
): Promise<GeneratedAuthorizationCode> {
  const code = randomUrlToken();
  const state = randomUrlToken();
  const [codeHash, stateHash] = await Promise.all([hashValue(code), hashValue(state)]);
  const expiresAt = new Date(Date.now() + AUTH_CODE_TTL_MS).toISOString();

  return {
    code,
    state,
    codeHash,
    stateHash,
    expiresAt,
    redirectUrl: buildRedirectUrl(redirectUri, code, state),
  };
}

export async function hashAuthorizationValue(value: string): Promise<string> {
  return hashValue(value);
}

export function assertAllowedRedirectUri(redirectUri: string, env: Env): void {
  let redirect: URL;
  try {
    redirect = new URL(redirectUri);
  } catch {
    throw new Error("Invalid redirect URI");
  }

  const allowed = [
    ...(env.ALLOWED_APP_URLS || "").split(","),
    ...(env.ALLOWED_ORIGINS || "").split(","),
  ]
    .map((value) => value.trim())
    .filter(Boolean);

  if (allowed.length === 0) {
    throw new Error("Redirect URI allowlist is not configured");
  }

  const isAllowed = allowed.some((allowedUrl) => {
    if (allowedUrl.includes("*.")) {
      return matchesWildcardOrigin(redirect, allowedUrl);
    }

    try {
      const base = new URL(allowedUrl);
      return (
        sameLocalAwareOrigin(redirect, base) ||
        sameLocalAwareUrlPrefix(redirect, base)
      );
    } catch {
      return false;
    }
  });

  if (!isAllowed) {
    throw new Error("Redirect URI is not allowlisted");
  }
}

function sameLocalAwareOrigin(left: URL, right: URL): boolean {
  return (
    left.protocol === right.protocol &&
    equivalentLocalHost(left.hostname, right.hostname) &&
    left.port === right.port
  );
}

function sameLocalAwareUrlPrefix(redirect: URL, allowed: URL): boolean {
  if (!sameLocalAwareOrigin(redirect, allowed)) {
    return false;
  }

  const allowedPath = normalizePath(allowed.pathname);
  const redirectPath = normalizePath(redirect.pathname);
  return redirectPath === allowedPath || redirectPath.startsWith(`${allowedPath}/`);
}

function equivalentLocalHost(left: string, right: string): boolean {
  const localHosts = new Set(["localhost", "127.0.0.1", "::1"]);
  if (localHosts.has(left) && localHosts.has(right)) {
    return true;
  }
  return left.toLowerCase() === right.toLowerCase();
}

function normalizePath(pathname: string): string {
  const normalized = pathname.replace(/\/+$/, "");
  return normalized || "/";
}

function matchesWildcardOrigin(redirect: URL, pattern: string): boolean {
  try {
    const patternUrl = new URL(pattern);
    if (!patternUrl.hostname.startsWith("*.")) {
      return false;
    }
    if (redirect.protocol !== patternUrl.protocol) {
      return false;
    }
    const redirectHost = redirect.hostname.toLowerCase();
    const patternHost = patternUrl.hostname.slice(2).toLowerCase();
    if (!patternHost) {
      return false;
    }
    return (
      redirectHost === patternHost ||
      redirectHost.endsWith(`.${patternHost}`)
    );
  } catch {
    return false;
  }
}

// Resolves the DurableObjectStub return type dynamically using ReturnType to prevent
// ambient/runtime import mismatches of DurableObjectStub inside Vitest mock files.
export function getAuthorizationCodeStub(
  env: Env,
  codeHash: string,
): ReturnType<Env["AUTH_CODE_STORE"]["get"]> {
  const id = env.AUTH_CODE_STORE.idFromName(codeHash);
  return env.AUTH_CODE_STORE.get(id);
}

export function assertTargetApp(targetApp: TargetApp): void {
  if (targetApp !== "lte") {
    throw new Error("Unsupported target app");
  }
}

function buildRedirectUrl(redirectUri: string, code: string, state: string): string {
  const url = new URL(redirectUri);
  url.searchParams.set("code", code);
  url.searchParams.set("state", state);
  return url.toString();
}

function randomUrlToken(): string {
  const bytes = new Uint8Array(TOKEN_BYTES);
  crypto.getRandomValues(bytes);
  return base64Url(bytes);
}

async function hashValue(value: string): Promise<string> {
  const input = new TextEncoder().encode(value);
  const digest = await crypto.subtle.digest("SHA-256", input);
  return [...new Uint8Array(digest)]
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}

function base64Url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}
