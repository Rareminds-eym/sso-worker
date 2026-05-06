import type { Env, RouteConfig } from "./types";
import { signup } from "./routes/signup";
import { signupMember } from "./routes/signup-member";
import { login } from "./routes/login";
import { refresh } from "./routes/refresh";
import { logout } from "./routes/logout";
import { me } from "./routes/me";
import { switchOrg } from "./routes/switch-org";
import { createInvite, acceptInvite } from "./routes/invite";
import { listOrgs } from "./routes/orgs";
import { jwks } from "./routes/jwks";
import { requestVerification, verifyEmail } from "./routes/verify-email";
import { forgotPassword, resetPassword } from "./routes/password-reset";
import { cancelInvite, resendInvite } from "./routes/invite-manage";
import { oauthRedirect, oauthCallback } from "./routes/oauth";
import { changePassword, adminResetPassword } from "./routes/change-password";
import { rateLimit } from "./lib/rate-limit";
import { authenticate } from "./lib/auth";
import { json, error } from "./lib/response";
import { db } from "./lib/db";

/** Max request body size: 10 KB */
const MAX_BODY_SIZE = 10_240;

// ─── Declarative Route Table ───────────────────────────────────
const routes: Record<string, Record<string, RouteConfig>> = {
  POST: {
    "/auth/signup":              { handler: signup },
    "/auth/signup-member":       { handler: signupMember },
    "/auth/login":               { handler: login },
    "/auth/refresh":             { handler: refresh },
    "/auth/logout":              { handler: logout },
    "/auth/switch-org":          { handler: switchOrg,           auth: true },
    "/auth/invite":              { handler: createInvite,        auth: true },
    "/auth/invite/accept":       { handler: acceptInvite },
    "/auth/invite/cancel":       { handler: cancelInvite,        auth: true },
    "/auth/invite/resend":       { handler: resendInvite,        auth: true },
    "/auth/request-verification": { handler: requestVerification, auth: true },
    "/auth/verify-email":        { handler: verifyEmail },
    "/auth/forgot-password":     { handler: forgotPassword },
    "/auth/reset-password":      { handler: resetPassword },
    "/auth/change-password":     { handler: changePassword,      auth: true },
    "/auth/admin-reset-password": { handler: adminResetPassword, auth: true },
  },
  GET: {
    "/auth/me":               { handler: me, auth: true },
    "/auth/orgs":             { handler: listOrgs, auth: true },
    "/auth/oauth/google":     { handler: oauthRedirect },
    "/auth/oauth/github":     { handler: oauthRedirect },
    "/auth/oauth/google/callback": { handler: oauthCallback },
    "/auth/oauth/github/callback": { handler: oauthCallback },
    "/.well-known/jwks.json": { handler: (_req, env) => jwks(env) },
    "/health":                { handler: () => Promise.resolve(json({ status: "ok" })) },
  },
};

// ─── CORS ──────────────────────────────────────────────────────
function originMatchesPattern(origin: string, pattern: string): boolean {
  if (pattern === "*") return true;
  if (pattern.includes("*.")) {
    // Wildcard subdomain: "https://*.rareminds.in" matches "https://skillpassport.rareminds.in"
    const wildcardSuffix = pattern.replace("*.", "");
    try {
      const originUrl = new URL(origin);
      const patternUrl = new URL(wildcardSuffix);
      return (
        originUrl.protocol === patternUrl.protocol &&
        (originUrl.hostname === patternUrl.hostname ||
          originUrl.hostname.endsWith("." + patternUrl.hostname))
      );
    } catch {
      return false;
    }
  }
  return origin === pattern;
}

function corsHeaders(req: Request, env: Env): Record<string, string> {
  const origin = req.headers.get("Origin") ?? "";
  const allowed = env.ALLOWED_ORIGINS.split(",").map((o) => o.trim());
  const isAllowed = allowed.some((pattern) => originMatchesPattern(origin, pattern));

  if (!isAllowed) return {};

  return {
    "Access-Control-Allow-Origin": origin,
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Request-ID",
    "Access-Control-Allow-Credentials": "true",
    "Access-Control-Expose-Headers": "X-Access-Token, X-Request-ID",
    "Access-Control-Max-Age": "86400",
  };
}

function withCors(response: Response, cors: Record<string, string>): Response {
  const res = new Response(response.body, response);
  for (const [k, v] of Object.entries(cors)) res.headers.set(k, v);
  return res;
}

// ─── CSRF Protection ───────────────────────────────────────────
function csrfCheck(req: Request, env: Env): boolean {
  if (req.method === "GET" || req.method === "OPTIONS") return true;

  const origin = req.headers.get("Origin");
  if (!origin) return true; // non-browser clients (curl, SDKs) don't send Origin

  const allowed = env.ALLOWED_ORIGINS.split(",").map((o) => o.trim());
  return allowed.some((pattern) => originMatchesPattern(origin, pattern));
}

// ─── Worker Entry ──────────────────────────────────────────────
export default {
  async scheduled(_event: ScheduledEvent, env: Env, _ctx: ExecutionContext): Promise<void> {
    const database = db(env);
    const deleted = await database.rpc<number>("cleanup_expired_tokens");
    console.log(`[SSO] Cleaned up ${deleted} expired token rows`);
  },

  async fetch(req: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const cors = corsHeaders(req, env);
    const requestId = crypto.randomUUID();

    // Preflight
    if (req.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: cors });
    }

    const url = new URL(req.url);
    const { pathname } = url;
    const method = req.method;
    const start = Date.now();

    // CSRF check
    if (!csrfCheck(req, env)) {
      return withCors(error("Origin not allowed", 403), cors);
    }

    // Body size limit (10 KB for auth endpoints)
    const contentLength = parseInt(req.headers.get("Content-Length") ?? "0", 10);
    if (contentLength > MAX_BODY_SIZE) {
      return withCors(error("Request body too large", 413), cors);
    }

    // Rate limiting
    const rateLimited = await rateLimit(req, env, pathname);
    if (rateLimited) return withCors(rateLimited, cors);

    // Route matching
    const config = routes[method]?.[pathname];
    if (!config) {
      return withCors(error("Not found", 404), cors);
    }

    try {
      // Declarative auth
      let authPayload;
      if (config.auth) {
        authPayload = await authenticate(req, env);
        if (!authPayload) {
          return withCors(error("Unauthorized", 401), cors);
        }
      }

      const response = await config.handler(req, env, ctx, authPayload);
      const res = withCors(response, cors);
      res.headers.set("X-Request-ID", requestId);

      console.log(
        JSON.stringify({
          rid: requestId,
          method,
          path: pathname,
          status: res.status,
          ms: Date.now() - start,
        }),
      );

      return res;
    } catch (err: any) {
      console.error(
        JSON.stringify({
          rid: requestId,
          method,
          path: pathname,
          error: err?.message ?? "unknown",
          stack: err?.stack,
          ms: Date.now() - start,
        }),
      );
      return withCors(error("Internal server error", 500), cors);
    }
  },
};
