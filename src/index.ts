import type { Env, RouteConfig } from "./types";
import { signup } from "./routes/signup";
import { login } from "./routes/login";
import { refresh } from "./routes/refresh";
import { logout } from "./routes/logout";
import { validate } from "./routes/validate";
import { switchOrg } from "./routes/switch-org";
import { createInvite, acceptInvite } from "./routes/invite";
import { listOrgs } from "./routes/orgs";
import { jwks } from "./routes/jwks";
import { rateLimit } from "./lib/rate-limit";
import { authenticate } from "./lib/auth";
import { json, error } from "./lib/response";

// ─── Declarative Route Table ───────────────────────────────────
// auth: true → authenticate() is called automatically; 401 if it fails.
// auth: false/omitted → public route.
const routes: Record<string, Record<string, RouteConfig>> = {
  POST: {
    "/auth/signup":        { handler: signup },
    "/auth/login":         { handler: login },
    "/auth/refresh":       { handler: refresh },
    "/auth/logout":        { handler: logout },
    "/auth/switch-org":    { handler: switchOrg,    auth: true },
    "/auth/invite":        { handler: createInvite, auth: true },
    "/auth/invite/accept": { handler: acceptInvite },
  },
  GET: {
    "/auth/validate-session": { handler: validate, auth: true },
    "/auth/orgs":             { handler: listOrgs, auth: true },
    "/.well-known/jwks.json": { handler: (_req, env) => jwks(env) },
    "/health":                { handler: () => Promise.resolve(json({ status: "ok" })) },
  },
};

// ─── CORS ──────────────────────────────────────────────────────
function corsHeaders(req: Request, env: Env): Record<string, string> {
  const origin = req.headers.get("Origin") ?? "";
  const allowed = env.ALLOWED_ORIGINS.split(",").map((o) => o.trim());
  const isAllowed = allowed.includes(origin) || allowed.includes("*");

  if (!isAllowed) return {};

  return {
    "Access-Control-Allow-Origin": origin,
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Request-ID",
    "Access-Control-Allow-Credentials": "true",
    "Access-Control-Max-Age": "86400",
  };
}

function withCors(response: Response, cors: Record<string, string>): Response {
  const res = new Response(response.body, response);
  for (const [k, v] of Object.entries(cors)) res.headers.set(k, v);
  return res;
}

// ─── CSRF Protection ───────────────────────────────────────────
// For state-changing requests with credentials, verify the Origin header
// matches an allowed origin. Prevents cross-site form submissions.
function csrfCheck(req: Request, env: Env): boolean {
  if (req.method === "GET" || req.method === "OPTIONS") return true;

  const origin = req.headers.get("Origin");
  if (!origin) return true; // non-browser clients (curl, SDKs) don't send Origin

  const allowed = env.ALLOWED_ORIGINS.split(",").map((o) => o.trim());
  return allowed.includes(origin) || allowed.includes("*");
}

// ─── Worker Entry ──────────────────────────────────────────────
export default {
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

    // Rate limiting
    const rateLimited = await rateLimit(req, env, pathname);
    if (rateLimited) return withCors(rateLimited, cors);

    // Route matching
    const config = routes[method]?.[pathname];
    if (!config) {
      return withCors(error("Not found", 404), cors);
    }

    try {
      // Declarative auth — if route requires auth, verify before calling handler
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

      // Structured log
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
