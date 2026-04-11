# SSO API

Production-grade Single Sign-On API built on Cloudflare Workers, backed by Supabase (PostgreSQL). RS256 JWTs, stateful session rotation, multi-tenant organizations, invite flows, and edge-native rate limiting — fully verified against the live database schema.

---

## Architecture

```
Client Apps
    │
    ▼
Cloudflare Worker  (sso-api)
    │
    ├── Supabase PostgreSQL  (auth DB via service-role key)
    ├── Cloudflare KV        (rate limiting + account lockout)
    └── /.well-known/jwks.json  (public key — consumed by downstream services)
```

Token strategy:
- **Access token** — RS256 JWT, 15-minute TTL, signed with private key, verified by any service via JWKS
- **Refresh token** — random UUID pair, SHA-256 hashed before DB storage, 30-day TTL, rotated on every use

---

## Project Structure

```
sso-worker/
├── src/
│   ├── index.ts              # Router, CORS, CSRF, rate limiting, request ID, structured logging
│   ├── types.ts              # Env, RouteConfig, RouteHandler, all DB model interfaces, request bodies
│   ├── lib/
│   │   ├── constants.ts      # All shared magic numbers (TTLs, thresholds, timeouts)
│   │   ├── db.ts             # PostgREST client with AbortController timeout on every call
│   │   ├── jwt.ts            # RS256 sign/verify/export with module-level key cache
│   │   ├── hash.ts           # bcrypt password hashing, SHA-256 token hashing, refresh token generation
│   │   ├── cookies.ts        # HttpOnly/Secure/SameSite=None cookie set/clear/parse
│   │   ├── rate-limit.ts     # Per-IP fixed-window limiter + per-email account lockout
│   │   ├── auth.ts           # Token extraction (header → cookie) + JWT verification
│   │   ├── audit.ts          # Non-blocking audit log via ctx.waitUntil()
│   │   ├── validate.ts       # Email format + password length validation
│   │   └── response.ts       # json() and error() response helpers
│   └── routes/
│       ├── signup.ts         # Transactional signup via signup_user() RPC
│       ├── login.ts          # Credential verify, blocked check, lockout, last_login_at update
│       ├── refresh.ts        # Token rotation with theft detection, rotated_from chain
│       ├── logout.ts         # Session revocation + cookie clear
│       ├── validate.ts       # Access token verification (declarative auth)
│       ├── switch-org.ts     # Org switch with session rotation
│       ├── invite.ts         # Create invite + accept invite (with membership reactivation)
│       ├── orgs.ts           # List user's active organizations
│       └── jwks.ts           # Public key set for external JWT verification
├── scripts/
│   ├── schema.sql            # Full DB schema matching live Supabase tables
│   └── generate-keys.mjs    # RS256 key pair generator
├── wrangler.toml
├── package.json
├── tsconfig.json
├── .gitignore
└── .dev.vars.example
```

---

## API Reference

All responses are `Content-Type: application/json`. All error responses have the shape `{ "error": "message" }`.

Every response includes an `X-Request-ID` header (UUID) for log correlation.

### Public Endpoints (no auth required)

---

#### `POST /auth/signup`

Create a new user account and organization atomically. Uses a PostgreSQL RPC function (`signup_user`) so if any step fails, the entire operation rolls back — no orphaned rows.

**Rate limit:** 3 requests / 60s per IP

**Request body:**
```json
{
  "email": "user@example.com",
  "password": "min8chars",
  "org_name": "Acme Corp"
}
```

**Success `201`:**
```json
{
  "user": { "id": "uuid", "email": "user@example.com" },
  "org":  { "id": "uuid", "name": "Acme Corp", "slug": "acme-corp" }
}
```

**Sets cookies:** `access_token` (15 min), `refresh_token` (30 days)

**Errors:**
- `400` — missing fields, invalid email, password too short/long (max 72 chars)
- `409` — email already registered

---

#### `POST /auth/login`

Authenticate with email and password.

**Rate limit:** 5 requests / 60s per IP. Additionally, 10 failed attempts per email triggers a 15-minute account lockout (resets on successful login).

Constant-time response whether or not the user exists (prevents email enumeration via timing).

**Request body:**
```json
{
  "email": "user@example.com",
  "password": "yourpassword"
}
```

**Success `200`:**
```json
{
  "success": true,
  "user": { "id": "uuid", "email": "user@example.com" },
  "active_org_id": "uuid",
  "organizations": [
    { "org_id": "uuid", "role": "owner" },
    { "org_id": "uuid", "role": "member" }
  ]
}
```

`organizations` lists all active memberships — use this to show an org picker or call `/auth/switch-org`.

**Sets cookies:** `access_token` (15 min), `refresh_token` (30 days)

**Side effects:** Updates `users.last_login_at` (non-blocking via `waitUntil`).

**Errors:**
- `400` — missing fields, invalid email format
- `401` — invalid credentials
- `403` — account is blocked (`users.is_blocked = true`)
- `429` — rate limited or account locked out

---

#### `POST /auth/refresh`

Rotate the refresh token. Issues a new access token and a new refresh token. The old refresh token is immediately revoked.

**Theft detection:** If a revoked refresh token is presented, ALL sessions for that user are immediately revoked and a `refresh_theft_detected` audit event is written.

**Rate limit:** 10 requests / 60s per IP

**Request:** No body. Reads `refresh_token` cookie automatically.

**Success `200`:**
```json
{ "success": true }
```

**Sets cookies:** new `access_token` (15 min), new `refresh_token` (30 days)

**Side effects:** New session row has `rotated_from` pointing to the old session ID (full rotation chain in DB).

**Errors:**
- `401` — no refresh token, invalid token, revoked token (theft), expired session

---

#### `POST /auth/logout`

Revoke the current session and clear auth cookies.

**Request:** No body. Reads `refresh_token` cookie automatically.

**Success `200`:**
```json
{ "success": true }
```

**Clears cookies:** `access_token`, `refresh_token`

---

#### `POST /auth/invite/accept`

Accept an invite token. If the user doesn't exist, creates their account (password required). If the user exists but their membership was deactivated, it is reactivated with the invite's role.

**Rate limit:** 5 requests / 60s per IP

**Request body:**
```json
{
  "token": "invite-uuid-token",
  "password": "required-only-for-new-accounts"
}
```

**Success `200`:**
```json
{
  "success": true,
  "user": { "id": "uuid", "email": "user@example.com" },
  "org_id": "uuid"
}
```

**Sets cookies:** `access_token` (15 min), `refresh_token` (30 days)

**Errors:**
- `400` — missing token, password required for new account
- `404` — invalid invite token
- `410` — invite already accepted or expired

---

#### `GET /.well-known/jwks.json`

Public key set for verifying access tokens in downstream services. Cached for 1 hour.

**Success `200`:**
```json
{
  "keys": [
    {
      "kty": "RSA",
      "kid": "key-1",
      "alg": "RS256",
      "use": "sig",
      "n": "...",
      "e": "AQAB"
    }
  ]
}
```

---

#### `GET /health`

Health check.

**Success `200`:**
```json
{ "status": "ok" }
```

---

### Authenticated Endpoints

These require a valid access token. Pass it as:
- `Authorization: Bearer <token>` header, **or**
- `access_token` cookie (set automatically after login/signup)

Returns `401` if the token is missing, invalid, or expired.

---

#### `GET /auth/validate-session`

Verify the current access token and return its payload.

**Success `200`:**
```json
{
  "sub": "user-uuid",
  "email": "user@example.com",
  "org_id": "org-uuid",
  "role": "owner"
}
```

---

#### `GET /auth/orgs`

List all active organizations the authenticated user belongs to.

**Success `200`:**
```json
{
  "organizations": [
    {
      "org_id": "uuid",
      "role": "owner",
      "name": "Acme Corp",
      "slug": "acme-corp",
      "is_active": true
    },
    {
      "org_id": "uuid",
      "role": "member",
      "name": "Other Org",
      "slug": "other-org",
      "is_active": false
    }
  ]
}
```

`is_active` is `true` for the org currently encoded in the access token.

---

#### `POST /auth/switch-org`

Switch the active organization. Revokes the current session and issues new tokens scoped to the target org. The user must have an active membership in the target org.

**Request body:**
```json
{ "org_id": "target-org-uuid" }
```

**Success `200`:**
```json
{
  "success": true,
  "org_id": "target-org-uuid",
  "role": "member"
}
```

**Sets cookies:** new `access_token`, new `refresh_token`

**Errors:**
- `400` — missing org_id
- `403` — not an active member of the target org

---

#### `POST /auth/invite`

Create an invite for a user to join the current organization. Only `owner` and `admin` roles can invite. Assignable roles are `admin` and `member` only — `owner` cannot be assigned via invite.

**Rate limit:** 5 requests / 60s per IP

**Request body:**
```json
{
  "email": "newuser@example.com",
  "org_id": "your-current-org-uuid",
  "role": "member"
}
```

**Success `201`:**
```json
{
  "invite_id": "uuid",
  "token": "uuid-token",
  "email": "newuser@example.com",
  "expires_at": "2026-04-18T..."
}
```

The `token` should be sent to the invitee (e.g., via email link). It expires in 7 days.

**Errors:**
- `400` — missing fields, invalid email, invalid role
- `403` — insufficient role, or inviting to a different org than your active one
- `409` — user is already an active member, or a pending invite already exists

---

## Database Schema

Tables in the live Supabase database (all have RLS enabled):

| Table | Purpose |
|-------|---------|
| `users` | Accounts — email, bcrypt password hash, blocked flag, last login |
| `organizations` | Tenants — name, unique slug, metadata |
| `memberships` | User ↔ org mapping — role (owner/admin/member), status (active/inactive) |
| `sessions` | Refresh token store — hashed token, org scope, rotation chain, device info |
| `invites` | Pending invitations — token, expiry, accepted timestamp |
| `audit_logs` | Immutable event log — action, user, org, IP, user agent |
| `oauth_accounts` | OAuth provider links (reserved for future use) |

### Database Functions

| Function | Description |
|----------|-------------|
| `signup_user(p_email, p_password_hash, p_org_name, p_org_slug)` | Atomic user + org + membership creation in one transaction. Handles slug collisions automatically. |
| `cleanup_expired_sessions()` | Deletes revoked and expired sessions. Call periodically via pg_cron or a scheduled Worker. |
| `set_updated_at()` | Trigger function that keeps `users.updated_at` current. |

---

## Setup

### 1. Install dependencies

```bash
npm install
```

### 2. Apply database schema

Run `scripts/schema.sql` in your Supabase SQL Editor (Dashboard → SQL Editor → New Query → paste and run). This creates all tables, indexes, functions, triggers, and enables RLS. Safe to run on an existing database — uses `IF NOT EXISTS` and `CREATE OR REPLACE`.

### 3. Generate RS256 key pair

```bash
npm run generate-keys
# Outputs: private.pem (keep secret), public.pem (safe to share)
```

### 4. Create KV namespace

```bash
wrangler kv namespace create RATE_LIMIT_KV
# Copy the returned ID into wrangler.toml → [[kv_namespaces]] id
```

### 5. Set secrets

```bash
cat private.pem | wrangler secret put JWT_PRIVATE_KEY
cat public.pem  | wrangler secret put JWT_PUBLIC_KEY
echo "key-1"    | wrangler secret put JWT_KID
wrangler secret put SUPABASE_SERVICE_ROLE_KEY
# Paste your Supabase service role key when prompted
```

### 6. Configure `wrangler.toml`

```toml
[vars]
SUPABASE_URL    = "https://your-project.supabase.co"
ALLOWED_ORIGINS = "https://yourapp.com,https://admin.yourapp.com"
```

`nodejs_compat` compatibility flag is required for `bcryptjs` to work in Workers.

### 7. Local development

```bash
cp .dev.vars.example .dev.vars
# Fill in real values in .dev.vars
npm run dev
```

### 8. Deploy

```bash
npm run deploy
```

---

## Environment Variables

| Variable | Type | Description |
|----------|------|-------------|
| `SUPABASE_URL` | var | Your Supabase project URL |
| `ALLOWED_ORIGINS` | var | Comma-separated list of allowed CORS origins |
| `SUPABASE_SERVICE_ROLE_KEY` | secret | Supabase service role key — bypasses RLS |
| `JWT_PRIVATE_KEY` | secret | PEM-encoded RS256 private key for signing tokens |
| `JWT_PUBLIC_KEY` | secret | PEM-encoded RS256 public key for verifying tokens |
| `JWT_KID` | secret | Key ID included in JWT header and JWKS (e.g. `key-1`) |
| `RATE_LIMIT_KV` | KV binding | Cloudflare KV namespace for rate limiting and account lockout |

---

## Security Design

### Authentication
- **RS256 asymmetric JWTs** — private key signs, public key verifies. Downstream services verify independently via JWKS without sharing any secret.
- **Module-level key cache** — PEM keys are parsed once per isolate lifetime, not on every request.
- **Access token TTL: 15 minutes** — short-lived to limit blast radius of token theft.

### Session Management
- **Refresh tokens are never stored in plaintext** — SHA-256 hashed before writing to DB.
- **Rotation on every use** — each refresh call revokes the old token and issues a new one.
- **Theft detection** — if a revoked refresh token is presented, all sessions for that user are immediately revoked and an audit event is written.
- **Rotation chain** — `sessions.rotated_from` links each session to its predecessor for forensic tracing.
- **`last_used_at` tracking** — updated on every refresh.

### Rate Limiting
- **Per-IP fixed-window limiter** — implemented in Cloudflare KV. Limits per route:
  - `/auth/login` — 5 req / 60s
  - `/auth/signup` — 3 req / 60s
  - `/auth/refresh` — 10 req / 60s
  - `/auth/invite` — 5 req / 60s
  - `/auth/invite/accept` — 5 req / 60s
- **Per-email account lockout** — 10 failed login attempts triggers a 15-minute lockout. Tracks by email (not IP) to block distributed brute-force. Counter resets on successful login.
- **Retry-After header** included on all 429 responses.

### Timing Attack Prevention
- Login always runs `bcrypt.compare` even when the user doesn't exist (dummy hash at cost 12). Prevents email enumeration via response time differences.

### Input Validation
- Email: regex format check on all inputs
- Password: minimum 8 characters, maximum 72 characters (bcrypt silently truncates at 72 bytes — enforced to prevent unexpected behavior)

### CORS & CSRF
- **CORS** — only origins listed in `ALLOWED_ORIGINS` receive CORS headers. Credentials are allowed.
- **CSRF** — `Origin` header is validated on all POST requests. Requests without an `Origin` header (non-browser clients) are allowed through.

### Cookies
- `HttpOnly` — not accessible to JavaScript
- `Secure` — HTTPS only
- `SameSite=None` — required for cross-origin cookie sending (paired with CORS credentials)
- Cookie attributes on `clearCookies` match `setAuthCookies` exactly — browsers require this to reliably clear cookies.

### Data Protection
- Internal error messages are never returned to clients — all 500 responses return a generic message.
- Supabase service role key is a Cloudflare secret — never in `wrangler.toml` or source code.
- RLS is enabled on all tables — direct client access is blocked even if the anon key leaks.

### Invite Security
- Invite tokens are UUIDs (128-bit entropy) — brute-force is computationally infeasible.
- Role escalation is blocked — invites can only assign `admin` or `member`, never `owner`.
- Invites expire after 7 days.
- `accepted_at` timestamp is recorded when an invite is accepted.
- Re-inviting a deactivated member reactivates their membership with the new role.

### Audit Logging
All security-relevant events are written to `audit_logs` with user ID, org ID, IP address, user agent, and structured metadata. Writes are non-blocking via `ctx.waitUntil()` — they never delay the response.

| Event | Trigger |
|-------|---------|
| `signup` | New account created |
| `login` | Successful login |
| `login_failed` | Wrong password or unknown email |
| `logout` | Session revoked |
| `refresh` | Token rotated |
| `refresh_theft_detected` | Revoked token reused |
| `switch_org` | Active org changed |
| `invite_created` | Invite sent |
| `invite_accepted` | Invite accepted |

---

## Reliability

- **AbortController timeout on all DB calls** — 10-second timeout (`DB_TIMEOUT_MS`). Supabase hangs won't block the Worker indefinitely.
- **Non-blocking audit writes** — `ctx.waitUntil()` defers audit DB writes until after the response is sent.
- **Non-blocking side effects** — `last_login_at` update and lockout counter clear also use `ctx.waitUntil()`.
- **Transactional signup** — `signup_user()` PostgreSQL function wraps user + org + membership in a single transaction. No orphaned rows on partial failure.
- **Structured JSON logging** — every request logs `{ rid, method, path, status, ms }`. Errors include `error` and `stack`. Use `rid` (request ID) to correlate client errors with server logs.
- **`X-Request-ID` response header** — the same UUID is returned to the client for support tracing.

---

## Token Verification (Downstream Services)

Any service can verify access tokens without contacting the SSO API:

```typescript
import { createRemoteJWKSet, jwtVerify } from "jose";

const JWKS = createRemoteJWKSet(
  new URL("https://your-sso-worker.workers.dev/.well-known/jwks.json")
);

const { payload } = await jwtVerify(token, JWKS, {
  algorithms: ["RS256"],
  issuer: "sso-api",
});

// payload.sub     — user ID
// payload.email   — user email
// payload.org_id  — active organization ID
// payload.role    — role in active org (owner | admin | member)
```

---

## Constants Reference

Defined in `src/lib/constants.ts`:

| Constant | Value | Description |
|----------|-------|-------------|
| `SESSION_TTL_MS` | 30 days | Refresh token / session lifetime |
| `ACCESS_TOKEN_MAX_AGE` | 900s (15 min) | Access token cookie Max-Age |
| `INVITE_TTL_MS` | 7 days | Invite expiry |
| `DB_TIMEOUT_MS` | 10,000ms | Supabase fetch timeout |
| `ACCOUNT_LOCKOUT_THRESHOLD` | 10 | Failed logins before lockout |
| `ACCOUNT_LOCKOUT_WINDOW` | 900s (15 min) | Lockout duration |

---

## Known Limitations

- **KV rate limiting is not atomic** — under extreme concurrency, a few extra requests may slip through the per-IP limiter or lockout counter. For strict guarantees, replace with Cloudflare Durable Objects.
- **No email verification flow** — `users.is_email_verified` is stored but no verification endpoint exists yet.
- **No password reset flow** — no forgot-password / reset-password mechanism yet.
- **No session listing endpoint** — users cannot view or selectively revoke individual sessions.
- **No invite cancellation endpoint** — invites can only expire or be accepted.
- **No OAuth implementation** — `oauth_accounts` table exists in the DB but is not yet wired up.
