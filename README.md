# SSO API

Production-grade Single Sign-On API built on Cloudflare Workers, backed by Supabase (PostgreSQL). RS256 JWTs with key rotation, stateful session rotation, multi-tenant organizations, invite management, email verification, password reset, OAuth placeholders, and edge-native rate limiting.

---

## Architecture

```
Client Apps (auth-client SDK)
    │
    ▼
Cloudflare Worker  (sso-api)
    │
    ├── Supabase PostgreSQL  (auth DB via service-role key)
    ├── In-Memory Map        (rate limiting per-worker instance)
    └── /.well-known/jwks.json  (public key set — consumed by auth-core SDK)
```

Token strategy:
- **Access token** — RS256 JWT, 15-minute TTL, signed with private key, verified by any service via JWKS
- **Refresh token** — random UUID pair, SHA-256 hashed before DB storage, 30-day TTL, rotated on every use

JWT claims: `sub`, `email`, `org_id`, `roles`, `products`, `membership_status`, `is_email_verified`, `iss` (`sso-api`), `aud` (`sso-client`)

---

## API Reference

All responses are `Content-Type: application/json`. Errors: `{ "error": "message" }`. Every response includes `X-Request-ID` (UUID). Request body limit: 10 KB.

### Public Endpoints

| Method | Path | Description | Rate Limit |
|--------|------|-------------|------------|
| `POST` | `/auth/signup` | Create user + org | 5/hour |
| `POST` | `/auth/signup-member` | Create user (no org) | 5/hour |
| `POST` | `/auth/login` | Authenticate | 10/min |
| `POST` | `/auth/refresh` | Rotate tokens | 30/min |
| `POST` | `/auth/logout` | Revoke session | 20/min |
| `POST` | `/auth/invite/accept` | Accept invite | — |
| `POST` | `/auth/verify-email` | Verify email token | 10/hour |
| `POST` | `/auth/forgot-password` | Request password reset | 3/hour |
| `POST` | `/auth/reset-password` | Reset password with token | 5/hour |
| `GET`  | `/auth/oauth/google` | Google OAuth (placeholder) | — |
| `GET`  | `/auth/oauth/github` | GitHub OAuth (placeholder) | — |
| `GET`  | `/.well-known/jwks.json` | Public key set (supports rotation) | No limit |
| `GET`  | `/health` | Health check | No limit |

### Authenticated Endpoints

Require `Authorization: Bearer <token>` header or `access_token` cookie.

| Method | Path | Description | Rate Limit |
|--------|------|-------------|------------|
| `GET`  | `/auth/me` | Current user identity | 60/min |
| `GET`  | `/auth/orgs` | List user's orgs | — |
| `POST` | `/auth/switch-org` | Switch active org | — |
| `POST` | `/auth/invite` | Create invite (owner/admin) | — |
| `POST` | `/auth/invite/cancel` | Cancel pending invite | — |
| `POST` | `/auth/invite/resend` | Resend invite with new token | 3/hour |
| `POST` | `/auth/request-verification` | Request email verification | 3/hour |

---

### `POST /auth/signup`

```json
// Request
{ "email": "user@example.com", "password": "ValidPass123!", "org_name": "Acme Corp" }

// Response 201
{
  "access_token": "eyJ...",
  "user": { "id": "uuid", "email": "user@example.com" },
  "org": { "id": "uuid", "name": "Acme Corp", "slug": "acme-corp" },
  "email_sent": true
}
```
Sets cookies: `access_token` (15 min), `refresh_token` (30 days). Errors: `400`, `409`, `500`.

**Idempotency**: If a user exists but email is NOT verified, the endpoint allows re-signup by cleaning up the incomplete signup data (deletes user, which cascades to sessions, memberships, email_verifications) and creating a new user. This handles cases where:
- User signed up but never verified email
- Session/org creation failed after user creation
- User wants to retry signup with a different organization name

If the user exists and email IS verified, returns `409` with message: "An account with this email already exists. Please log in."

**Rollback**: If any step fails after user creation (session creation, JWT signing, email verification setup), the user and organization are automatically deleted from the database to maintain consistency.

### `POST /auth/signup-member`

```json
// Request
{ "email": "user@example.com", "password": "ValidPass123!", "role": "learner", "org_id": "optional-org-uuid" }

// Response 201
{
  "access_token": "eyJ...",
  "user": { "id": "uuid", "email": "user@example.com" },
  "org": { "id": "uuid" },
  "email_sent": true
}
```
Creates a user without creating an organization. Optionally joins an existing org with the specified role. Used by learners, educators, recruiters who self-register. Sets cookies: `access_token` (15 min), `refresh_token` (30 days). Errors: `400`, `404`, `409`, `500`.

**Idempotency**: Same behavior as `/auth/signup` - if a user exists but email is NOT verified, the endpoint allows re-signup by cleaning up the incomplete signup data and creating a new user. If the user exists and email IS verified, returns `409` with message: "An account with this email already exists. Please log in."

**Rollback**: If any step fails after user creation (session creation, JWT signing, email verification setup), the user is automatically deleted from the database to maintain consistency.

### `POST /auth/login`

```json
// Request
{ "email": "user@example.com", "password": "SecurePass123!" }

// Response 200
{
  "access_token": "eyJ...",
  "user": { "id": "uuid", "email": "user@example.com" },
  "active_org_id": "uuid",
  "organizations": [{ "org_id": "uuid" }]
}
```
Sets cookies. Account lockout after 10 failed attempts (15 min). Constant-time response prevents email enumeration. Errors: `400`, `401`, `403`, `429`.

### `POST /auth/refresh`

Accepts refresh token from cookie or body `{ "refresh_token": "..." }`.

```json
// Response 200
{ "access_token": "eyJ..." }
```
Sets rotated cookies. Theft detection: reusing a revoked token revokes ALL user sessions. Errors: `401`.

### `POST /auth/logout`

Accepts refresh token from cookie or body. Revokes session, clears cookies. Audit log includes user_id from the session.

```json
// Response 200
{ "success": true }
```

### `GET /auth/me`

```json
// Response 200
{
  "sub": "uuid", "email": "user@example.com", "org_id": "uuid",
  "roles": ["owner"], "products": [], "membership_status": "active",
  "is_email_verified": true
}
```

### `GET /auth/orgs`

```json
// Response 200
{
  "organizations": [{
    "org_id": "uuid", "roles": ["owner"], "name": "Acme Corp",
    "slug": "acme-corp", "is_active": true
  }]
}
```

### `POST /auth/switch-org`

```json
// Request
{ "org_id": "target-org-uuid" }

// Response 200
{ "access_token": "eyJ...", "org_id": "uuid", "roles": ["admin"] }
```
Sets rotated cookies. Errors: `400`, `403`, `500`.

### `POST /auth/invite`

Requires `owner` or `admin` role. Assignable roles: `admin`, `member`.

```json
// Request
{ "email": "new@example.com", "org_id": "your-org-uuid", "role": ["member"] }

// Response 201
{ "invite_id": "uuid", "token": "uuid", "email": "new@example.com", "expires_at": "..." }
```
Expires in 7 days. Errors: `400`, `403`, `409`.

### `POST /auth/invite/accept`

```json
// Request
{ "token": "invite-uuid", "password": "NewUser123!" }

// Response 200
{ "access_token": "eyJ...", "user": { "id": "uuid", "email": "..." }, "org_id": "uuid" }
```
Creates user if needed. Reactivates deactivated memberships. Sets cookies. Errors: `400`, `404`, `410`.

### `POST /auth/invite/cancel`

Authenticated. Owner/admin or original inviter can cancel.

```json
// Request
{ "invite_id": "uuid" }

// Response 200
{ "cancelled": true }
```
Errors: `400`, `403`, `404`, `409` (already accepted).

### `POST /auth/invite/resend`

Authenticated. Owner/admin only. Generates new token and extends expiry.

```json
// Request
{ "invite_id": "uuid" }

// Response 200
{ "invite_id": "uuid", "token": "new-uuid", "email": "...", "expires_at": "..." }
```
Errors: `400`, `403`, `404`, `409` (already accepted).

### `POST /auth/request-verification`

Authenticated. Returns a token to deliver via email.

```json
// Response 201
{ "verification_token": "uuid", "expires_at": "..." }
```
Token expires in 24 hours. Returns `{ "already_verified": true }` if already verified.

### `POST /auth/verify-email`

```json
// Request
{ "token": "verification-uuid" }

// Response 200
{ "verified": true }
```
Errors: `400`, `404`, `410` (expired/used).

### `POST /auth/forgot-password`

Always returns 200 to prevent email enumeration. Invalidates previous unused reset tokens.

```json
// Request
{ "email": "user@example.com" }

// Response 200
{ "reset_token": "uuid", "expires_at": "..." }
```
Token expires in 1 hour. If email doesn't exist: `{ "message": "If an account exists, a reset token has been generated." }`.

### `POST /auth/reset-password`

Resets password and revokes ALL sessions (forces re-login everywhere).

```json
// Request
{ "token": "reset-uuid", "password": "NewSecure123!" }

// Response 200
{ "reset": true }
```
Errors: `400`, `404`, `410` (expired/used).

### OAuth Endpoints (Placeholder)

`GET /auth/oauth/google`, `/auth/oauth/github`, and their `/callback` routes return `501 Not Configured` until a provider is wired up. The `oauth_accounts` table is ready in the schema.

---

## Database Schema

| Table | Purpose |
|-------|---------|
| `users` | Accounts — email, bcrypt hash, blocked flag, email verified, last login |
| `organizations` | Tenants — name, unique slug, metadata |
| `memberships` | User ↔ org — status (`active`/`inactive`/`suspended`/`expired`) |
| `membership_roles` | Many-to-many roles per membership |
| `roles` | Lookup — `owner`, `admin`, `member` |
| `products` | Lookup — product codes |
| `organization_products` | Org-level product subscriptions |
| `membership_products` | Per-user product access |
| `sessions` | Refresh tokens — hashed, rotation chain, device info |
| `invites` | Pending invitations — token, expiry, roles |
| `email_verifications` | Verification tokens — used flag, expiry |
| `password_resets` | Reset tokens — used flag, 1h expiry |
| `audit_logs` | Immutable event log — action, user, org, IP, user agent |
| `oauth_accounts` | OAuth provider links (reserved for future use) |

All tables have RLS enabled with explicit deny-all policies for the `anon` role. The worker uses the `service_role` key which bypasses RLS.

### Database Functions

| Function | Description |
|----------|-------------|
| `signup_user()` | Atomic user + org + membership + owner role in one transaction |
| `get_jwt_claims()` | Single-query RBAC claims (roles, products, membership status) |
| `cleanup_expired_sessions()` | Deletes revoked/expired sessions (call via pg_cron) |

---

## Setup

```bash
npm install                                    # 1. Install deps
# Run scripts/schema.sql in Supabase SQL Editor # 2. Apply schema
npm run generate-keys                          # 3. Generate RS256 keys
cat private.pem | wrangler secret put JWT_PRIVATE_KEY  # 4. Set secrets
cat public.pem  | wrangler secret put JWT_PUBLIC_KEY
echo "key-1"    | wrangler secret put JWT_KID
wrangler secret put SUPABASE_SERVICE_ROLE_KEY
npm run deploy                                 # 5. Deploy
```

Configure `wrangler.toml`:
```toml
[vars]
SUPABASE_URL    = "https://your-project.supabase.co"
ALLOWED_ORIGINS = "https://yourapp.com,https://admin.yourapp.com"
APP_URL         = "https://yourapp.com"
```

`nodejs_compat` flag is required for `bcryptjs`.

---

## Environment Variables

| Variable | Type | Description |
|----------|------|-------------|
| `SUPABASE_URL` | var | Supabase project URL |
| `ALLOWED_ORIGINS` | var | Comma-separated CORS origins |
| `APP_URL` | var | Base URL for email links (optional) |
| `SUPABASE_SERVICE_ROLE_KEY` | secret | Supabase service role key (bypasses RLS) |
| `JWT_PRIVATE_KEY` | secret | PEM-encoded RS256 private key |
| `JWT_PUBLIC_KEY` | secret | PEM-encoded RS256 public key |
| `JWT_KID` | secret | Key ID for JWT header and JWKS (e.g. `key-1`) |
| `JWT_PUBLIC_KEY_PREVIOUS` | secret | Previous public key PEM (set during key rotation) |
| `JWT_KID_PREVIOUS` | secret | Previous key ID (set during key rotation) |

---

## Key Rotation

The JWKS endpoint serves multiple keys during rotation so tokens signed with the old key remain verifiable until they expire (15 min).

```bash
# 1. Generate new key pair
node scripts/generate-keys.mjs  # → new private.pem, public.pem

# 2. Copy current keys to "previous" slots
wrangler secret put JWT_PUBLIC_KEY_PREVIOUS  # paste current public key
wrangler secret put JWT_KID_PREVIOUS         # e.g. "key-1"

# 3. Upload new keys as primary
cat private.pem | wrangler secret put JWT_PRIVATE_KEY
cat public.pem  | wrangler secret put JWT_PUBLIC_KEY
echo "key-2"    | wrangler secret put JWT_KID

# 4. Deploy
npm run deploy

# 5. Wait 15+ minutes (old access tokens expire)

# 6. Remove previous keys
wrangler secret delete JWT_PUBLIC_KEY_PREVIOUS
wrangler secret delete JWT_KID_PREVIOUS
npm run deploy
```

---

## Email Delivery

The worker includes a pluggable email module (`src/lib/email.ts`) with template builders for password reset, email verification, and invite emails. Currently logs to console — replace `sendEmail()` with your Amazon SES integration.

Templates: `passwordResetEmail(url)`, `verificationEmail(url)`, `inviteEmail(inviter, orgName, url)`

---

## Security

### Authentication & Authorization

- **RS256 asymmetric JWTs** with `iss` and `aud` claims enforced
- **Key rotation support** — JWKS serves current + previous keys during rotation window
- **Refresh tokens SHA-256 hashed** before DB storage, rotated on every use
- **Theft detection** — revoked token reuse revokes ALL user sessions
- **Password reset** — revokes all sessions on password change (force re-login)

### CSRF Protection: Not Needed

**Why CSRF tokens are not required:**

This API uses **Authorization header authentication** (Bearer tokens), not cookie-based authentication for API requests. CSRF attacks only work when:
1. Authentication credentials are automatically sent by the browser (cookies)
2. The attacker can trick the user's browser into making a request

Since all authenticated API endpoints require the `Authorization: Bearer <token>` header (which browsers don't automatically send), CSRF attacks are not possible.

**What we do instead:**
- **Origin validation** — POST requests must come from allowed origins (CORS security)
- **HttpOnly cookies** — Refresh tokens are in HttpOnly cookies (not accessible to JavaScript)
- **SameSite=None** — Cookies work cross-site but require Secure flag (HTTPS only)

**Note:** The refresh token endpoint (`/auth/refresh`) does use cookies, but it's protected by origin validation and only returns a new access token (doesn't perform state-changing operations based on cookies alone).

### Network Security

- **In-memory rate limiting** — per-IP per-endpoint limits (lenient, per-worker instance)
- **Request body size limit** — 10 KB max on all endpoints
- **Constant-time login** — bcrypt compare runs even for non-existent users (dummy hash at cost 12)
- **Email enumeration prevention** — forgot-password always returns 200
- **HttpOnly/Secure/SameSite=None cookies** — not accessible to JavaScript
- **CORS** with origin allowlist + origin validation on POST (prevents unauthorized domains)
- **CORS `Expose-Headers`** — exposes `X-Access-Token` and `X-Request-ID` to browser JS
- **RLS enabled** on all tables with explicit deny-all policies for `anon` role
- **Input validation** — email regex, password 10–72 chars with complexity (3 of 4: uppercase, lowercase, numbers, special chars)
- **Non-blocking audit logging** via `ctx.waitUntil()`

### Audit Events

`signup`, `login`, `login_failed`, `logout`, `refresh`, `refresh_theft_detected`, `switch_org`, `invite_created`, `invite_accepted`, `invite_cancelled`, `invite_resent`, `verification_requested`, `email_verified`, `password_reset_requested`, `password_reset_completed`

---

## Rate Limiting

The SSO Worker uses **in-memory Map-based rate limiting** (per-worker instance) with lenient limits designed to prevent abuse while allowing legitimate high-frequency usage.

### Implementation Details

- **Per-IP per-endpoint** — Each endpoint has its own rate limit tracked separately
- **Fixed window** — Limits reset after the window expires (e.g., 60 seconds, 3600 seconds)
- **In-memory storage** — Uses JavaScript Map (not KV or Durable Objects)
- **Automatic cleanup** — Expired entries are cleaned every 5 minutes to prevent memory leaks
- **Per-worker instance** — Each worker has its own Map (not global across all workers)

### Rate Limit Headers

When a request is rate limited (429 status), the response includes:

```
Retry-After: 60
X-RateLimit-Limit: 10
X-RateLimit-Remaining: 0
X-RateLimit-Reset: 1715612400000
```

### Endpoint Limits

| Endpoint | Limit | Window | Reasoning |
|----------|-------|--------|-----------|
| `/auth/login` | 10 req | 1 minute | Allow multiple login attempts (typos, password managers) |
| `/auth/signup` | 5 req | 1 hour | Prevent bulk account creation |
| `/auth/forgot-password` | 3 req | 1 hour | Prevent email spam |
| `/auth/reset-password` | 5 req | 1 hour | Allow retries for token issues |
| `/auth/verify-email` | 10 req | 1 hour | Allow retries for verification issues |
| `/auth/request-verification` | 3 req | 1 hour | Prevent email spam |
| `/auth/refresh` | 30 req | 1 minute | High limit for SPAs with multiple tabs |
| `/auth/me` | 60 req | 1 minute | High limit for frequent identity checks |
| `/auth/logout` | 20 req | 1 minute | Allow multiple logout attempts |
| `/health` | No limit | — | Health checks should never be rate limited |
| `/.well-known/jwks.json` | No limit | — | Public key endpoint for JWT verification |

### Production Considerations

**Per-Worker Limitation**: Since rate limiting is per-worker instance, the effective limit under load is `limit × number_of_workers`. For example, with 3 workers, a 10 req/min limit becomes ~30 req/min globally.

**For Strict Global Limits**: Migrate to Cloudflare Durable Objects, which provide single-instance guarantees and atomic operations.

**Monitoring**: Rate limit violations are logged with:
```json
{
  "level": "warn",
  "message": "[rate-limit] login rate limit exceeded for IP 1.2.3.4: 11/10"
}
```

---

## Constants

| Constant | Value | Description |
|----------|-------|-------------|
| `SESSION_TTL_MS` | 30 days | Refresh token lifetime |
| `ACCESS_TOKEN_MAX_AGE` | 900s (15 min) | Access token cookie Max-Age |
| `INVITE_TTL_MS` | 7 days | Invite expiry |
| `DB_TIMEOUT_MS` | 10,000ms | Supabase fetch timeout |
| `JWT_ISSUER` | `"sso-api"` | JWT issuer claim |
| `JWT_AUDIENCE` | `"sso-client"` | JWT audience claim |
| `MAX_BODY_SIZE` | 10,240 bytes | Request body size limit |

**Rate Limit Configurations** (lenient, per-worker instance):
- Login: 10 requests/minute
- Signup: 5 requests/hour
- Forgot password: 3 requests/hour
- Reset password: 5 requests/hour
- Verify email: 10 requests/hour
- Resend verification: 3 requests/hour
- Refresh: 30 requests/minute
- Me: 60 requests/minute
- Logout: 20 requests/minute
- Health check: No limit

---

## Project Structure

```
sso-worker/
├── src/
│   ├── index.ts              # Router, CORS, origin validation, body limit, rate limiting, logging
│   ├── types.ts              # Env, route types, JWT payload, DB models, request bodies
│   ├── lib/
│   │   ├── constants.ts      # TTLs, thresholds, timeouts, JWT issuer/audience
│   │   ├── db.ts             # PostgREST client with AbortController timeout
│   │   ├── jwt.ts            # RS256 sign/verify + JWKS export with rotation support
│   │   ├── hash.ts           # bcrypt passwords, SHA-256 token hashing
│   │   ├── cookies.ts        # HttpOnly/Secure/SameSite=None cookie management
│   │   ├── auth.ts           # Token extraction (header → cookie) + verification
│   │   ├── audit.ts          # Non-blocking audit log via ctx.waitUntil()
│   │   ├── email.ts          # Pluggable email delivery + template builders
│   │   ├── validate.ts       # Email + password validation
│   │   └── response.ts       # json() and error() helpers
│   ├── middleware/
│   │   └── rateLimit.ts      # In-memory Map-based rate limiting (per-worker)
│   └── routes/
│       ├── signup.ts         ├── login.ts            ├── refresh.ts
│       ├── logout.ts         ├── me.ts               ├── switch-org.ts
│       ├── invite.ts         ├── invite-manage.ts    ├── orgs.ts
│       ├── jwks.ts           ├── verify-email.ts     ├── password-reset.ts
│       └── oauth.ts
├── scripts/
│   ├── schema.sql            # Full DB schema with RLS deny-all policies
│   └── generate-keys.mjs     # RS256 key pair generator
├── wrangler.toml
└── package.json
```

## Known Limitations

- **In-memory rate limiting is per-worker** — each worker instance has its own Map. Under load with multiple workers, effective limits are multiplied. For strict global limits, migrate to Durable Objects.
- **No session listing endpoint** — users cannot view or selectively revoke individual sessions.
- **OAuth not implemented** — routes return 501 until a provider is configured.
- **Email delivery is a stub** — `sendEmail()` logs to console. Replace with Amazon SES.

## License

UNLICENSED — private.
