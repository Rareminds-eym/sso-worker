# SSO API

Production-grade Single Sign-On API built on Cloudflare Workers, backed by Supabase (PostgreSQL). RS256 JWTs, stateful session rotation, multi-tenant organizations, invite flows, email verification, and edge-native rate limiting.

---

## Architecture

```
Client Apps (auth-client SDK)
    │
    ▼
Cloudflare Worker  (sso-api)
    │
    ├── Supabase PostgreSQL  (auth DB via service-role key)
    ├── Cloudflare KV        (rate limiting + account lockout)
    └── /.well-known/jwks.json  (public key — consumed by auth-core SDK)
```

Token strategy:
- **Access token** — RS256 JWT, 15-minute TTL, signed with private key, verified by any service via JWKS
- **Refresh token** — random UUID pair, SHA-256 hashed before DB storage, 30-day TTL, rotated on every use

JWT claims: `sub`, `email`, `org_id`, `roles`, `products`, `membership_status`, `is_email_verified`, `iss` (`sso-api`), `aud` (`sso-client`)

---

## API Reference

All responses are `Content-Type: application/json`. Errors: `{ "error": "message" }`. Every response includes `X-Request-ID` (UUID).

### Public Endpoints

| Method | Path | Description | Rate Limit |
|--------|------|-------------|------------|
| `POST` | `/auth/signup` | Create user + org | 3/60s |
| `POST` | `/auth/login` | Authenticate | 5/60s |
| `POST` | `/auth/refresh` | Rotate tokens | 10/60s |
| `POST` | `/auth/logout` | Revoke session | — |
| `POST` | `/auth/invite/accept` | Accept invite | 5/60s |
| `POST` | `/auth/verify-email` | Verify email token | 5/60s |
| `GET`  | `/.well-known/jwks.json` | Public key set | — |
| `GET`  | `/health` | Health check | — |

### Authenticated Endpoints

Require `Authorization: Bearer <token>` header or `access_token` cookie.

| Method | Path | Description | Rate Limit |
|--------|------|-------------|------------|
| `GET`  | `/auth/me` | Current user identity | — |
| `GET`  | `/auth/orgs` | List user's orgs | — |
| `POST` | `/auth/switch-org` | Switch active org | — |
| `POST` | `/auth/invite` | Create invite (owner/admin) | 5/60s |
| `POST` | `/auth/request-verification` | Request email verification | 3/60s |

---

### `POST /auth/signup`

```json
// Request
{ "email": "user@example.com", "password": "min8chars", "org_name": "Acme Corp" }

// Response 201
{
  "access_token": "eyJ...",
  "user": { "id": "uuid", "email": "user@example.com" },
  "org": { "id": "uuid", "name": "Acme Corp", "slug": "acme-corp" }
}
```
Sets cookies: `access_token` (15 min), `refresh_token` (30 days). Errors: `400`, `409`.

### `POST /auth/login`

```json
// Request
{ "email": "user@example.com", "password": "yourpassword" }

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

Accepts refresh token from cookie or body. Revokes session, clears cookies.

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
{ "token": "invite-uuid", "password": "required-for-new-users" }

// Response 200
{ "access_token": "eyJ...", "user": { "id": "uuid", "email": "..." }, "org_id": "uuid" }
```
Creates user if needed. Reactivates deactivated memberships. Sets cookies. Errors: `400`, `404`, `410`.

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
| `audit_logs` | Immutable event log — action, user, org, IP, user agent |
| `oauth_accounts` | Reserved for future OAuth provider support |

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
wrangler kv namespace create RATE_LIMIT_KV     # 4. Create KV (copy ID to wrangler.toml)
cat private.pem | wrangler secret put JWT_PRIVATE_KEY  # 5. Set secrets
cat public.pem  | wrangler secret put JWT_PUBLIC_KEY
echo "key-1"    | wrangler secret put JWT_KID
wrangler secret put SUPABASE_SERVICE_ROLE_KEY
npm run deploy                                 # 6. Deploy
```

Configure `wrangler.toml`:
```toml
[vars]
SUPABASE_URL    = "https://your-project.supabase.co"
ALLOWED_ORIGINS = "https://yourapp.com,https://admin.yourapp.com"
```

`nodejs_compat` flag is required for `bcryptjs`.

---

## Environment Variables

| Variable | Type | Description |
|----------|------|-------------|
| `SUPABASE_URL` | var | Supabase project URL |
| `ALLOWED_ORIGINS` | var | Comma-separated CORS origins |
| `SUPABASE_SERVICE_ROLE_KEY` | secret | Supabase service role key (bypasses RLS) |
| `JWT_PRIVATE_KEY` | secret | PEM-encoded RS256 private key |
| `JWT_PUBLIC_KEY` | secret | PEM-encoded RS256 public key |
| `JWT_KID` | secret | Key ID for JWT header and JWKS (e.g. `key-1`) |
| `RATE_LIMIT_KV` | KV binding | Cloudflare KV for rate limiting |

---

## Security

- **RS256 asymmetric JWTs** with `iss` and `aud` claims enforced
- **Refresh tokens SHA-256 hashed** before DB storage, rotated on every use
- **Theft detection** — revoked token reuse revokes ALL user sessions
- **Per-IP rate limiting** + per-email account lockout (10 failures → 15 min lock)
- **Constant-time login** — bcrypt compare runs even for non-existent users
- **HttpOnly/Secure/SameSite=None cookies** — not accessible to JavaScript
- **CORS** with origin allowlist + **CSRF** origin validation on POST
- **RLS enabled** on all tables — direct client access blocked
- **Non-blocking audit logging** via `ctx.waitUntil()`
- **CORS `Access-Control-Expose-Headers`** — exposes `X-Access-Token` and `X-Request-ID` to browser JS
- **Input validation** — email regex, password 8–72 chars (bcrypt truncation guard)
- **Timing attack prevention** — login always runs bcrypt compare even for non-existent users (dummy hash at cost 12)

### Audit Events

`signup`, `login`, `login_failed`, `logout`, `refresh`, `refresh_theft_detected`, `switch_org`, `invite_created`, `invite_accepted`, `verification_requested`, `email_verified`

---

## Constants

| Constant | Value | Description |
|----------|-------|-------------|
| `SESSION_TTL_MS` | 30 days | Refresh token lifetime |
| `ACCESS_TOKEN_MAX_AGE` | 900s (15 min) | Access token cookie Max-Age |
| `INVITE_TTL_MS` | 7 days | Invite expiry |
| `DB_TIMEOUT_MS` | 10,000ms | Supabase fetch timeout |
| `ACCOUNT_LOCKOUT_THRESHOLD` | 10 | Failed logins before lockout |
| `ACCOUNT_LOCKOUT_WINDOW` | 900s (15 min) | Lockout duration |
| `JWT_ISSUER` | `"sso-api"` | JWT issuer claim |
| `JWT_AUDIENCE` | `"sso-client"` | JWT audience claim |

---

## Known Limitations

- **KV rate limiting is not atomic** — under extreme concurrency, limits can be slightly exceeded. Use Durable Objects for strict guarantees.
- **No password reset flow** — no forgot-password mechanism yet.
- **No session listing endpoint** — users cannot view or selectively revoke individual sessions.
- **No invite cancellation** — invites can only expire or be accepted.
- **No OAuth** — `oauth_accounts` table exists but is not wired up.

---

## Project Structure

```
sso-worker/
├── src/
│   ├── index.ts              # Router, CORS, CSRF, rate limiting, structured logging
│   ├── types.ts              # Env, route types, JWT payload, DB models, request bodies
│   ├── lib/
│   │   ├── constants.ts      # TTLs, thresholds, timeouts, JWT issuer/audience
│   │   ├── db.ts             # PostgREST client with AbortController timeout
│   │   ├── jwt.ts            # RS256 sign/verify + JWKS export via Web Crypto
│   │   ├── hash.ts           # bcrypt passwords, SHA-256 token hashing
│   │   ├── cookies.ts        # HttpOnly/Secure/SameSite=None cookie management
│   │   ├── rate-limit.ts     # Per-IP limiter + per-email account lockout
│   │   ├── auth.ts           # Token extraction (header → cookie) + verification
│   │   ├── audit.ts          # Non-blocking audit log via ctx.waitUntil()
│   │   ├── validate.ts       # Email + password validation
│   │   └── response.ts       # json() and error() helpers
│   └── routes/
│       ├── signup.ts          ├── login.ts           ├── refresh.ts
│       ├── logout.ts          ├── me.ts              ├── switch-org.ts
│       ├── invite.ts          ├── orgs.ts            ├── jwks.ts
│       └── verify-email.ts
├── scripts/
│   ├── schema.sql            # Full DB schema
│   └── generate-keys.mjs     # RS256 key pair generator
├── wrangler.toml
└── package.json
```

## License

UNLICENSED — private.
