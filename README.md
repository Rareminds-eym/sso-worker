# SSO API — Cloudflare Workers + Supabase

Production-grade SSO system with RS256 JWTs, session-based refresh rotation, multi-tenant org support, and edge-native rate limiting.

## Architecture

```
Client Apps → Cloudflare Worker (SSO API) → Supabase (Auth DB)
                    ↓
              JWKS endpoint (public key verification)
```

## Endpoints

| Method | Path                        | Auth | Description                    |
|--------|-----------------------------|------|--------------------------------|
| POST   | `/auth/signup`              | No   | Register user + create org     |
| POST   | `/auth/login`               | No   | Authenticate, get tokens       |
| POST   | `/auth/refresh`             | No   | Rotate refresh token           |
| POST   | `/auth/logout`              | No   | Revoke session, clear cookies  |
| GET    | `/auth/validate-session`    | Yes  | Verify access token            |
| GET    | `/auth/orgs`                | Yes  | List user's organizations      |
| POST   | `/auth/switch-org`          | Yes  | Switch active organization     |
| POST   | `/auth/invite`              | Yes  | Create org invite (admin+)     |
| POST   | `/auth/invite/accept`       | No   | Accept invite, join org        |
| GET    | `/.well-known/jwks.json`    | No   | Public key set for JWT verify  |
| GET    | `/health`                   | No   | Health check                   |

## Setup

### 1. Database
Run `scripts/schema.sql` in your Supabase SQL Editor.

### 2. Generate RS256 Keys
```bash
npm run generate-keys
```

### 3. Configure Secrets
```bash
wrangler secret put SUPABASE_SERVICE_ROLE_KEY
cat private.pem | wrangler secret put JWT_PRIVATE_KEY
cat public.pem  | wrangler secret put JWT_PUBLIC_KEY
echo "key-1"    | wrangler secret put JWT_KID
```

### 4. Create KV Namespace
```bash
wrangler kv namespace create RATE_LIMIT_KV
# Update the id in wrangler.toml with the returned ID
```

### 5. Update `wrangler.toml`
Set your `SUPABASE_URL` and `ALLOWED_ORIGINS`.

### 6. Deploy
```bash
npm run deploy
```

## Security Features

- RS256 JWT with cached key import, JWKS endpoint for external verification
- Refresh token rotation with SHA-256 hashing and theft detection (nuclear revocation)
- Constant-time login (dummy bcrypt on user-not-found prevents email enumeration)
- Per-IP rate limiting + per-account lockout (distributed brute-force protection)
- HttpOnly / Secure / SameSite=None cookies, never exposed to JS
- CSRF protection via Origin header validation on state-changing requests
- Invite role escalation blocked (no "owner" assignment via invite)
- RLS enabled on all Supabase tables, only service-role key bypasses
- CORS with explicit origin allowlist and credentials support
- Transactional signup via Supabase RPC (no orphaned rows on failure)
- Structured JSON logging with request ID correlation
- Non-blocking audit log via `ctx.waitUntil()`
- AbortController timeout on all Supabase fetch calls
- Internal error messages never leaked to clients
