# SSO Authorization Code Implementation Plan

## Goal

Implement the SSO Worker side of the `SkillPassport -> LTE -> Dashboard` flow, with SSO as the only authority for authorization-code storage, JWT issuance, refresh-token sessions, product entitlement checks, and one-time code consumption.

## Final Flow

1. SkillPassport calls SSO `generateAuthorizationCode`.
2. SSO verifies the SkillPassport access token.
3. SSO checks the user has `lte` product entitlement.
4. SSO generates one-time `code` and `state`.
5. SSO stores hashed code and hashed state in Durable Object for 60 seconds.
6. SkillPassport sends browser to LTE with raw `code` and `state`.
7. LTE calls SSO `exchangeAuthorizationCode`.
8. SSO hashes the submitted code and state.
9. SSO loads the matching Durable Object record.
10. SSO verifies expiry, redirect URI, state, target app, user status, email policy, and LTE entitlement.
11. SSO atomically consumes the code.
12. SSO issues LTE access token and LTE refresh token.
13. SSO stores the LTE refresh token hash in SSO session storage.
14. SSO returns LTE user claims, LTE access token, LTE refresh token, and LTE subscription snapshot to LTE backend only.

## SSO Responsibilities

Own one-time authorization-code storage.

Own refresh-token session truth for both SkillPassport and LTE.

Issue product-scoped access tokens.

Validate redirect URI against allowed app URLs.

Validate user status and entitlement before issuing LTE tokens.

Return enough user and subscription data for LTE to sync `users_shadow` and `subscription_cache`.

## Data Ownership

Authorization code record - SSO Durable Object only.

Raw authorization code - Returned once to SkillPassport and submitted once by LTE.

Raw state - Returned once to SkillPassport and submitted once by LTE.

Code hash and state hash - Stored only inside SSO Durable Object.

LTE refresh token hash - Stored only in SSO sessions table.

LTE access token - Created by SSO and returned only to LTE backend.

LTE subscription snapshot - Read from SSO database and returned to LTE backend for cache sync.

## SSO Files To Create

`src/durable-objects/AuthorizationCodeStore.ts` - Durable Object that stores, consumes, and expires one authorization code record.

`src/lib/authorization-code.ts` - Helpers to generate code/state, hash them, build redirect URLs, and resolve Durable Object IDs.

`src/lib/lte-entitlement.ts` - Helper to confirm the user has active LTE product access.

`src/lib/subscription-snapshot.ts` - Helper to build the LTE subscription snapshot returned during exchange.

`src/lib/app-token.ts` - Helper to issue access tokens scoped to target app audience.

`src/types/sso-code.ts` - Typed request and response contracts for authorization-code RPCs.

## SSO Files To Update

`wrangler.toml` - Add `AUTH_CODE_STORE` Durable Object binding and migration.

`src/index.ts` - Export `AuthorizationCodeStore` and add `generateAuthorizationCode` and `exchangeAuthorizationCode` RPC methods.

`src/types.ts` - Add `AUTH_CODE_STORE` to `Env` and add typed SSO RPC payloads if kept in the shared type file.

`src/lib/jwt.ts` - Support target-app scoped LTE access token claims if current signing helper does not accept audience/product scope.

`src/lib/session-rotation.ts` - Store and rotate LTE refresh-token sessions with app context.

`src/lib/db.ts` - Reuse typed database helpers for users, memberships, products, sessions, and subscriptions.

`src/lib/validate.ts` - Validate LTE redirect URI from `ALLOWED_APP_URLS`.

`src/lib/audit.ts` - Add audit events for code generation, exchange success, exchange failure, and token issue.

`src/__tests__/mocks` - Add mock Durable Object namespace and store behavior for SSO tests.

## SSO RPC Methods To Add

`generateAuthorizationCode` - Validates SkillPassport access token and creates a one-time LTE authorization code.

`exchangeAuthorizationCode` - Validates and consumes the one-time code, then returns LTE tokens and claims.

## Durable Object Record

`codeHash` - SHA-256 hash of the raw authorization code.

`stateHash` - SHA-256 hash of the raw state value.

`userId` - SSO user ID.

`targetApp` - Must be `lte`.

`redirectUri` - Exact LTE callback URI.

`expiresAt` - Current time plus short TTL, normally 60 seconds.

`createdAt` - Creation timestamp for audit/debugging.

## Generate Authorization Code Rules

SkillPassport access token must be valid.

User must not be blocked.

Email verification policy must pass.

User membership must be active.

User must have LTE product entitlement.

Redirect URI must be allowlisted.

Code and state must be cryptographically random.

Only hashes are stored in Durable Object.

Raw code and state are returned only once.

## Exchange Authorization Code Rules

Code must exist.

Code must not be expired.

Code must not already be consumed.

Submitted state hash must match stored state hash.

Submitted redirect URI must exactly match stored redirect URI.

Stored target app must be `lte`.

User must still be valid and entitled at exchange time.

Durable Object record must be deleted during successful exchange.

LTE refresh token hash must be stored in SSO session storage.

Refresh token must be returned only to LTE backend, never to browser URL.

## Token Rules

SkillPassport access token - Audience/scope for SkillPassport.

LTE access token - Audience/scope for LTE.

Refresh tokens - Opaque strings, hashed before database storage.

Refresh session rows - Include app context so SkillPassport and LTE sessions can be separated.

Access token TTL - Short, around 15 minutes.

Refresh token TTL - Longer, around 7 days.

## Tables Used By SSO

`users` - Source of user identity, email verification, blocked status, and profile metadata.

`memberships` - Source of organization and membership status.

`roles` and membership-role join table - Source of runtime role claims.

`products` and product entitlement tables - Source of LTE access entitlement.

`sessions` - Source of refresh-token truth for SkillPassport and LTE.

`subscriptions` or sales subscription source - Source for LTE subscription snapshot.

No LTE local table is the source of truth for SSO authorization.

## Implementation Order

1. Add `AUTH_CODE_STORE` Durable Object binding and migration in `wrangler.toml`.
2. Export `AuthorizationCodeStore` from `src/index.ts`.
3. Add `AUTH_CODE_STORE` to SSO `Env`.
4. Add typed authorization-code request and response contracts.
5. Add code/state generation and hashing helpers.
6. Add LTE redirect URI validation through existing app URL allowlist.
7. Add LTE entitlement helper.
8. Add subscription snapshot helper.
9. Add `generateAuthorizationCode` RPC.
10. Add `exchangeAuthorizationCode` RPC.
11. Add LTE app context to refresh-token session creation and rotation.
12. Add audit events.
13. Add unit tests for success, expiry, reuse, state mismatch, redirect mismatch, and missing entitlement.
14. Verify SkillPassport and LTE can call SSO through local service binding.

## Verification Checklist

SSO Worker starts with `AUTH_CODE_STORE` binding.

SkillPassport can call `generateAuthorizationCode`.

User without LTE product does not receive a code.

Code expires after 60 seconds.

Code cannot be reused.

Wrong state fails.

Wrong redirect URI fails.

Exchange returns LTE access token only to LTE backend.

Exchange returns LTE refresh token only to LTE backend.

LTE refresh session is stored in SSO sessions table.

LTE subscription snapshot is returned for LTE cache sync.

Audit events are written for generation and exchange.
