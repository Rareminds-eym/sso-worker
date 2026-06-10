import type { Env, JwtClaims } from "../types";
import { audit } from "./audit";
import {
    ABSOLUTE_SESSION_LIFETIME_MS,
    REUSE_GRACE_INTERVAL_SEC,
    SESSION_TTL_MS,
} from "./constants";
import { db, type DbClient } from "./db";
import { generateRefreshToken, hashToken } from "./hash";
import { signAccessToken } from "./jwt";

/**
 * Shared refresh-token rotation module.
 *
 * Single source of truth for refresh-token rotation, reuse-grace resolution,
 * family-scoped theft detection, absolute-lifetime enforcement, and audit
 * emission. Both the `POST /auth/refresh` HTTP route and the `refreshSession`
 * RPC delegate here so the two entry points cannot diverge in security
 * behavior (Requirement 4).
 *
 * This module is PURE ORCHESTRATION over the existing primitives:
 *   - `db(env)`           — PostgREST client (`rpc`/`queryOne`)
 *   - `hashToken` / `generateRefreshToken` — token hashing + minting
 *   - `signAccessToken`   — access-token (JWT) signing
 *   - `audit`             — non-blocking audit logging
 *   - `RATE_LIMIT_KV`     — grace-window store
 *
 * The atomic single-winner claim and family revocation live in the
 * `rotate_session` / `revoke_token_family` Postgres functions; no raw SQL is
 * implemented here.
 */

// ─── Public types (per design "1. SSO Worker — Shared Rotation Module") ───────

export type RotationOutcome =
    | {
        kind: "rotated";
        accessToken: string;
        refreshToken: string;
        userId: string;
        orgId: string | null;
        familyId: string;
    }
    | {
        kind: "overlap";
        accessToken: string;
        refreshToken: string;
        userId: string;
        orgId: string | null;
        familyId: string;
    }
    | { kind: "theft"; userId: string; familyId: string }
    | { kind: "expired_lifetime"; userId: string; familyId: string }
    | { kind: "invalid" }
    | { kind: "session_expired" };

export interface RotationContext {
    ip: string | null;
    ua: string | null;
}

// ─── RPC result shape ─────────────────────────────────────────────────────────

/** Reason codes returned by the `rotate_session` Postgres function. */
type RotateReason = "ok" | "revoked" | "expired" | "lifetime_exceeded" | "not_found";

/**
 * One row of the `rotate_session` RETURNS TABLE(...) result. PostgREST returns
 * a JSON array for set-returning functions, so the helper reads `rows[0]`.
 */
interface RotateSessionRow {
    claimed: boolean;
    reason: RotateReason;
    new_session_id: string | null;
    user_id: string | null;
    org_id: string | null;
    family_id: string | null;
    expires_at: string | null;
}

// ─── Entry point ───────────────────────────────────────────────────────────────

/**
 * Single shared rotation path. Performs the atomic claim via the
 * `rotate_session` RPC, then resolves the outcome: winner, benign grace
 * overlap, theft, absolute-lifetime expiry, plain expiry, or invalid token.
 *
 * @param env           Worker environment bindings.
 * @param ctx           Execution context (used for non-blocking audit writes).
 * @param presentedToken The opaque refresh token presented by the caller.
 * @param rotationCtx   Originating IP / User-Agent for audit + session metadata.
 */
export async function rotateRefreshToken(
    env: Env,
    ctx: ExecutionContext,
    presentedToken: string,
    rotationCtx: RotationContext,
): Promise<RotationOutcome> {
    const database = db(env);
    const { ip, ua } = rotationCtx;

    // 1. Hash the presented token. The session lookup itself is performed
    //    atomically inside `rotate_session` (FOR UPDATE) and surfaces as
    //    reason='not_found' → { kind: "invalid" }.
    const oldHash = await hashToken(presentedToken);

    // 2. Generate the successor refresh token + hash in the worker; only the
    //    hash is ever sent to the database.
    const newRefreshToken = generateRefreshToken();
    const newRefreshHash = await hashToken(newRefreshToken);

    // 3. Atomic single-winner claim.
    const rows = await database.rpc<RotateSessionRow[]>("rotate_session", {
        p_old_hash: oldHash,
        p_new_hash: newRefreshHash,
        p_new_user_agent: ua,
        p_new_ip: ip,
        p_token_ttl_ms: SESSION_TTL_MS,
        p_absolute_lifetime_ms: ABSOLUTE_SESSION_LIFETIME_MS,
    });

    const row = Array.isArray(rows) ? rows[0] : (rows as RotateSessionRow | undefined);
    if (!row) {
        // Defensive: the function always RETURN QUERYs a row, but treat a missing
        // result as an invalid presentation rather than throwing.
        return { kind: "invalid" };
    }

    // 4. Resolve outcome.
    if (row.claimed) {
        // WINNER. Persist the grace entry BEFORE returning so a concurrent loser
        // presenting the same old token can recover the replacement.
        await env.RATE_LIMIT_KV.put(graceKey(oldHash), newRefreshToken, {
            expirationTtl: REUSE_GRACE_INTERVAL_SEC,
        });

        const accessToken = await mintAccessToken(
            database,
            env,
            row.user_id!,
            row.org_id,
        );

        audit(ctx, env, "refresh", {
            user_id: row.user_id,
            org_id: row.org_id,
            ip_address: ip,
            user_agent: ua,
            metadata: { family_id: row.family_id },
        });

        return {
            kind: "rotated",
            accessToken,
            refreshToken: newRefreshToken,
            userId: row.user_id!,
            orgId: row.org_id,
            familyId: row.family_id!,
        };
    }

    switch (row.reason) {
        case "revoked":
            return resolveRevoked(database, env, ctx, oldHash, row, rotationCtx);

        case "lifetime_exceeded":
            // Distinct from theft — refresh refused because the family is too old.
            audit(ctx, env, "lifetime_expiry", {
                user_id: row.user_id,
                ip_address: ip,
                user_agent: ua,
                metadata: { family_id: row.family_id },
            });
            return {
                kind: "expired_lifetime",
                userId: row.user_id!,
                familyId: row.family_id!,
            };

        case "expired":
            return { kind: "session_expired" };

        case "not_found":
        default:
            return { kind: "invalid" };
    }
}

// ─── Grace / theft resolution ───────────────────────────────────────────────

/**
 * Resolve a lost claim (reason='revoked'): a benign rotation overlap if the
 * grace entry is still present, otherwise theft.
 *
 * FAIL-SAFE: if the grace KV read is unavailable/errors, classify toward THEFT
 * (the secure default) rather than overlap.
 */
async function resolveRevoked(
    database: DbClient,
    env: Env,
    ctx: ExecutionContext,
    oldHash: string,
    row: RotateSessionRow,
    rotationCtx: RotationContext,
): Promise<RotationOutcome> {
    const { ip, ua } = rotationCtx;
    const userId = row.user_id!;
    const familyId = row.family_id!;

    let replacement: string | null = null;
    try {
        replacement = await env.RATE_LIMIT_KV.get(graceKey(oldHash));
    } catch (err) {
        // Secure default: a grace read we cannot trust is treated as theft.
        console.error("[SSO] Grace KV read failed; classifying as theft:", err);
        return revokeFamilyAsTheft(database, env, ctx, familyId, userId, rotationCtx);
    }

    if (replacement) {
        // Benign overlap — return the winner's already-issued replacement token and
        // mint a fresh access token for the family. NEVER theft.
        const orgId = await resolveFamilyOrgId(database, familyId);
        const accessToken = await mintAccessToken(database, env, userId, orgId);

        audit(ctx, env, "rotation_overlap", {
            user_id: userId,
            org_id: orgId,
            ip_address: ip,
            user_agent: ua,
            metadata: { family_id: familyId },
        });

        return {
            kind: "overlap",
            accessToken,
            refreshToken: replacement,
            userId,
            orgId,
            familyId,
        };
    }

    // Grace window elapsed → theft.
    return revokeFamilyAsTheft(database, env, ctx, familyId, userId, rotationCtx);
}

/** Revoke the affected token family and emit a distinct theft audit event. */
async function revokeFamilyAsTheft(
    database: DbClient,
    env: Env,
    ctx: ExecutionContext,
    familyId: string,
    userId: string,
    rotationCtx: RotationContext,
): Promise<RotationOutcome> {
    await database.rpc<number>("revoke_token_family", { p_family_id: familyId });

    audit(ctx, env, "theft_detected", {
        user_id: userId,
        ip_address: rotationCtx.ip,
        user_agent: rotationCtx.ua,
        metadata: { family_id: familyId },
    });

    return { kind: "theft", userId, familyId };
}

// ─── Helpers ───────────────────────────────────────────────────────────────

/** KV key for the grace entry storing a family's just-issued replacement token. */
function graceKey(oldHash: string): string {
    return `grace:${oldHash}`;
}

/**
 * Resolve the org id for a token family from its surviving unrevoked session.
 * The `rotate_session` RPC does not return org_id on the 'revoked' path, so the
 * overlap branch reads it from the family's current live session.
 */
async function resolveFamilyOrgId(
    database: DbClient,
    familyId: string,
): Promise<string | null> {
    const survivor = await database.queryOne<{ org_id: string | null }>(
        `sessions?family_id=eq.${familyId}&revoked=eq.false&select=org_id&limit=1`,
    );
    return survivor?.org_id ?? null;
}

/**
 * Mint an access token for the given user/org by fetching the user's email +
 * verification status and RBAC claims, mirroring the existing inline rotation
 * logic in `routes/refresh.ts` and `index.ts::refreshSession`.
 */
async function mintAccessToken(
    database: DbClient,
    env: Env,
    userId: string,
    orgId: string | null,
): Promise<string> {
    const [user, claims] = await Promise.all([
        database.queryOne<{ id: string; email: string; is_email_verified: boolean }>(
            `users?id=eq.${userId}&select=id,email,is_email_verified`,
        ),
        database.rpc<JwtClaims>("get_jwt_claims", {
            p_user_id: userId,
            p_org_id: orgId,
        }),
    ]);

    return signAccessToken(
        {
            sub: userId,
            email: user?.email ?? "",
            org_id: orgId ?? "",
            roles: claims?.roles ?? [],
            products: claims?.products ?? [],
            membership_status: claims?.membership_status ?? "active",
            is_email_verified: user?.is_email_verified ?? false,
        },
        env,
    );
}
