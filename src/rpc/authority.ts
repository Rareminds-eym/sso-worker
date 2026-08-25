import { SESSION_TTL_MS, PLATFORM_ORG_ID } from "../lib/constants";
import { db, type DbClient } from "../lib/db";
import { generateRefreshToken, hashPassword, hashToken } from "../lib/hash";
import { exportPemAsJwk, getPublicJWK, signAccessToken, verifyAccessToken } from "../lib/jwt";
import { endpointRateLimit } from "../lib/rate-limit";
import { rotateRefreshToken, type RotationOutcome } from "../lib/session-rotation";
import { performLogin } from "../routes/login";
import { performSignup } from "../routes/signup";
import { performSignupMember } from "../routes/signup-member";
import type { Env, JwtClaims } from "../types";
import type {
    AllLogoutRpcInput,
    AllLogoutRpcOutcome,
    Correlated,
    CurrentLogoutRpcInput,
    CurrentLogoutRpcOutcome,
    JsonValue,
    LoginRpcInput,
    RpcIdentity,
    RpcSession,
    SessionIssueRpcOutcome,
    SessionRejectionCode,
    SessionRotateRpcOutcome,
    SignupMemberRpcInput,
    SignupRpcInput,
    SsoJwksKey,
    SsoJwksRpcOutcome,
    SsoServiceBinding,
} from "./contracts";
import {
    createPreservedWorkflowAuthority,
    type PreservedWorkflowDependencies,
} from "./preserved-workflows";

type AuthorityMethods = SsoServiceBinding;

type LegacySessionResult = Record<string, unknown> & {
    readonly error?: unknown;
    readonly status?: unknown;
    readonly access_token?: unknown;
    readonly refresh_token?: unknown;
};
export interface AuthorityDependencies extends PreservedWorkflowDependencies {
    readonly database: (env: Env) => DbClient;
    readonly hash: typeof hashToken;
    readonly rotate: typeof rotateRefreshToken;
    readonly rateLimit: typeof endpointRateLimit;
    readonly currentJwk: typeof getPublicJWK;
    readonly exportJwk: typeof exportPemAsJwk;
    readonly performLogin: typeof performLogin;
    readonly performSignup: typeof performSignup;
    readonly performSignupMember: typeof performSignupMember;
    readonly now: () => number;
}

const defaultDependencies: AuthorityDependencies = {
    database: db,
    hash: hashToken,
    rotate: rotateRefreshToken,
    rateLimit: endpointRateLimit,
    currentJwk: getPublicJWK,
    exportJwk: exportPemAsJwk,
    performLogin,
    performSignup,
    performSignupMember,
    hashPassword,
    generateRefreshToken,
    signAccessToken,
    verifyAccessToken,
    now: Date.now,
};

/**
 * Creates the clean private authority adapters exposed to Auth Core.
 * Business failures stay typed; unexpected infrastructure failures are redacted.
 */
export function createSsoAuthority(
    env: Env,
    ctx: ExecutionContext,
    overrides: Partial<AuthorityDependencies> = {},
): AuthorityMethods {
    const dependencies = { ...defaultDependencies, ...overrides };
    const database = dependencies.database(env);
    const preserved = createPreservedWorkflowAuthority(env, ctx, database, dependencies);

    return {
        getJwks: (input) => getJwks(env, input, dependencies),
        login: (input) => issueLogin(env, ctx, input, database, dependencies),
        signup: (input) => issueSignup(env, ctx, input, database, dependencies),
        signupMember: (input) => issueSignupMember(env, ctx, input, database, dependencies),
        refreshCurrentSession: (input) => rotateSession(env, ctx, input, database, dependencies),
        logoutCurrentSession: (input) => revokeCurrent(env, input, database, dependencies),
        logoutAllSessions: (input) => revokeAll(env, input, database, dependencies),
        ...preserved,
    };
}

async function getJwks(
    env: Env,
    input: Correlated,
    dependencies: AuthorityDependencies,
): Promise<SsoJwksRpcOutcome> {
    try {
        const freshnessSeconds = parseFreshness(env.JWKS_FRESHNESS_SECONDS);
        const keys = await buildJwks(env, dependencies);
        return { kind: "succeeded", correlationId: input.correlationId, keys, freshnessSeconds };
    } catch (error) {
        return transient(input, error);
    }
}

async function buildJwks(
    env: Env,
    dependencies: AuthorityDependencies,
): Promise<readonly SsoJwksKey[]> {
    const active = toJwksKey(await dependencies.currentJwk(env), env.JWT_KID, "active");
    const hasPreviousKey = Boolean(env.JWT_PUBLIC_KEY_PREVIOUS);
    const hasPreviousKid = Boolean(env.JWT_KID_PREVIOUS);
    if (hasPreviousKey !== hasPreviousKid) throw new Error("Incomplete retiring key metadata");
    if (!hasPreviousKey) return [active];

    const retiring = toJwksKey(
        await dependencies.exportJwk(env.JWT_PUBLIC_KEY_PREVIOUS!, env.JWT_KID_PREVIOUS!),
        env.JWT_KID_PREVIOUS!,
        "retiring",
    );
    if (retiring.kid === active.kid) throw new Error("Duplicate JWKS key identifier");
    return [active, retiring];
}

function toJwksKey(value: unknown, kid: string, status: SsoJwksKey["status"]): SsoJwksKey {
    if (!isRecord(value) || value.kty !== "RSA" || typeof value.n !== "string" || typeof value.e !== "string") {
        throw new Error("Invalid public signing key");
    }
    if (!kid || !value.n || !value.e) throw new Error("Incomplete public signing key");
    return { kty: "RSA", kid, alg: "RS256", use: "sig", status, n: value.n, e: value.e };
}

function parseFreshness(value: string): number {
    const parsed = Number(value);
    if (!Number.isFinite(parsed) || parsed <= 0 || !Number.isInteger(parsed)) {
        throw new Error("Invalid JWKS freshness metadata");
    }
    return parsed;
}
async function issueLogin(
    env: Env,
    ctx: ExecutionContext,
    input: LoginRpcInput,
    database: DbClient,
    dependencies: AuthorityDependencies,
): Promise<SessionIssueRpcOutcome> {
    try {
        const result = await dependencies.performLogin(
            env,
            ctx,
            { email: input.email, password: input.password },
            null,
            null,
        ) as LegacySessionResult;
        return adaptIssue(input, result, "login", input.currentRefreshToken, env, database, dependencies, undefined);
    } catch (error) {
        console.error("[SSO issueLogin Error]", error);
        return transient(input, error);
    }
}

async function issueSignup(
    env: Env,
    ctx: ExecutionContext,
    input: SignupRpcInput,
    database: DbClient,
    dependencies: AuthorityDependencies,
): Promise<SessionIssueRpcOutcome> {
    try {
        const result = await dependencies.performSignup(env, ctx, {
            email: input.email,
            password: input.password,
            org_name: input.organizationName,
            role: input.role,
            user_metadata: input.userMetadata as Record<string, unknown> | undefined,
        }) as LegacySessionResult;
        return adaptIssue(input, result, "signup", input.currentRefreshToken, env, database, dependencies, result.email_sent === true);
    } catch (error) {
        return transient(input, error);
    }
}

async function issueSignupMember(
    env: Env,
    ctx: ExecutionContext,
    input: SignupMemberRpcInput,
    database: DbClient,
    dependencies: AuthorityDependencies,
): Promise<SessionIssueRpcOutcome> {
    try {
        const result = await dependencies.performSignupMember(env, ctx, {
            email: input.email,
            password: input.password,
            role: input.role,
            org_id: input.organizationId,
            user_metadata: input.userMetadata as Record<string, unknown> | undefined,
        }) as LegacySessionResult;
        return adaptIssue(input, result, "signup_member", input.currentRefreshToken, env, database, dependencies, result.email_sent === true);
    } catch (error) {
        return transient(input, error);
    }
}

async function adaptIssue(
    input: Correlated,
    result: LegacySessionResult,
    operation: "login" | "signup" | "signup_member",
    currentRefreshToken: string | undefined,
    env: Env,
    database: DbClient,
    dependencies: AuthorityDependencies,
    emailSent?: boolean,
): Promise<SessionIssueRpcOutcome> {
    if (result.error !== undefined) return issueFailure(input, result, operation);
    if (typeof result.access_token !== "string" || typeof result.refresh_token !== "string") {
        console.error("[SSO adaptIssue Error] result missing access_token/refresh_token:", result);
        return { kind: "unavailable", correlationId: input.correlationId };
    }
    try {
        if (currentRefreshToken && result.refresh_token === currentRefreshToken) {
            throw new Error("Replacement refresh credential was reused");
        }
        const prior = currentRefreshToken
            ? await findPresentedSession(currentRefreshToken, database, dependencies)
            : null;
        const session = await loadSession(
            env,
            database,
            result.access_token,
            result.refresh_token,
            dependencies,
        );
        if (prior && prior.id !== await sessionIdForToken(result.refresh_token, database, dependencies)) {
            await revokeMatching(database, `id=eq.${encodeURIComponent(prior.id)}`);
        }
        return {
            kind: "issued",
            correlationId: input.correlationId,
            session,
            ...(emailSent === undefined ? {} : { emailSent }),
        };
    } catch (error) {
        console.error("[SSO adaptIssue Error]", error);
        return transient(input, error);
    }
}

function issueFailure(
    input: Correlated,
    result: LegacySessionResult,
    operation: "login" | "signup" | "signup_member",
): SessionIssueRpcOutcome {
    const status = typeof result.status === "number" ? result.status : 500;
    if (status === 429) return { kind: "rate_limited", correlationId: input.correlationId };
    if (status >= 500) return { kind: "unavailable", correlationId: input.correlationId };

    let code: SessionRejectionCode = "invalid_request";
    if (operation === "login" && status === 401) code = "invalid_credentials";
    else if (operation === "login" && status === 403) code = "account_blocked";
    else if ((operation === "signup" || operation === "signup_member") && status === 409) code = "identity_conflict";
    else if (operation === "signup_member" && status === 404) code = "membership_rejected";
    return { kind: "rejected", correlationId: input.correlationId, code };
}
async function rotateSession(
    env: Env,
    ctx: ExecutionContext,
    input: Parameters<SsoServiceBinding["refreshCurrentSession"]>[0],
    database: DbClient,
    dependencies: AuthorityDependencies,
): Promise<SessionRotateRpcOutcome> {
    if (!input.refreshToken) return rejectedRotation(input, "absent");
    try {
        const limited = await checkCredentialRateLimit(env, input.refreshToken, "refresh", 30, dependencies);
        if (limited) return { ...limited, correlationId: input.correlationId };
        const outcome = await dependencies.rotate(env, ctx, input.refreshToken, { ip: null, ua: null });
        return adaptRotation(input, outcome, env, database, dependencies);
    } catch (error) {
        return transient(input, error);
    }
}

async function adaptRotation(
    input: Correlated,
    outcome: RotationOutcome,
    env: Env,
    database: DbClient,
    dependencies: AuthorityDependencies,
): Promise<SessionRotateRpcOutcome> {
    switch (outcome.kind) {
        case "rotated":
        case "overlap": {
            const session = await loadSession(
                env,
                database,
                outcome.accessToken,
                outcome.refreshToken,
                dependencies,
            );
            return { kind: outcome.kind, correlationId: input.correlationId, session };
        }
        case "theft": return rejectedRotation(input, "replay_detected");
        case "blocked": return rejectedRotation(input, "blocked");
        case "expired_lifetime":
        case "session_expired": return rejectedRotation(input, "expired");
        case "invalid": return rejectedRotation(input, "absent");
        default: return assertNever(outcome);
    }
}

function rejectedRotation(
    input: Correlated,
    code: "absent" | "expired" | "blocked" | "replay_detected",
): SessionRotateRpcOutcome {
    return { kind: "rejected", correlationId: input.correlationId, code };
}

async function loadSession(
    env: Env,
    database: DbClient,
    accessToken: string,
    refreshToken: string,
    dependencies: AuthorityDependencies,
): Promise<RpcSession> {
    const refreshHash = await dependencies.hash(refreshToken);
    const session = await database.queryOne<AuthoritySessionRow>(
        `sessions?refresh_token_hash=eq.${encodeURIComponent(refreshHash)}&revoked=eq.false&select=id,user_id,org_id,expires_at,revoked`,
    );
    if (!session || session.revoked) throw new Error("Issued session is not authoritative");
    const identity = await loadIdentity(database, session.user_id, session.org_id);
    const remainingLifetimeSeconds = Math.ceil((Date.parse(session.expires_at) - dependencies.now()) / 1000);
    if (!Number.isFinite(remainingLifetimeSeconds) || remainingLifetimeSeconds <= 0) {
        throw new Error("Issued session has no remaining lifetime");
    }
    if (!accessToken || !refreshToken || remainingLifetimeSeconds > (SESSION_TTL_MS / 1000) + 300) {
        throw new Error("Invalid issued credential metadata");
    }
    return { accessToken, refreshToken, remainingLifetimeSeconds, identity };
}

async function loadIdentity(database: DbClient, userId: string, orgId: string | null): Promise<RpcIdentity> {
    const user = await database.queryOne<{
        id: string;
        email: string;
        is_email_verified: boolean;
        user_metadata?: Record<string, unknown>;
    }>(`users?id=eq.${encodeURIComponent(userId)}&select=id,email,is_email_verified,user_metadata`);
    if (!user || !user.email) throw new Error("Session identity is absent");

    const claims = orgId
        ? await database.rpc<JwtClaims>("get_jwt_claims", { p_user_id: userId, p_org_id: orgId })
        : { roles: [], products: [], membership_status: "active" as const };
    if (!isStringArray(claims.roles) || !isStringArray(claims.products)) throw new Error("Invalid identity claims");

    const userRole = (user.user_metadata?.role as string | undefined) ?? (user.user_metadata?.roles as string[] | undefined)?.[0];
    const roles = claims.roles.length > 0
        ? claims.roles
        : (userRole ? [userRole] : ["learner"]);

    return {
        subject: user.id,
        email: user.email,
        organizationId: (orgId && orgId.length > 0) ? orgId : PLATFORM_ORG_ID,
        roles,
        products: claims.products,
        membershipStatus: claims.membership_status,
        emailVerified: user.is_email_verified,
        userMetadata: normalizeMetadata(user.user_metadata),
    };
}
interface AuthoritySessionRow {
    readonly id: string;
    readonly user_id: string;
    readonly org_id: string | null;
    readonly expires_at: string;
    readonly revoked: boolean;
}

async function revokeCurrent(
    env: Env,
    input: CurrentLogoutRpcInput,
    database: DbClient,
    dependencies: AuthorityDependencies,
): Promise<CurrentLogoutRpcOutcome> {
    try {
        const limited = await checkCredentialRateLimit(
            env,
            input.refreshToken,
            "logout-current",
            10,
            dependencies,
        );
        if (limited) return { ...limited, correlationId: input.correlationId };
        const session = await findPresentedSession(input.refreshToken, database, dependencies);
        if (!isActiveSession(session, dependencies.now())) {
            return { kind: "current_already_ended", correlationId: input.correlationId };
        }
        const revoked = await revokeMatching(database, `id=eq.${encodeURIComponent(session.id)}`);
        return {
            kind: revoked > 0 ? "current_revoked" : "current_already_ended",
            correlationId: input.correlationId,
        };
    } catch (error) {
        return transient(input, error);
    }
}

async function revokeAll(
    env: Env,
    input: AllLogoutRpcInput,
    database: DbClient,
    dependencies: AuthorityDependencies,
): Promise<AllLogoutRpcOutcome> {
    try {
        const limited = await checkCredentialRateLimit(
            env,
            input.refreshToken,
            "logout-all",
            10,
            dependencies,
        );
        if (limited) return { ...limited, correlationId: input.correlationId };
        const session = await findPresentedSession(input.refreshToken, database, dependencies);
        if (!isActiveSession(session, dependencies.now())) {
            return { kind: "all_already_ended", correlationId: input.correlationId };
        }
        const revoked = await revokeMatching(database, `user_id=eq.${encodeURIComponent(session.user_id)}`);
        return {
            kind: revoked > 0 ? "all_revoked" : "all_already_ended",
            correlationId: input.correlationId,
        };
    } catch (error) {
        return transient(input, error);
    }
}

async function sessionIdForToken(
    refreshToken: string,
    database: DbClient,
    dependencies: AuthorityDependencies,
): Promise<string | null> {
    const session = await findPresentedSession(refreshToken, database, dependencies);
    return session?.id ?? null;
}

async function findPresentedSession(
    refreshToken: string,
    database: DbClient,
    dependencies: AuthorityDependencies,
): Promise<AuthoritySessionRow | null> {
    if (!refreshToken) return null;
    const refreshHash = await dependencies.hash(refreshToken);
    return database.queryOne<AuthoritySessionRow>(
        `sessions?refresh_token_hash=eq.${encodeURIComponent(refreshHash)}&select=id,user_id,org_id,expires_at,revoked`,
    );
}

function isActiveSession(session: AuthoritySessionRow | null, now: number): session is AuthoritySessionRow {
    return session !== null && !session.revoked && Date.parse(session.expires_at) > now;
}

async function revokeMatching(database: DbClient, filter: string): Promise<number> {
    const rows = await database.query<{ id: string }>(
        `sessions?${filter}&revoked=eq.false&select=id`,
        {
            method: "PATCH",
            headers: { Prefer: "return=representation" },
            body: JSON.stringify({ revoked: true }),
        },
    );
    return rows.length;
}

async function checkCredentialRateLimit(
    env: Env,
    credential: string,
    operation: string,
    maximum: number,
    dependencies: AuthorityDependencies,
): Promise<{ readonly kind: "rate_limited"; readonly retryAfterSeconds?: number } | null> {
    const tokenHash = await dependencies.hash(credential);
    const response = await dependencies.rateLimit(env, `${operation}:${tokenHash}`, maximum, 60);
    if (!response) return null;

    const retryAfterHeader = response.headers.get("Retry-After");
    const retryAfterSeconds = retryAfterHeader === null ? Number.NaN : Number(retryAfterHeader);
    if (!Number.isFinite(retryAfterSeconds) || retryAfterSeconds <= 0) {
        return { kind: "rate_limited" };
    }
    return { kind: "rate_limited", retryAfterSeconds: Math.ceil(retryAfterSeconds) };
}
function transient(
    input: Correlated,
    error: unknown,
): { readonly kind: "timeout" | "unavailable"; readonly correlationId: Correlated["correlationId"] } {
    return {
        kind: isTimeout(error) ? "timeout" : "unavailable",
        correlationId: input.correlationId,
    };
}

function isTimeout(error: unknown): boolean {
    return error instanceof DOMException
        ? error.name === "AbortError" || error.name === "TimeoutError"
        : error instanceof Error && (error.name === "AbortError" || error.name === "TimeoutError");
}

function normalizeMetadata(value: Record<string, unknown> | undefined): Readonly<Record<string, JsonValue>> | undefined {
    if (!value) return undefined;
    const normalized = JSON.parse(JSON.stringify(value)) as unknown;
    if (!isRecord(normalized)) throw new Error("Invalid identity metadata");
    return normalized as Record<string, JsonValue>;
}

function isRecord(value: unknown): value is Record<string, unknown> {
    return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isStringArray(value: unknown): value is string[] {
    return Array.isArray(value) && value.every((entry) => typeof entry === "string");
}

function assertNever(value: never): never {
    throw new Error(`Unhandled authority outcome: ${String(value)}`);
}
