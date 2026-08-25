import { audit } from "../lib/audit";
import { SESSION_TTL_MS, PLATFORM_ORG_ID } from "../lib/constants";
import { db } from "../lib/db";
import { generateRefreshToken, hashPassword, hashToken } from "../lib/hash";
import { signAccessToken } from "../lib/jwt";
import { endpointRateLimit } from "../lib/rate-limit";
import { publishSyncEvent } from "../lib/sync-queue";
import { validateEmail } from "../lib/validate";
import { resolveEffectiveRoles } from "../lib/roles";
import type { Env, JwtClaims, Membership, OAuthLoginBody, User } from "../types";

/**
 * performOAuthLogin - Authenticate (and optionally provision) a user from an
 * OAuth identity profile already exchanged server-side by a trusted gateway.
 *
 * Linking policy:
 *   1. Existing oauth_accounts link → log in.
 *   2. No link, matching email → link identities (only safe because the
 *      caller guarantees the provider verified the email) and mark verified.
 *   3. Neither → create a learner via signup_user RPC with an unguessable
 *      placeholder password hash (password login impossible until reset),
 *      verify email immediately (provider-verified), then link.
 *
 * Session issuance and SkillPassport re-sync are identical to performLogin.
 */
export async function performOAuthLogin(
  env: Env,
  ctx: ExecutionContext,
  body: OAuthLoginBody,
  ip: string | null,
  ua: string | null,
) {
  if (body.provider !== "google") {
    return { error: "Unsupported OAuth provider", status: 400 };
  }

  const providerUserId = typeof body.provider_user_id === "string" ? body.provider_user_id.trim() : "";
  if (!providerUserId || providerUserId.length > 255) {
    return { error: "provider_user_id is required", status: 400 };
  }

  const emailErr = validateEmail(body.email);
  if (emailErr) {
    return { error: "Invalid email format", status: 400 };
  }
  if (body.email_verified !== true) {
    return { error: "Provider account email is not verified", status: 400 };
  }

  const rateLimited = await endpointRateLimit(env, `oauth:ip:${ip ?? "unknown"}`, 10, 60);
  if (rateLimited) {
    return { error: "Rate limit exceeded", status: 429 };
  }

  const email = body.email.toLowerCase().trim();
  const database = db(env);

  // ─── Step 1: existing link? ─────────────────────────────────────
  const link = await database.queryOne<{ user_id: string }>(
    `oauth_accounts?provider=eq.google&provider_user_id=eq.${encodeURIComponent(providerUserId)}&select=user_id`,
  ).catch(() => null);

  let user: User | null = null;
  let isNewUser = false;

  if (link?.user_id) {
    user = await database.queryOne<User>(
      `users?id=eq.${encodeURIComponent(link.user_id)}&select=*`,
    );
    if (!user) {
      // Dangling link (user deleted); treat as no-link and fall through.
      console.warn(`[SSO] oauth link ${providerUserId} points to missing user ${link.user_id}`);
    }
  }

  // ─── Step 2: email match → link identities ──────────────────────
  if (!user) {
    const existing = await database.queryOne<User>(
      `users?email=eq.${encodeURIComponent(email)}&select=*`,
    );

    if (existing) {
      if (existing.is_blocked) {
        return { error: "Account is blocked", status: 403 };
      }
      // Provider proved control of this address — clear the verification gate
      // so the user isn't stranded by App.tsx's verified-email requirement.
      const needsVerification = !existing.is_email_verified;
      await Promise.all([
        insertOAuthLink(database, existing.id, providerUserId),
        needsVerification
          ? database.update(
              "users",
              { id: `eq.${encodeURIComponent(existing.id)}` },
              { is_email_verified: true },
            )
          : Promise.resolve(),
      ]);
      existing.is_email_verified = true;
      user = existing;
    }
  }

  // ─── Step 3: neither → provision learner ────────────────────────
  if (!user) {
    const nameParts = (body.name ?? "").trim().split(/\s+/).filter(Boolean);
    const firstName = nameParts[0] ?? "";
    const lastName = nameParts.slice(1).join(" ");
    const user_metadata: Record<string, unknown> = {
      role: "learner",
      auth_provider: "google",
      ...(body.picture ? { avatar_url: body.picture } : {}),
      ...(firstName ? { firstName } : {}),
      ...(lastName ? { lastName } : {}),
    };

    let result: { user_id: string; org_id: string; slug: string };
    try {
      result = await database.rpc<{ user_id: string; org_id: string; slug: string }>(
        "signup_user",
        {
          p_email: email,
          // ponytail: unguessable placeholder satisfies NOT NULL; password login
          // stays impossible until password-reset sets a real hash. Nullable
          // column migration only worthwhile if more providers land.
          p_password_hash: await hashPassword(crypto.randomUUID()),
          p_org_name: null,
          p_org_slug: `google-${crypto.randomUUID().split("-")[0]}`,
          p_role: "learner",
          p_user_metadata: user_metadata,
        },
      );
    } catch (err: unknown) {
      const errMessage = err instanceof Error ? err.message : String(err);
      if (errMessage.includes("duplicate") || errMessage.includes("23505")) {
        // Lost a race against a concurrent signup with the same email —
        // next attempt will hit the Step 2 link path.
        return { error: "An account with this email already exists. Please log in.", status: 409 };
      }
      throw err;
    }

    // signup_user hardcodes is_email_verified=false; Google already verified it.
    // The two writes are independent — run them concurrently. No user re-fetch:
    // every field consumed downstream is known locally (saves a round trip).
    const createdAt = new Date().toISOString();
    await Promise.all([
      database.update(
        "users",
        { id: `eq.${encodeURIComponent(result.user_id)}` },
        { is_email_verified: true },
      ),
      insertOAuthLink(database, result.user_id, providerUserId),
    ]);

    user = {
      id: result.user_id,
      email,
      password_hash: "",
      is_email_verified: true,
      is_blocked: false,
      last_login_at: null,
      created_at: createdAt,
      updated_at: createdAt,
      user_metadata,
    };
    isNewUser = true;

    publishSyncEvent(env.SYNC_QUEUE, ctx, 'organization.created', {
      // Must match signup_user's COALESCE so consumers validate and the SP DB
      // reflects the real temp-org name on first delivery.
      name: `Organization for ${email}`,
      id: result.org_id,
      slug: result.slug,
      created_by: result.user_id,
    });
    publishSyncEvent(env.SYNC_QUEUE, ctx, 'membership.created', {
      user_id: result.user_id,
      organization_id: result.org_id,
      roles: ["learner"],
      status: "active",
    });
  }

  if (!user) {
    return { error: "OAuth authentication failed", status: 500 };
  }
  if (user.is_blocked) {
    return { error: "Account is blocked", status: 403 };
  }
  // Closure-stable reference: TS narrowing doesn't survive into async callbacks.
  const authenticatedUser = user;

  // ─── Session issuance (identical to performLogin) ────────────────
  ctx.waitUntil(
    database.update("users", { id: `eq.${encodeURIComponent(authenticatedUser.id)}` }, { last_login_at: new Date().toISOString() })
      .catch((err) => console.warn("[SSO] Failed to update last_login_at:", err)),
  );

  const memberships = await database.query<Membership>(
    `memberships?user_id=eq.${encodeURIComponent(authenticatedUser.id)}&status=eq.active&select=*&order=created_at.asc`,
  );

  const activeMembership = memberships[0] ?? null;
  const dbOrgId = activeMembership?.org_id
    ?? (authenticatedUser.user_metadata?.org_id as string | undefined)
    ?? PLATFORM_ORG_ID;

  const claims = await database.rpc<JwtClaims>("get_jwt_claims", {
    p_user_id: authenticatedUser.id,
    p_org_id: dbOrgId,
  }).catch(() => null);

  const refreshToken = generateRefreshToken();
  const refreshHash = await hashToken(refreshToken);
  const sessionId = crypto.randomUUID();

  await database.mutate("sessions", {
    id: sessionId,
    user_id: authenticatedUser.id,
    org_id: dbOrgId,
    refresh_token_hash: refreshHash,
    user_agent: ua,
    ip_address: ip,
    revoked: false,
    expires_at: new Date(Date.now() + SESSION_TTL_MS).toISOString(),
    family_id: sessionId,
    family_created_at: new Date().toISOString(),
  });

  const effectiveRoles = resolveEffectiveRoles({
    claims,
    userMetadata: authenticatedUser.user_metadata,
    fallbackRole: "learner",
  });

  const accessToken = await signAccessToken(
    {
      sub: authenticatedUser.id,
      email: authenticatedUser.email,
      org_id: dbOrgId,
      roles: effectiveRoles,
      products: claims?.products ?? [],
      membership_status: claims?.membership_status ?? "active",
      is_email_verified: true,
      user_metadata: authenticatedUser.user_metadata ?? {},
    },
    env,
  );

  audit(ctx, env, "login", {
    user_id: authenticatedUser.id,
    org_id: activeMembership?.org_id ?? null,
    ip_address: ip,
    user_agent: ua,
    metadata: {
      provider: "google",
      linked: !isNewUser,
    },
  });

  // ─── SkillPassport re-sync backstop (same as login) ──────────────
  ctx.waitUntil(
    (async () => {
      try {
        if (!env?.RATE_LIMIT_KV) return;
        const cacheKey = `login:user-synced:${authenticatedUser.id}`;
        const cached = await env.RATE_LIMIT_KV.get(cacheKey);

        if (cached === 'true') return;

        const { checkUserExistsInSkillpassport } = await import('../lib/skillpassport-check');
        const exists = await checkUserExistsInSkillpassport(env, authenticatedUser.id);

        if (exists) {
          await env.RATE_LIMIT_KV.put(cacheKey, 'true', { expirationTtl: 300 });
          return;
        }

        console.log(`[SSO] User ${authenticatedUser.id} missing, batch querying data for re-sync`);

        if (!env.SYNC_QUEUE) {
          console.error('[SSO] SYNC_QUEUE not bound, cannot re-sync user');
          return;
        }

        const [orgResult, subscriptions] = await Promise.all([
          activeMembership
            ? database.queryOne<{ id: string; name: string }>(
                `organizations?id=eq.${encodeURIComponent(activeMembership.org_id)}&select=id,name`
              ).catch(() => null)
            : Promise.resolve(null),
          database.query<{
            id: string;
            plan_id: string;
            plan_code: string;
            plan_type: string;
            plan_amount: number;
            billing_cycle: string;
            features: string[];
            status: string;
            subscription_start_date: string;
            subscription_end_date: string | null;
            product_id: string | null;
            updated_at: string;
          }>(`subscriptions?user_id=eq.${encodeURIComponent(authenticatedUser.id)}&order=created_at.desc&limit=1`)
            .catch(() => []),
        ]);

        publishSyncEvent(env.SYNC_QUEUE, ctx, 'user.created', {
          id: authenticatedUser.id,
          email: authenticatedUser.email,
          user_metadata: authenticatedUser.user_metadata ?? {},
        });

        if (orgResult && activeMembership && claims) {
          publishSyncEvent(env.SYNC_QUEUE, ctx, 'organization.created', {
            id: orgResult.id,
            name: orgResult.name,
          });

          publishSyncEvent(env.SYNC_QUEUE, ctx, 'membership.created', {
            user_id: authenticatedUser.id,
            organization_id: activeMembership.org_id,
            roles: claims.roles.length > 0 ? claims.roles : ['member'],
            status: 'active',
          });
        }

        if (subscriptions.length > 0) {
          const sub = subscriptions[0];
          publishSyncEvent(env.SYNC_QUEUE, ctx, 'subscription.created', {
            id: sub.id,
            user_id: authenticatedUser.id,
            organization_id: activeMembership?.org_id ?? null,
            plan_id: sub.plan_id,
            plan_code: sub.plan_code,
            plan_type: sub.plan_type,
            plan_amount: sub.plan_amount,
            billing_cycle: sub.billing_cycle,
            features: sub.features,
            status: sub.status,
            subscription_start_date: sub.subscription_start_date,
            subscription_end_date: sub.subscription_end_date,
            is_organization_subscription: false,
            product_id: sub.product_id,
            updated_at: sub.updated_at,
          });
        }

        console.log(`[SSO] Batch re-sync completed for user ${authenticatedUser.id}`);
      } catch (err) {
        console.error('[SSO] Batch sync failed:', err);
      }
    })()
  );

  return {
    access_token: accessToken,
    refresh_token: refreshToken,
    user: { id: authenticatedUser.id, email: authenticatedUser.email },
    active_org_id: activeMembership?.org_id ?? null,
    organizations: memberships.map((m) => ({ org_id: m.org_id })),
  };
}

/**
 * Idempotent link insert — UNIQUE(provider, provider_user_id) backstops races
 * (PostgREST ignore-duplicates returns an empty body, treated as success).
 * A transient failure here surfaces as an identity_error; the next login
 * self-heals via the email-match path.
 */
async function insertOAuthLink(
  database: ReturnType<typeof db>,
  userId: string,
  providerUserId: string,
): Promise<void> {
  await database.query("oauth_accounts", {
    method: "POST",
    headers: { Prefer: "resolution=ignore-duplicates,return=minimal" },
    body: JSON.stringify({
      user_id: userId,
      provider: "google",
      provider_user_id: providerUserId,
    }),
  });
}
