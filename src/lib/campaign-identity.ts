import { db } from './db';
import { hashPassword, hashToken, generateRefreshToken } from './hash';
import { PLATFORM_ORG_ID, SESSION_TTL_MS } from './constants';
import { mintAccessToken } from './session-rotation';
import { createAuthorizationCode, getAuthorizationCodeStub, hashAuthorizationValue } from './authorization-code';
import type { Env, JwtClaims } from '../types';

export interface CampaignRegistration {
  email: string;
  name: string;
  mobile: string;
  educatorId?: string;
}

/** Private binding only. Its caller must authenticate the campaign email proof. */
export async function ensureCampaignUser(env: Env, input: CampaignRegistration) {
  if (!input || typeof input.email !== 'string' || typeof input.name !== 'string' ||
      !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(input.email) || !input.name.trim() ||
      !/^\d{10}$/.test(input.mobile) ||
      (input.educatorId !== undefined && !/^LRN-[A-Z]{3}\d{2}-\d{8}$/.test(input.educatorId))) {
    throw new Error('Invalid campaign registration');
  }
  // A random, undisclosed password allows verified-email/Google login without a shared default password.
  return db(env).rpc<{ user_id: string; educator_id: string; joined_at: string }>('ensure_educator_campaign_user', {
    p_email: input.email.toLowerCase().trim(), p_name: input.name.trim(), p_mobile: input.mobile,
    p_org_id: PLATFORM_ORG_ID, p_password_hash: await hashPassword(generateRefreshToken()),
    p_educator_id: input.educatorId ?? null,
  });
}

/** Transactional outbox; retries are safe because the existing consumer upserts by SSO user ID. */
export async function flushCampaignOutbox(env: Env) {
  if (!env.SYNC_QUEUE) throw new Error('SYNC_QUEUE is not configured');
  const database = db(env);
  const rows = await database.query<{ id: string; user_id: string; payload: { org_id?: string | null } }>(
    'events?event_type=eq.campaign.identity.sync&status=eq.received&order=created_at.asc&limit=100');
  for (const row of rows) {
    const user = await database.queryOne<Record<string, unknown>>(
      `users?id=eq.${row.user_id}&select=id,email,is_email_verified,user_metadata`);
    if (!user) continue;
    await env.SYNC_QUEUE.send({ type: 'user.updated', payload: user, timestamp: new Date().toISOString() });
    if (row.payload.org_id) {
      const org = await database.queryOne<{ id: string; name: string }>(`organizations?id=eq.${row.payload.org_id}&select=id,name`);
      if (!org) throw new Error('Campaign organization unavailable');
      const claims = await database.rpc<JwtClaims>('get_jwt_claims', { p_user_id: row.user_id, p_org_id: row.payload.org_id });
      const metadata = user.user_metadata as Record<string, unknown>;
      await env.SYNC_QUEUE.send({ type: 'organization.created', payload: org, timestamp: new Date().toISOString() });
      await env.SYNC_QUEUE.send({ type: 'membership.created', payload: {
        user_id: row.user_id, organization_id: row.payload.org_id, roles: claims.roles, status: claims.membership_status,
        learner_profile: { learner_id: metadata.learner_id, contactNumber: metadata.contact_number, learner_type: 'teacher' },
      }, timestamp: new Date().toISOString() });
    }
    await database.update('events', { id: `eq.${row.id}` }, { status: 'completed', processed_at: new Date().toISOString() });
  }
}

function callbackUri(env: Env) {
  if (!env.SKILLPASSPORT_URL) throw new Error('SKILLPASSPORT_URL is required');
  const url = new URL('/api/campaign/callback', env.SKILLPASSPORT_URL);
  if (url.protocol !== 'https:' && !['localhost', '127.0.0.1'].includes(url.hostname)) {
    throw new Error('SkillPassport callback must use HTTPS');
  }
  return url.toString();
}

export async function createCampaignHandoff(env: Env, input: { email: string; state: string }) {
  if (!/^[a-f0-9]{64}$/.test(input.state)) throw new Error('Invalid handoff state');
  const database = db(env);
  const user = await database.queryOne<{ id: string; is_blocked: boolean; is_email_verified: boolean; user_metadata?: { campaigns?: { '100keducators'?: { educator_id?: string } } } }>(
    `users?email=eq.${encodeURIComponent(input.email.toLowerCase().trim())}&select=id,is_blocked,is_email_verified,user_metadata`);
  if (!user || user.is_blocked || !user.is_email_verified) throw new Error('Verified account required');
  if (!user.user_metadata?.campaigns?.['100keducators']?.educator_id) throw new Error('Campaign registration required');
  const membership = await database.queryOne<{ org_id: string }>(
    `memberships?user_id=eq.${user.id}&status=eq.active&order=created_at.asc&limit=1&select=org_id`);
  const redirectUri = callbackUri(env);
  const generated = await createAuthorizationCode(redirectUri);
  await getAuthorizationCodeStub(env, generated.codeHash).store({
    codeHash: generated.codeHash, stateHash: await hashAuthorizationValue(input.state),
    userId: user.id, orgId: membership?.org_id ?? PLATFORM_ORG_ID,
    targetApp: 'skillpassport', redirectUri,
    expiresAt: Date.parse(generated.expiresAt), createdAt: Date.now(),
  });
  const url = new URL(redirectUri);
  url.searchParams.set('code', generated.code);
  url.searchParams.set('state', input.state);
  return { redirectUrl: url.toString() };
}

export async function exchangeCampaignHandoff(env: Env, input: { code: string; state: string; redirectUri: string }) {
  if (!/^[A-Za-z0-9_-]{43}$/.test(input.code) || !/^[a-f0-9]{64}$/.test(input.state) || input.redirectUri !== callbackUri(env)) {
    throw new Error('Invalid campaign callback');
  }
  const codeHash = await hashAuthorizationValue(input.code);
  const result = await getAuthorizationCodeStub(env, codeHash).consume({
    codeHash, stateHash: await hashAuthorizationValue(input.state), redirectUri: input.redirectUri, now: Date.now(),
  });
  if (!result.success || result.record.targetApp !== 'skillpassport') throw new Error('Invalid or expired handoff');
  const database = db(env);
  const token = await mintAccessToken(database, env, result.record.userId, result.record.orgId);
  if (!token || typeof token !== 'object') throw new Error('Account is unavailable');
  const refreshToken = generateRefreshToken();
  const sessionId = crypto.randomUUID();
  const now = new Date().toISOString();
  await database.mutate('sessions', {
    id: sessionId, user_id: result.record.userId, org_id: result.record.orgId,
    refresh_token_hash: await hashToken(refreshToken), revoked: false,
    expires_at: new Date(Date.now() + SESSION_TTL_MS).toISOString(),
    family_id: sessionId, family_created_at: now, device_info: { app: 'skillpassport' },
  });
  try {
    await recordSkillpassportAccess(env, refreshToken, 'login');
  } catch (error) {
    await database.update('sessions', { id: `eq.${sessionId}` }, { revoked: true });
    throw error;
  }
  return { refreshToken, remainingLifetimeSeconds: SESSION_TTL_MS / 1000 };
}

/** App identity is fixed by this private method, never accepted from browser input. */
export async function recordSkillpassportAccess(env: Env, refreshToken: string, eventType: 'login' | 'session_access', signup = false) {
  if (typeof refreshToken !== 'string' || !refreshToken || refreshToken.length > 4096 ||
      !['login', 'session_access'].includes(eventType)) throw new Error('Invalid access event');
  await db(env).rpc('record_application_access', {
    p_refresh_hash: await hashToken(refreshToken), p_app_id: 'skillpassport', p_event_type: eventType, p_signup: signup,
  });
}
