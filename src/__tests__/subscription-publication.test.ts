import { SignJWT, exportSPKI, generateKeyPair } from 'jose';
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { SsoWorker } from '../index';
import { PLATFORM_ORG_ID } from '../lib/constants';
import { preparePublishedIncludedCreditOccurrence } from '../lib/subscriptions';
import type { Env } from '../types';
import { executionContext } from './execution-context';

const actor = 'a0000000-0000-4000-8000-000000000001';
const planId = 'b0000000-0000-4000-8000-000000000001';
const productId = 'c0000000-0000-4000-8000-000000000001';
const revisionId = 'd0000000-0000-4000-8000-000000000001';
const featureId = 'e0000000-0000-4000-8000-000000000001';
const timestamp = '2026-11-19T10:00:00.123456Z';
const definitions = [{ id: featureId, key: 'seats', type: 'numeric_limit' }];
const plan = () => ({
  id: planId, plan_code: `pln_${'a'.repeat(32)}`, product_id: productId,
  applicable_entities: ['organization'], entity_config: {
    subscription_authoring: { schemaVersion: 1, currencies: [{ code: 'USD', minorUnit: 2 }] },
    subscription_credit_authoring: { schemaVersion: 1, pools: [], timePolicies: [] },
    subscription_publication: { schemaVersion: 2, requiredFeatureKeys: ['seats'], requiredCreditAllocations: [] },
  }
});
const bundle = () => ({
  schemaVersion: 1, draft: {
    schemaVersion: 2, id: revisionId, revisionNumber: 1,
    plan: { id: planId, code: plan().plan_code, productId }, name: 'Synthetic complete offer', audiences: ['organization'],
    purchaseMode: 'self_service', prices: [{
      id: featureId, currency: 'USD', minorUnit: 2, amountMinor: 0,
      intervalUnit: 'year', intervalCount: 1, quantityBasis: 'subscription', audiences: ['organization']
    }],
    features: [{ key: 'seats', type: 'numeric_limit', enabled: true, limit: { kind: 'finite', value: 0 } }]
  },
  includedCredits: { schemaVersion: 1, id: productId, revisionId, funding: 'included', rules: [] }
});
const projection = () => ({
  schemaVersion: 1, bundle: bundle(), entitlements: [
    { plan_id: planId, feature_id: featureId, is_enabled: true, value_numeric: 0, value_text: null },
  ]
});
const receipt = () => ({ planId, revisionId, previousRevisionId: null, publishedBy: actor, publishedAt: timestamp });
let env: Env, keys: Awaited<ReturnType<typeof generateKeyPair>>, transport = vi.fn<typeof fetch>();
let live: unknown, stored: unknown, published: unknown, canonical = plan();
beforeAll(async () => {
  keys = await generateKeyPair('RS256');
  env = {
    SUPABASE_URL: 'https://sso.example.invalid', SUPABASE_SERVICE_ROLE_KEY: 'synthetic-database-key',
    JWT_PUBLIC_KEY: await exportSPKI(keys.publicKey), SKILLPASSPORT_URL: 'https://app.example.invalid',
    INTERNAL_WEBHOOK_SECRET: 'synthetic-internal-secret', SYNC_QUEUE: {
      send: vi.fn().mockResolvedValue(undefined), sendBatch: vi.fn().mockResolvedValue(undefined),
    },
  } as unknown as Env;
});
beforeEach(() => {
  live = { roles: ['super_admin'], membership_status: 'active' }; canonical = plan();
  stored = { projection: projection(), stagedBy: actor, stagedAt: timestamp }; published = receipt();
  transport = vi.fn<typeof fetch>().mockImplementation(async (input, init) => {
    const url = new URL(String(input));
    if (url.pathname === '/api/internal/subscriptions/projection') return Response.json(stored);
    if (url.pathname.endsWith('/users')) return Response.json([{ id: actor, is_blocked: false }]);
    if (url.pathname.endsWith('/get_jwt_claims')) return Response.json(live);
    if (url.pathname.endsWith('/products')) return Response.json([{ id: productId }]);
    if (url.pathname.endsWith('/plans')) return Response.json([canonical]);
    if (url.pathname.endsWith('/subscription_plan_drafts')) return Response.json([
      { snapshot: bundle().draft, included_credits: bundle().includedCredits, staged_by: actor, staged_at: timestamp },
    ]);
    if (url.pathname.endsWith('/publish_subscription_plan_revision')) return Response.json(published);
    throw new Error(`Unexpected isolated transport ${url.pathname} ${init?.method}`);
  });
  vi.stubGlobal('fetch', transport);
});
afterEach(() => vi.unstubAllGlobals());
async function credential(patch: Record<string, unknown> = {}) {
  return new SignJWT({
    sub: actor, org_id: PLATFORM_ORG_ID, membership_status: 'active', roles: ['super_admin'],
    exp: Math.floor(Date.now() / 1000) + 300, ...patch
  }).setProtectedHeader({ alg: 'RS256', typ: 'JWT' })
    .setIssuer('sso-api').setAudience('sso-client').sign(keys.privateKey);
}
const writes = () => transport.mock.calls.filter(call => new URL(String(call[0])).pathname.endsWith('/publish_subscription_plan_revision'));
const appReads = () => transport.mock.calls.filter(call => new URL(String(call[0])).hostname === 'app.example.invalid');
async function publish(token?: string, previous: string | null = null, targetEnv = env) {
  return new SsoWorker(executionContext(), targetEnv).publishSubscriptionPlanRevision(token ?? await credential(),
    planId, revisionId, previous, productId, definitions);
}

describe('actual signed/live subscription publication service boundary with isolated owner IO', () => {
  it('prepares canonical immutable desired state without application IO or any write', async () => {
    const result = await new SsoWorker({} as ExecutionContext, env).prepareSubscriptionPlanPublication(
      await credential(), planId, revisionId, productId, definitions);
    expect(result).toEqual({ kind: 'prepared', projection: projection(), preparedBy: actor });
    expect(writes()).toHaveLength(0); expect(appReads()).toHaveLength(0);
  });

  it('reads actual application state before a single canonical CAS, deriving actor and expected owner configuration', async () => {
    expect(await publish()).toEqual({ kind: 'published', receipt: receipt() });
    expect(appReads()).toHaveLength(1); expect(writes()).toHaveLength(1);
    const [url, init] = appReads()[0];
    expect(new URL(String(url)).searchParams.get('planId')).toBe(planId);
    expect(new URL(String(url)).searchParams.get('revisionId')).toBe(revisionId);
    // Workers only accept 'follow' or 'manual'; 'manual' plus the exact 200 check refuses redirects.
    expect(init).toMatchObject({ method: 'GET', redirect: 'manual', headers: { Authorization: 'Bearer synthetic-internal-secret' } });
    expect(transport.mock.calls.indexOf(appReads()[0])).toBeLessThan(transport.mock.calls.indexOf(writes()[0]));
    expect(JSON.parse(String(writes()[0][1]?.body))).toEqual({
      p_plan_id: planId, p_revision_id: revisionId,
      p_expected_previous_revision_id: null, p_actor_id: actor,
      p_expected_plan: { ...bundle().draft.plan, audiences: canonical.applicable_entities, configuration: canonical.entity_config }
    });
  });

  it.each(['', 'malformed.jwt'])('rejects invalid credentials before owner IO %#', async token => {
    expect(await publish(token)).toEqual({ kind: 'forbidden' }); expect(transport).not.toHaveBeenCalled();
  });
  it.each([{ roles: ['admin'] }, { org_id: productId }, { membership_status: 'suspended' }, { exp: 1 }])(
    'rejects insufficient genuine signed claims before owner IO %#', async patch => {
      expect(await publish(await credential(patch))).toEqual({ kind: 'forbidden' }); expect(transport).not.toHaveBeenCalled();
    });
  it('checks live revocation before application access', async () => {
    live = { roles: [], membership_status: 'active' };
    expect(await publish()).toEqual({ kind: 'forbidden' }); expect(appReads()).toHaveLength(0); expect(writes()).toHaveLength(0);
  });
  it('rejects a changed canonical code or incomplete coverage before application access', async () => {
    canonical.plan_code = `pln_${'b'.repeat(32)}`;
    expect(await publish()).toEqual({ kind: 'invalid' }); expect(appReads()).toHaveLength(0); expect(writes()).toHaveLength(0);
  });

  it.each([
    null, {}, { ready: true }, { projection: projection(), stagedBy: 'invalid', stagedAt: timestamp },
    { projection: projection(), stagedBy: actor, stagedAt: 'invalid' },
    { projection: { ...projection(), entitlements: [] }, stagedBy: actor, stagedAt: timestamp },
    { projection: { ...projection(), entitlements: [{ ...projection().entitlements[0], value_numeric: null }] }, stagedBy: actor, stagedAt: timestamp },
    { projection: { ...projection(), bundle: { ...bundle(), draft: { ...bundle().draft, name: 'Altered offer' } } }, stagedBy: actor, stagedAt: timestamp },
  ])('rejects malformed, missing or altered owner evidence as a persistence failure before write %#', async value => {
    stored = value;
    await expect(publish()).rejects.toThrow(); expect(appReads()).toHaveLength(1); expect(writes()).toHaveLength(0);
  });
  it.each([401, 404, 503, 302])('does not retry or publish after owner status %s', async status => {
    const original = transport.getMockImplementation()!;
    transport.mockImplementation(async (input, init) => new URL(String(input)).hostname === 'app.example.invalid'
      ? new Response('Unavailable', { status }) : original(input, init));
    await expect(publish()).rejects.toThrow('readback failed'); expect(appReads()).toHaveLength(1); expect(writes()).toHaveLength(0);
  });
  it.each([undefined, '', 'http://remote.example.invalid', 'https://user:password@app.example.invalid', 'https://app.example.invalid/other'])
    ('rejects missing or invalid configured application owner without an alternate target %#', async url => {
      await expect(publish(undefined, null, { ...env, SKILLPASSPORT_URL: url } as Env)).rejects.toThrow();
      expect(appReads()).toHaveLength(0); expect(writes()).toHaveLength(0);
    });
  it('does not retry an uncertain SSO commit or compensate immutable application preparation', async () => {
    const original = transport.getMockImplementation()!;
    transport.mockImplementation(async (input, init) => {
      if (new URL(String(input)).pathname.endsWith('/publish_subscription_plan_revision')) throw new Error('Synthetic uncertain commit');
      return original(input, init);
    });
    await expect(publish()).rejects.toThrow('uncertain commit'); expect(writes()).toHaveLength(1); expect(appReads()).toHaveLength(1);
  });
  it.each([null, {}, { ...receipt(), publishedBy: productId }, { ...receipt(), revisionId: planId },
    { ...receipt(), previousRevisionId: productId }, { ...receipt(), publishedAt: 'invalid' }])(
      'rejects malformed or misbound canonical acknowledgements without retry %#', async value => {
        published = value; await expect(publish()).rejects.toThrow(); expect(writes()).toHaveLength(1);
      });
});

function creditFixture() {
  const timeId = 'f0000000-0000-4000-8000-000000000001';
  const ruleId = 'f0000000-0000-4000-8000-000000000002';
  const terms = {
    ...bundle(), draft: {
      ...bundle().draft,
      features: [{ key: 'ai_credits', type: 'metered', enabled: true, limit: { kind: 'allocation_policy' } }]
    },
    includedCredits: {
      ...bundle().includedCredits, rules: [{
        id: ruleId, featureKey: 'ai_credits', poolKey: 'organization_ai', recipient: 'organization', audiences: ['organization'],
        quantity: { kind: 'finite', value: 10 }, cadence: { kind: 'monthly', timePolicyId: timeId },
        expiry: { kind: 'allocation_period_end' }, rollover: { kind: 'none' },
      }]
    },
  };
  const settings = {
    ...plan().entity_config,
    subscription_credit_authoring: {
      schemaVersion: 1, pools: [{
        key: 'organization_ai', featureKey: 'ai_credits',
        recipient: 'organization', audiences: ['organization']
      }], timePolicies: [{
        id: timeId, timeZone: 'UTC',
        monthlyAnchor: 'subscription_anniversary', monthDayOverflow: 'clamp', ambiguousTime: 'reject', nonexistentTime: 'reject'
      }]
    },
    subscription_publication: {
      schemaVersion: 2, requiredFeatureKeys: ['ai_credits'],
      requiredCreditAllocations: [{ poolKey: 'organization_ai', audiences: ['organization'] }]
    },
  };
  return {
    event: {
      plan_id: planId, revision_id: revisionId, published_by: actor, published_at: timestamp,
      canonical_plan: { ...terms.draft.plan, audiences: ['organization'], configuration: settings }
    },
    draft: { snapshot: terms.draft, included_credits: terms.includedCredits, staged_by: actor, staged_at: timestamp },
    features: [{ key: 'ai_credits', type: 'metered' }],
    occurrence: {
      subscriptionId: actor, productId, planId, revisionId, ruleId, audience: 'organization',
      recipient: { kind: 'organization', id: actor }, activatedAt: Date.parse('2026-01-31T12:00:00Z'),
      subscriptionEndsAt: Date.parse('2027-01-31T12:00:00Z'), periodStartsAt: Date.parse('2026-01-31T12:00:00Z'),
      periodEndsAt: Date.parse('2027-01-31T12:00:00Z'), occurrenceIndex: 0
    },
  };
}
function publishedReader(events: unknown[], drafts: unknown[]) {
  return {
    query: vi.fn(async (path: string) => {
      if (path.startsWith('subscription_plan_publication_events?')) return events;
      if (path.startsWith('subscription_plan_drafts?')) return drafts;
      throw new Error('Mutable or unrelated owner query is prohibited in this isolated control');
    })
  };
}

describe('immutable publication-bound credit occurrence preparation', () => {
  it('loads only the exact saved event and draft, using recorded calendar settings', async () => {
    const fixture = creditFixture(), reader = publishedReader([fixture.event], [fixture.draft]);
    const result = await preparePublishedIncludedCreditOccurrence(reader, planId, revisionId, productId, fixture.features, fixture.occurrence);
    expect(reader.query).toHaveBeenCalledTimes(2);
    expect(reader.query.mock.calls[0][0]).toBe('subscription_plan_publication_events?select=plan_id,revision_id,published_by,published_at,canonical_plan'
      + `&plan_id=eq.${planId}&revision_id=eq.${revisionId}&limit=2`);
    expect(result).toMatchObject({
      planId, revisionId, quantity: 10, startsAt: Date.parse('2026-01-31T12:00:00Z'),
      endsAt: Date.parse('2026-02-28T12:00:00Z'), expiresAt: Date.parse('2026-02-28T12:00:00Z')
    });
    expect(result.timePolicies[0].timeZone).toBe('UTC');
    expect(Object.isFrozen(result.timePolicies[0])).toBe(true);
    expect(result).not.toHaveProperty('authorized');
  });

  it('retains historical terms after mutable plan settings and latest publication change', async () => {
    const fixture = creditFixture();
    // A reader that touches a current pointer, live plan or product fails; only historical records resolve.
    const reader = publishedReader([structuredClone(fixture.event)], [structuredClone(fixture.draft)]);
    canonical.plan_code = `pln_${'f'.repeat(32)}`;
    canonical.entity_config.subscription_credit_authoring.timePolicies = [];
    const result = await preparePublishedIncludedCreditOccurrence(reader, planId, revisionId, productId, fixture.features, fixture.occurrence);
    expect(result.endsAt).toBe(Date.parse('2026-02-28T12:00:00Z'));
    expect(transport).not.toHaveBeenCalled();
  });

  it.each([
    { events: [], reason: 'Published revision must resolve exactly once' },
    { events: [null], reason: 'Stored publication evidence differs' },
    { events: [{ ready: true }], reason: 'Stored publication evidence differs' },
  ])('rejects absent or fabricated publication state before reading a draft %#', async ({ events, reason }) => {
    const fixture = creditFixture(), reader = publishedReader(events, [fixture.draft]);
    await expect(preparePublishedIncludedCreditOccurrence(reader, planId, revisionId, productId, fixture.features, fixture.occurrence))
      .rejects.toThrow(reason);
    expect(reader.query).toHaveBeenCalledTimes(1);
  });

  it('rejects ambiguous duplicate event rows instead of choosing one', async () => {
    const fixture = creditFixture(), reader = publishedReader([fixture.event, fixture.event], [fixture.draft]);
    await expect(preparePublishedIncludedCreditOccurrence(reader, planId, revisionId, productId, fixture.features, fixture.occurrence))
      .rejects.toThrow('resolve exactly once');
    expect(reader.query).toHaveBeenCalledTimes(1);
  });

  it.each([
    { plan_id: actor }, { revision_id: actor }, { published_by: 'invalid' }, { published_at: '2026-02-30T00:00:00Z' },
    { canonical_plan: null }, { ready: true },
  ])('rejects malformed or misbound persisted publication metadata %#', async patch => {
    const fixture = creditFixture(), reader = publishedReader([{ ...fixture.event, ...patch }], [fixture.draft]);
    await expect(preparePublishedIncludedCreditOccurrence(reader, planId, revisionId, productId, fixture.features, fixture.occurrence))
      .rejects.toThrow('Stored publication evidence differs');
    expect(reader.query).toHaveBeenCalledTimes(1);
  });

  it.each(['id', 'productId', 'code', 'configuration'])('rejects changed canonical %s in the event snapshot', async key => {
    const fixture = creditFixture();
    const value = key === 'code' ? `pln_${'b'.repeat(32)}` : key === 'configuration' ? {} : actor;
    const event = { ...fixture.event, canonical_plan: { ...fixture.event.canonical_plan, [key]: value } };
    const reader = publishedReader([event], [fixture.draft]);
    await expect(preparePublishedIncludedCreditOccurrence(reader, planId, revisionId, productId, fixture.features, fixture.occurrence))
      .rejects.toThrow();
  });

  it('rejects incomplete recorded publication coverage', async () => {
    const fixture = creditFixture();
    fixture.event.canonical_plan.configuration.subscription_publication.requiredFeatureKeys.push('seats');
    const reader = publishedReader([fixture.event], [fixture.draft]);
    await expect(preparePublishedIncludedCreditOccurrence(reader, planId, revisionId, productId,
      [...fixture.features, { key: 'seats', type: 'numeric_limit' }], fixture.occurrence)).rejects.toThrow('Stored publication evidence differs');
  });

  it('does not substitute current calendar definitions when the saved snapshot is incomplete', async () => {
    const fixture = creditFixture(); fixture.event.canonical_plan.configuration.subscription_credit_authoring.timePolicies = [];
    const reader = publishedReader([fixture.event], [fixture.draft]);
    await expect(preparePublishedIncludedCreditOccurrence(reader, planId, revisionId, productId, fixture.features, fixture.occurrence))
      .rejects.toThrow('Stored published bundle differs');
    expect(reader.query).toHaveBeenCalledTimes(2);
  });

  it.each([
    { drafts: [], reason: 'Bundled revision must resolve exactly once' },
    { drafts: [null], reason: 'Stored published bundle differs' },
    { drafts: [creditFixture().draft, creditFixture().draft], reason: 'Bundled revision must resolve exactly once' },
  ])('rejects missing, malformed or ambiguous draft records %#', async ({ drafts, reason }) => {
    const fixture = creditFixture(), reader = publishedReader([fixture.event], drafts);
    await expect(preparePublishedIncludedCreditOccurrence(reader, planId, revisionId, productId, fixture.features, fixture.occurrence))
      .rejects.toThrow(reason);
    expect(reader.query).toHaveBeenCalledTimes(2);
  });

  it('rejects a stored draft belonging to a different plan even with valid independent terms', async () => {
    const fixture = creditFixture(); fixture.draft.snapshot.plan.id = actor;
    const reader = publishedReader([fixture.event], [fixture.draft]);
    await expect(preparePublishedIncludedCreditOccurrence(reader, planId, revisionId, productId, fixture.features, fixture.occurrence))
      .rejects.toThrow('Stored publication evidence differs');
  });

  it('rejects another subscription revision in the occurrence context', async () => {
    const fixture = creditFixture(), reader = publishedReader([fixture.event], [fixture.draft]);
    await expect(preparePublishedIncludedCreditOccurrence(reader, planId, revisionId, productId, fixture.features,
      { ...fixture.occurrence, revisionId: actor })).rejects.toThrow('subscription must bind');
  });

  it.each([
    { features: [] }, { features: [{ key: 'ai_credits', type: 'boolean' }] },
    { features: [{ key: 'ai_credits', type: 'metered' }, { key: 'ai_credits', type: 'metered' }] },
  ])('rejects invalid application-owned feature definitions before reading draft terms %#', async ({ features }) => {
    const fixture = creditFixture(), reader = publishedReader([fixture.event], [fixture.draft]);
    await expect(preparePublishedIncludedCreditOccurrence(reader, planId, revisionId, productId, features, fixture.occurrence))
      .rejects.toThrow('Stored publication evidence differs');
    expect(reader.query).toHaveBeenCalledTimes(1);
  });

  it('surfaces a failed immutable draft read without trying another source', async () => {
    const fixture = creditFixture(), reader = publishedReader([fixture.event], [fixture.draft]);
    const original = reader.query.getMockImplementation()!;
    reader.query.mockImplementation(async path => {
      if (path.startsWith('subscription_plan_drafts?')) throw new Error('Synthetic unavailable draft owner');
      return original(path);
    });
    await expect(preparePublishedIncludedCreditOccurrence(reader, planId, revisionId, productId, fixture.features, fixture.occurrence))
      .rejects.toThrow('unavailable draft owner');
    expect(reader.query).toHaveBeenCalledTimes(2);
  });

  it('validates lookup identities before querying and surfaces IO failure without retry', async () => {
    const fixture = creditFixture(), reader = publishedReader([fixture.event], [fixture.draft]);
    await expect(preparePublishedIncludedCreditOccurrence(reader, `${planId}&limit=999`, revisionId, productId, fixture.features, fixture.occurrence))
      .rejects.toThrow('expected UUID');
    expect(reader.query).not.toHaveBeenCalled();
    reader.query.mockRejectedValue(new Error('Synthetic unavailable publication owner'));
    await expect(preparePublishedIncludedCreditOccurrence(reader, planId, revisionId, productId, fixture.features, fixture.occurrence))
      .rejects.toThrow('unavailable publication owner');
    expect(reader.query).toHaveBeenCalledTimes(1);
  });
});
