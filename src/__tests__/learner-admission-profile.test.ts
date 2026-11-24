import { beforeEach, expect, it, vi } from 'vitest';
const f = vi.hoisted(() => ({ query: vi.fn(), mutate: vi.fn(), sync: vi.fn(), email: vi.fn() }));
vi.mock('../lib/db', () => ({ db: () => f }));
vi.mock('../lib/hash', () => ({ hashPassword: async () => 'fixture-hash' }));
vi.mock('../lib/organization-sync', () => ({ ensureOrganizationExists: async () => ({}) }));
vi.mock('../lib/learner-helpers', () => ({
  validateLearnerData: () => ({ valid: true }), generateTempPassword: () => 'fixture-only',
  splitName: () => ({ first_name: 'Test', last_name: 'Learner' }),
  checkUserExists: async () => false, getLearnerRole: async () => 'learner-role',
}));
import { performCreateLearnerUser } from '../routes/learner-admission';
import { learnerBulkImport } from '../queue/bulk-import-adapters';
const input = { email: 'learner@example.test', name: 'Test Learner', organization_id: '10000000-0000-4000-8000-000000000001', contact_number: '1234567890', enrollment_number: 'EN-1', metadata: { grade: '10', section: 'A', roll_number: '12', district_name: 'District', dateOfBirth: '2005-01-02', guardianName: 'Guardian' } };
const env = { SYNC_QUEUE: { send: f.sync }, EMAIL_QUEUE: { send: f.email }, SKILLPASSPORT_URL: 'https://fixture.test' } as never;
beforeEach(() => {
  vi.clearAllMocks(); f.query.mockResolvedValue([]);
  f.mutate.mockImplementation(async (table: string) => table === 'users' ? { id: 'learner-id', email: input.email } : { id: 'membership-id' });
  f.sync.mockResolvedValue(undefined); f.email.mockResolvedValue(undefined);
});
it('delivers manual enrollment fields through the canonical membership profile', async () => {
  expect(await performCreateLearnerUser(env, input)).toMatchObject({ success: true });
  const event = f.sync.mock.calls.map(([event]) => event).find(event => event.type === 'membership.created');
  expect(event.payload).toMatchObject({ organization_id: input.organization_id, roles: ['learner'], learner_profile: {
    contactNumber: input.contact_number, enrollmentNumber: 'EN-1', grade: '10', section: 'A', roll_number: '12', district_name: 'District', dateOfBirth: '2005-01-02', guardianName: 'Guardian',
  } });
});
it('keeps institution and role selection outside the profile metadata', async () => {
  await performCreateLearnerUser(env, { ...input, metadata: { ...input.metadata, school_id: 'foreign', role: 'super_admin' } });
  const event = f.sync.mock.calls.map(([event]) => event).find(event => event.type === 'membership.created');
  expect(event.payload.roles).toEqual(['learner']);
  expect(event.payload.organization_id).toBe(input.organization_id);
  expect(event.payload.learner_profile).not.toHaveProperty('school_id');
  expect(event.payload.learner_profile).not.toHaveProperty('role');
});
it('preserves the bulk importer profile mapping through the shared owner', () => {
  const map = learnerBulkImport.buildLearnerProfile;
  if (!map) throw new Error('Bulk profile mapping is required');
  expect(map({ email: input.email, name: input.name, contactNumber: '1234567890', roll_number: '12', grade: '10', section: 'A' })).toMatchObject({ contactNumber: '1234567890', roll_number: '12', grade: '10', section: 'A' });
});
