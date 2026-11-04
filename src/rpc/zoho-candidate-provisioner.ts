import { readZohoSsoConfig } from '../lib/zoho-config';
import { WorkerEntrypoint } from 'cloudflare:workers';
import { candidateProjectionSnapshot, confirmCandidateProjection, recoverCandidateDeliveries } from '../lib/zoho-candidate-delivery';
import { db } from '../lib/db';
import { isValidUUID } from '../lib/validate';
import { validateApprovalEvidence } from './zoho-approval-evidence';
import type { Env } from '../types';
import { candidateCapabilities } from '../lib/zoho-candidate-capabilities';
import { candidateSubjectSyncPolicy } from '../lib/zoho-candidate-sync-policy';
export { candidateCapabilities } from '../lib/zoho-candidate-capabilities';

/** Canonical local commit only. Projection delivery/confirmation remains a separate gate. */
export async function provisionCandidateCore(env: Env, grant: unknown): Promise<unknown> {
  if (!readZohoSsoConfig(env).candidateProvisioning) throw new Error('Candidate provisioning disabled');
  if (!grant || typeof grant !== 'object' || Array.isArray(grant) ||
      (grant as Record<string, unknown>).module !== 'Candidates' || !(await validateApprovalEvidence(env, grant)).allowed)
    throw new Error('Candidate execution authority unavailable');
  if (!(await candidateCapabilities(env)).ready) throw new Error('Candidate dependencies unavailable');
  // An RPC transport failure is ambiguous: never translate it to a no-effect response.
  return db(env).rpc('zoho_provision_candidate', { p_grant: grant });
}

export class ZohoCandidateProvisioner extends WorkerEntrypoint<Env> {
  async getSubjectSyncPolicy(input: unknown) { return candidateSubjectSyncPolicy(this.env, input); }
  async recoverProjections() { return recoverCandidateDeliveries(this.env); }
  async getProjectionSnapshot(input: unknown) { return candidateProjectionSnapshot(this.env, input); }
  async confirmProjection(input: unknown) { return confirmCandidateProjection(this.env, input); }
  async capabilities() { return candidateCapabilities(this.env); }
  async executeApprovedOperation(grant: unknown) { return provisionCandidateCore(this.env, grant); }
  async findOperationReceipt(input: unknown) {
    if (!input || typeof input !== 'object' || Array.isArray(input)) return null;
    const value = input as Record<string, unknown>;
    if (Object.keys(value).length !== 3 || typeof value.operationId !== 'string' || !isValidUUID(value.operationId) ||
        typeof value.sourceHash !== 'string' || !/^[a-f0-9]{64}$/.test(value.sourceHash) || value.readOnly !== true) return null;
    return db(this.env).rpc('zoho_find_candidate_receipt', { p_operation: value.operationId, p_source_hash: value.sourceHash });
  }
  async fetch() { return new Response('Not found', { status: 404 }); }
}
