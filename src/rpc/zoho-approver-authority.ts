import { WorkerEntrypoint } from "cloudflare:workers";
import { recordApprovalEvidence, validateApprovalEvidence } from "./zoho-approval-evidence";
import { previewCandidateReview, verifyCandidateReview } from "./zoho-candidate-review";
import { db } from "../lib/db";
import { isValidUUID } from "../lib/validate";
import type { Env } from "../types";
import { previewCandidateAdministration, executeCandidateAdministration, findCandidateAdministration, listCandidateErasedOperations, listPendingCandidateAdministrations, acknowledgeCandidateAdministration } from './zoho-candidate-administration';

/** Restricted service entrypoint: human evidence and live authority only; no account/session writer or email method. */
export class ZohoApproverAuthority extends WorkerEntrypoint<Env> {
  async previewCandidateAdministration(input: unknown) { return previewCandidateAdministration(this.env, input); }
  async executeCandidateAdministration(input: unknown) { return executeCandidateAdministration(this.env, input); }
  async findCandidateAdministration(input: unknown) { return findCandidateAdministration(this.env, input); }
  async listCandidateErasedOperations(input: unknown) { return listCandidateErasedOperations(this.env, input); }
  async listPendingCandidateAdministrations(input: unknown) { return listPendingCandidateAdministrations(this.env, input); }
  async acknowledgeCandidateAdministration(input: unknown) { return acknowledgeCandidateAdministration(this.env, input); }
  async previewCandidateReview(input: unknown) { return previewCandidateReview(this.env, input); }

  async verifyCandidateReview(input: unknown) { return verifyCandidateReview(this.env, input); }

  async recordApproval(input: unknown) { return recordApprovalEvidence(this.env, input); }

  async validateApproval(grant: unknown) { return validateApprovalEvidence(this.env, grant); }

  async checkApprover(actor: unknown): Promise<{ allowed: boolean }> {
    if (typeof actor !== "string" || !isValidUUID(actor)) return { allowed: false };
    try {
      const allowed = await db(this.env).rpc<unknown>("zoho_is_active_import_approver", { p_actor: actor });
      return { allowed: allowed === true };
    } catch {
      return { allowed: false };
    }
  }

  async fetch(_request: Request): Promise<Response> {
    return new Response("Not found", { status: 404 });
  }
}
