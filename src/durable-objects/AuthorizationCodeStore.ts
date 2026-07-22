import { DurableObject } from "cloudflare:workers";

interface AuthorizationCodeStoreEnv {}

export interface AuthorizationCodeRecord {
	codeHash: string;
	stateHash: string;
	userId: string;
	orgId: string;
	targetApp: "lte";
	redirectUri: string;
	expiresAt: number;
	createdAt: number;
}

export interface ConsumeAuthorizationCodeParams {
	codeHash: string;
	stateHash: string;
	redirectUri: string;
	now: number;
}

export type ConsumeAuthorizationCodeResult =
	| {
			success: true;
			record: AuthorizationCodeRecord;
	  }
	| {
			success: false;
			reason: "missing" | "expired" | "state_mismatch" | "redirect_uri_mismatch";
	  };

const AUTHORIZATION_CODE_KEY = "authorization-code";

export class AuthorizationCodeStore extends DurableObject<AuthorizationCodeStoreEnv> {
	async store(record: AuthorizationCodeRecord): Promise<void> {
		await this.ctx.storage.put(AUTHORIZATION_CODE_KEY, record);
		await this.ctx.storage.setAlarm(record.expiresAt);
	}

	async consume(params: ConsumeAuthorizationCodeParams): Promise<ConsumeAuthorizationCodeResult> {
		return this.ctx.storage.transaction(async (transaction) => {
			const record = await transaction.get<AuthorizationCodeRecord>(AUTHORIZATION_CODE_KEY);

			if (!record) {
				return { success: false, reason: "missing" };
			}

			if (!constantTimeEqual(record.codeHash, params.codeHash)) {
				return { success: false, reason: "missing" };
			}

			if (record.expiresAt <= params.now) {
				await transaction.delete(AUTHORIZATION_CODE_KEY);
				return { success: false, reason: "expired" };
			}

			if (!constantTimeEqual(record.stateHash, params.stateHash)) {
				return { success: false, reason: "state_mismatch" };
			}

			if (record.redirectUri !== params.redirectUri) {
				return { success: false, reason: "redirect_uri_mismatch" };
			}

			await transaction.delete(AUTHORIZATION_CODE_KEY);
			return { success: true, record };
		});
	}

	async alarm(): Promise<void> {
		await this.ctx.storage.delete(AUTHORIZATION_CODE_KEY);
	}
}

function constantTimeEqual(a: string, b: string): boolean {
	if (a.length !== b.length) {
		return false;
	}
	let result = 0;
	for (let i = 0; i < a.length; i++) {
		result |= a.charCodeAt(i) ^ b.charCodeAt(i);
	}
	return result === 0;
}
