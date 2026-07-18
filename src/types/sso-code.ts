import type { AccessTokenPayload } from "../types";

export type TargetApp = "lte";

export interface GenerateAuthorizationCodeRequest {
  accessToken: string;
  targetApp: TargetApp;
  redirectUri: string;
  ip?: string;
  ua?: string;
}

export interface GenerateAuthorizationCodeResponse {
  code: string;
  state: string;
  redirectUrl: string;
  codeExpiresAt: string;
}

export interface ExchangeAuthorizationCodeRequest {
  code: string;
  state: string;
  targetApp: TargetApp;
  redirectUri: string;
  ip?: string;
  ua?: string;
}

export interface LteUserClaims {
  sub: string;
  email: string;
  org_id: string;
  roles: string[];
  products: string[];
  membership_status: AccessTokenPayload["membership_status"];
  is_email_verified: boolean;
  user_metadata: Record<string, unknown>;
}

export interface LteSubscriptionSnapshot {
  id: string;
  user_id: string;
  organization_id: string | null;
  plan_id: string | null;
  plan_code: string | null;
  plan_name: string | null;
  plan_type: string | null;
  plan_amount: number | null;
  billing_cycle: string | null;
  status: string;
  features: unknown[];
  product_code: TargetApp;
  product_id: string | null;
  subscription_start_date: string | null;
  subscription_end_date: string | null;
  updated_at: string;
}

export interface ExchangeAuthorizationCodeResponse {
  access_token: string;
  refresh_token: string;
  user: LteUserClaims;
  subscription: LteSubscriptionSnapshot | null;
}
