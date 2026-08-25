/**
 * Closed, private service-binding contract between Auth Core and SSO Worker.
 *
 * Browser transport details are intentionally absent. Auth Core decodes cookies,
 * validates browser requests, and passes only the credential/value needed by the
 * authority operation plus a validated, non-secret correlation identifier.
 */

export type CorrelationId = string & { readonly __correlationId: unique symbol };

export type JsonValue =
    | string
    | number
    | boolean
    | null
    | readonly JsonValue[]
    | { readonly [key: string]: JsonValue };

export interface Correlated {
    readonly correlationId: CorrelationId;
}

export interface AuthorizedRpcInput extends Correlated {
    readonly accessToken: string;
}

export interface CurrentSessionCredential extends Correlated {
    readonly refreshToken: string;
}

export type MembershipStatus = "active" | "inactive" | "suspended" | "expired";

export interface RpcIdentity {
    readonly subject: string;
    readonly email: string;
    readonly organizationId: string;
    readonly roles: readonly string[];
    readonly products: readonly string[];
    readonly membershipStatus: MembershipStatus;
    readonly emailVerified: boolean;
    readonly userMetadata?: Readonly<Record<string, JsonValue>>;
}

export interface RpcSession {
    readonly accessToken: string;
    readonly refreshToken: string;
    readonly remainingLifetimeSeconds: number;
    readonly identity: RpcIdentity;
}
export type RpcTransientOutcome =
    | (Correlated & { readonly kind: "rate_limited"; readonly retryAfterSeconds?: number })
    | (Correlated & { readonly kind: "timeout" })
    | (Correlated & { readonly kind: "unavailable" });

export type RpcCancelledOutcome = Correlated & { readonly kind: "cancelled" };

export type SessionRejectionCode =
    | "invalid_credentials"
    | "account_blocked"
    | "identity_conflict"
    | "invalid_invitation"
    | "invitation_expired"
    | "membership_rejected"
    | "invalid_request";

export type WorkflowRejectionCode =
    | "authorization_denied"
    | "not_found"
    | "conflict"
    | "expired"
    | "already_used"
    | "invalid_one_time_value"
    | "account_blocked"
    | "invalid_request";

export type SessionDefinitiveCode =
    | "absent"
    | "expired"
    | "revoked"
    | "blocked"
    | "replay_detected";

export type SessionIssueRpcOutcome =
    | (Correlated & {
        readonly kind: "issued";
        readonly session: RpcSession;
        /** Whether a verification email was dispatched; present only when the operation can send one (signup). */
        readonly emailSent?: boolean;
    })
    | (Correlated & { readonly kind: "rejected"; readonly code: SessionRejectionCode })
    | RpcCancelledOutcome
    | RpcTransientOutcome;

export type SessionRotateRpcOutcome =
    | (Correlated & {
        readonly kind: "rotated" | "overlap";
        readonly session: RpcSession;
    })
    | (Correlated & { readonly kind: "rejected"; readonly code: SessionDefinitiveCode })
    | RpcCancelledOutcome
    | RpcTransientOutcome;

export type WorkflowRpcOutcome<T> =
    | (Correlated & { readonly kind: "succeeded"; readonly data: T })
    | (Correlated & { readonly kind: "rejected"; readonly code: WorkflowRejectionCode })
    | RpcCancelledOutcome
    | RpcTransientOutcome;

export type WorkflowOrRotatedSessionRpcOutcome<T> =
    | (Correlated & { readonly kind: "succeeded"; readonly data: T })
    | (Correlated & {
        readonly kind: "rotated";
        readonly data: T;
        readonly session: RpcSession;
    })
    | (Correlated & { readonly kind: "rejected"; readonly code: WorkflowRejectionCode })
    | RpcCancelledOutcome
    | RpcTransientOutcome;

export type WorkflowOrNewSessionRpcOutcome<T> =
    | (Correlated & { readonly kind: "succeeded"; readonly data: T })
    | (Correlated & {
        readonly kind: "issued";
        readonly data: T;
        readonly session: RpcSession;
    })
    | (Correlated & { readonly kind: "rejected"; readonly code: WorkflowRejectionCode })
    | RpcCancelledOutcome
    | RpcTransientOutcome;
export interface SsoJwksKey {
    readonly kty: "RSA";
    readonly kid: string;
    readonly alg: "RS256";
    readonly use: "sig";
    readonly status: "active" | "retiring";
    readonly n: string;
    readonly e: string;
}

export interface SsoJwksSnapshot extends Correlated {
    readonly kind: "succeeded";
    readonly keys: readonly SsoJwksKey[];
    readonly freshnessSeconds?: number;
}

export type SsoJwksRpcOutcome =
    | SsoJwksSnapshot
    | RpcCancelledOutcome
    | RpcTransientOutcome;

export interface LoginRpcInput extends Correlated {
    readonly email: string;
    readonly password: string;
    readonly currentRefreshToken?: string;
}

export interface SignupRpcInput extends Correlated {
    readonly email: string;
    readonly password: string;
    readonly organizationName: string;
    readonly role: string;
    readonly userMetadata?: Readonly<Record<string, JsonValue>>;
    readonly currentRefreshToken?: string;
}

export interface SignupMemberRpcInput extends Correlated {
    readonly email: string;
    readonly password: string;
    readonly role: string;
    readonly organizationId?: string;
    readonly userMetadata?: Readonly<Record<string, JsonValue>>;
    readonly currentRefreshToken?: string;
}

export interface RefreshCurrentRpcInput extends CurrentSessionCredential {
    readonly operation: "refresh_current_session";
}

export interface ChangeOrganizationRpcInput extends CurrentSessionCredential {
    readonly organizationId: string;
}

export interface CurrentLogoutRpcInput extends CurrentSessionCredential {
    readonly scope: "current";
}

export interface AllLogoutRpcInput extends CurrentSessionCredential {
    readonly scope: "all";
}

export type CurrentLogoutRpcOutcome =
    | (Correlated & { readonly kind: "current_revoked" })
    | (Correlated & { readonly kind: "current_already_ended" })
    | RpcCancelledOutcome
    | RpcTransientOutcome;

export type AllLogoutRpcOutcome =
    | (Correlated & { readonly kind: "all_revoked" })
    | (Correlated & { readonly kind: "all_already_ended" })
    | RpcCancelledOutcome
    | RpcTransientOutcome;

export interface RpcOrganization {
    readonly organizationId: string;
    readonly name: string | null;
    readonly slug: string | null;
    readonly roles: readonly string[];
    readonly active: boolean;
}

export interface OrganizationListData {
    readonly organizations: readonly RpcOrganization[];
}

export interface CreateInviteRpcInput extends AuthorizedRpcInput {
    readonly email: string;
    readonly organizationId: string;
    readonly roles: readonly string[];
}

export interface AcceptInviteRpcInput extends Correlated {
    readonly invitationToken: string;
    readonly password?: string;
    readonly currentRefreshToken?: string;
}

export interface CancelInviteRpcInput extends AuthorizedRpcInput {
    readonly inviteId: string;
}

export interface ResendInviteRpcInput extends AuthorizedRpcInput {
    readonly inviteId: string;
}

export interface RequestVerificationRpcInput extends AuthorizedRpcInput { }

export interface VerifyEmailRpcInput extends Correlated {
    readonly verificationToken: string;
    readonly currentRefreshToken?: string;
}

export interface ForgotPasswordRpcInput extends Correlated {
    readonly email: string;
}

export interface ResetPasswordRpcInput extends Correlated {
    readonly resetToken: string;
    readonly password: string;
    /** Existing cookie-session credential, when present, for authoritative replacement. */
    readonly currentRefreshToken?: string;
}

export interface InviteCreatedData {
    readonly inviteId: string;
    readonly email: string;
    readonly expiresAt: string;
}

export interface InviteAcceptedData {
    readonly inviteId: string;
    readonly organizationId: string;
}

export interface InviteCancelledData {
    readonly inviteId: string;
    readonly cancelled: true;
}

export interface InviteResentData {
    readonly inviteId: string;
    readonly email: string;
    readonly expiresAt: string;
}

export interface VerificationRequestedData {
    readonly accepted: true;
    readonly alreadyVerified: boolean;
}

export interface EmailVerifiedData {
    readonly verified: true;
}

export interface PasswordRecoveryRequestedData {
    readonly accepted: true;
}

export interface PasswordResetData {
    readonly reset: true;
}
export type OrganizationListRpcOutcome = WorkflowRpcOutcome<OrganizationListData>;
export type CreateInviteRpcOutcome = WorkflowRpcOutcome<InviteCreatedData>;
export type AcceptInviteRpcOutcome =
    | (Correlated & {
        readonly kind: "issued";
        readonly data: InviteAcceptedData;
        readonly session: RpcSession;
    })
    | (Correlated & { readonly kind: "rejected"; readonly code: SessionRejectionCode })
    | RpcCancelledOutcome
    | RpcTransientOutcome;
export type CancelInviteRpcOutcome = WorkflowRpcOutcome<InviteCancelledData>;
export type ResendInviteRpcOutcome = WorkflowRpcOutcome<InviteResentData>;
export type RequestVerificationRpcOutcome = WorkflowRpcOutcome<VerificationRequestedData>;
export type VerifyEmailRpcOutcome = WorkflowOrRotatedSessionRpcOutcome<EmailVerifiedData>;
export type ForgotPasswordRpcOutcome = WorkflowRpcOutcome<PasswordRecoveryRequestedData>;
export type ResetPasswordRpcOutcome = WorkflowOrNewSessionRpcOutcome<PasswordResetData>;
export type IdentityRpcOutcome = WorkflowRpcOutcome<RpcIdentity>;

/** Operation-specific aliases keep every binding method independently reviewable. */
export interface GetJwksRpcInput extends Correlated { }
export type GetJwksRpcOutcome = SsoJwksRpcOutcome;
export type LoginRpcOutcome = SessionIssueRpcOutcome;
export type SignupRpcOutcome = SessionIssueRpcOutcome;
export type SignupMemberRpcOutcome = SessionIssueRpcOutcome;
export type RefreshCurrentRpcOutcome = SessionRotateRpcOutcome;
export type ChangeOrganizationRpcOutcome = SessionRotateRpcOutcome;
export interface ListOrganizationsRpcInput extends AuthorizedRpcInput { }
export interface GetIdentityRpcInput extends AuthorizedRpcInput { }

/**
 * Complete clean-break capability surface exposed through the private binding.
 * Implementations return only correlated discriminated outcomes; browser
 * transport objects and raw failures are intentionally not representable.
 */
export interface SsoServiceBinding {
    getJwks(input: GetJwksRpcInput): Promise<GetJwksRpcOutcome>;
    login(input: LoginRpcInput): Promise<LoginRpcOutcome>;
    signup(input: SignupRpcInput): Promise<SignupRpcOutcome>;
    signupMember(input: SignupMemberRpcInput): Promise<SignupMemberRpcOutcome>;
    refreshCurrentSession(input: RefreshCurrentRpcInput): Promise<RefreshCurrentRpcOutcome>;
    changeOrganization(input: ChangeOrganizationRpcInput): Promise<ChangeOrganizationRpcOutcome>;
    logoutCurrentSession(input: CurrentLogoutRpcInput): Promise<CurrentLogoutRpcOutcome>;
    logoutAllSessions(input: AllLogoutRpcInput): Promise<AllLogoutRpcOutcome>;
    listOrganizations(input: ListOrganizationsRpcInput): Promise<OrganizationListRpcOutcome>;
    createInvite(input: CreateInviteRpcInput): Promise<CreateInviteRpcOutcome>;
    acceptInvite(input: AcceptInviteRpcInput): Promise<AcceptInviteRpcOutcome>;
    cancelInvite(input: CancelInviteRpcInput): Promise<CancelInviteRpcOutcome>;
    resendInvite(input: ResendInviteRpcInput): Promise<ResendInviteRpcOutcome>;
    requestVerification(input: RequestVerificationRpcInput): Promise<RequestVerificationRpcOutcome>;
    verifyEmail(input: VerifyEmailRpcInput): Promise<VerifyEmailRpcOutcome>;
    forgotPassword(input: ForgotPasswordRpcInput): Promise<ForgotPasswordRpcOutcome>;
    resetPassword(input: ResetPasswordRpcInput): Promise<ResetPasswordRpcOutcome>;
    getIdentity(input: GetIdentityRpcInput): Promise<IdentityRpcOutcome>;
}

export type SsoRpcMethod = keyof SsoServiceBinding;
export type SsoRpcInput<Method extends SsoRpcMethod> = Parameters<SsoServiceBinding[Method]>[0];
export type SsoRpcOutcome<Method extends SsoRpcMethod> = Awaited<ReturnType<SsoServiceBinding[Method]>>;

export const SSO_RPC_METHODS = [
    "getJwks",
    "login",
    "signup",
    "signupMember",
    "refreshCurrentSession",
    "changeOrganization",
    "logoutCurrentSession",
    "logoutAllSessions",
    "listOrganizations",
    "createInvite",
    "acceptInvite",
    "cancelInvite",
    "resendInvite",
    "requestVerification",
    "verifyEmail",
    "forgotPassword",
    "resetPassword",
    "getIdentity",
] as const satisfies readonly (keyof SsoServiceBinding)[];
