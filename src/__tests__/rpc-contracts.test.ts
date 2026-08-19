import { describe, expect, expectTypeOf, it } from "vitest";
import {
    SSO_RPC_METHODS,
    type AcceptInviteRpcInput,
    type AcceptInviteRpcOutcome,
    type AllLogoutRpcInput,
    type AllLogoutRpcOutcome,
    type CancelInviteRpcInput,
    type CancelInviteRpcOutcome,
    type ChangeOrganizationRpcInput,
    type ChangeOrganizationRpcOutcome,
    type Correlated,
    type CorrelationId,
    type CreateInviteRpcInput,
    type CreateInviteRpcOutcome,
    type CurrentLogoutRpcInput,
    type CurrentLogoutRpcOutcome,
    type ForgotPasswordRpcInput,
    type ForgotPasswordRpcOutcome,
    type GetIdentityRpcInput,
    type GetJwksRpcInput,
    type GetJwksRpcOutcome,
    type IdentityRpcOutcome,
    type ListOrganizationsRpcInput,
    type LoginRpcInput,
    type LoginRpcOutcome,
    type OrganizationListRpcOutcome,
    type RefreshCurrentRpcInput,
    type RefreshCurrentRpcOutcome,
    type RequestVerificationRpcInput,
    type RequestVerificationRpcOutcome,
    type ResendInviteRpcInput,
    type ResendInviteRpcOutcome,
    type ResetPasswordRpcInput,
    type ResetPasswordRpcOutcome,
    type SessionIssueRpcOutcome,
    type SignupMemberRpcInput,
    type SignupMemberRpcOutcome,
    type SignupRpcInput,
    type SignupRpcOutcome,
    type SsoRpcInput,
    type SsoRpcOutcome,
    type SsoServiceBinding,
    type VerifyEmailRpcInput,
    type VerifyEmailRpcOutcome,
} from "../rpc/contracts";

const correlationId = "corr_123" as CorrelationId;

type RpcMethod = keyof SsoServiceBinding;
type DeclaredMethod = (typeof SSO_RPC_METHODS)[number];
type MissingMethod = Exclude<RpcMethod, DeclaredMethod>;
type ExtraMethod = Exclude<DeclaredMethod, RpcMethod>;
type RpcInput<K extends RpcMethod> = Parameters<SsoServiceBinding[K]>[0];
type RpcOutcome<K extends RpcMethod> = Awaited<ReturnType<SsoServiceBinding[K]>>;
type NonCorrelatedInputMethod = {
    [K in RpcMethod]: RpcInput<K> extends Correlated ? never : K;
}[RpcMethod];
type NonCorrelatedOutcomeMethod = {
    [K in RpcMethod]: RpcOutcome<K> extends Correlated ? never : K;
}[RpcMethod];
type KeysOfUnion<T> = T extends T ? keyof T : never;
type AllRpcInput = { [K in RpcMethod]: RpcInput<K> }[RpcMethod];
type AllRpcOutcome = { [K in RpcMethod]: RpcOutcome<K> }[RpcMethod];
type ForbiddenTransportKey =
    | "headers"
    | "header"
    | "authorization"
    | "cookie"
    | "cookies"
    | "cookieHeader"
    | "url"
    | "origin"
    | "endpoint"
    | "redirectUrl"
    | "callbackUrl"
    | "request"
    | "response"
    | "fetch"
    | "error";
type ForbiddenFailureKey = "error" | "message" | "stack" | "cause" | "details" | "exception";
type CallerSuppliedIdentityKey = "subject" | "identity" | "userId" | "email" | "organizationId";
type TransportLeak = Extract<KeysOfUnion<AllRpcInput>, ForbiddenTransportKey>;
type UntypedFailureLeak = Extract<KeysOfUnion<AllRpcOutcome>, ForbiddenFailureKey>;
type AllLogoutIdentityLeak = Extract<keyof AllLogoutRpcInput, CallerSuppliedIdentityKey>;
type CurrentLogoutCrossScopeLeak = Extract<
    CurrentLogoutRpcOutcome["kind"],
    "all_revoked" | "all_already_ended"
>;
type AllLogoutCrossScopeLeak = Extract<
    AllLogoutRpcOutcome["kind"],
    "current_revoked" | "current_already_ended"
>;

// These compile-time fixtures prove transport data cannot enter closed inputs.
const invalidLoginInput: LoginRpcInput = {
    correlationId,
    email: "member@example.test",
    password: "not-a-real-secret",
    // @ts-expect-error Browser headers are outside the private binding contract.
    headers: new Headers(),
};
void invalidLoginInput;

const invalidCookieInput: CurrentLogoutRpcInput = {
    correlationId,
    refreshToken: "opaque-test-value",
    scope: "current",
    // @ts-expect-error Raw Cookie fields are decoded by Auth Core, never forwarded.
    cookie: "__Host-rm-refresh=opaque-test-value",
};
void invalidCookieInput;

const invalidPublicUrlInput: LoginRpcInput = {
    correlationId,
    email: "member@example.test",
    password: "not-a-real-secret",
    // @ts-expect-error Public callback URLs are outside the private binding contract.
    redirectUrl: "https://public.example.test/callback",
};
void invalidPublicUrlInput;

const invalidAllLogoutInput: AllLogoutRpcInput = {
    correlationId,
    refreshToken: "opaque-test-value",
    scope: "all",
    // @ts-expect-error Identity must be derived from the current session credential.
    subject: "caller-supplied-identity",
};
void invalidAllLogoutInput;

const invalidFailure: SessionIssueRpcOutcome = {
    correlationId,
    kind: "rejected",
    code: "invalid_credentials",
    // @ts-expect-error Raw/untyped failure details are not contract outcomes.
    error: "upstream detail",
};
void invalidFailure;

const invalidCorrelation: Correlated = {
    // @ts-expect-error Correlation identifiers must be validated and branded before RPC.
    correlationId: "unvalidated-correlation",
};
void invalidCorrelation;

const resetWithExistingSession: ResetPasswordRpcInput = {
    correlationId,
    resetToken: "one-time-reset-value",
    password: "replacement-password",
    currentRefreshToken: "opaque-current-session",
};

describe("private SSO RPC contract", () => {
    it("should expose every approved operation and no transport operation", () => {
        expect(SSO_RPC_METHODS).toEqual([
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
        ]);
        expect(SSO_RPC_METHODS).not.toContain("fetch");
        expect(SSO_RPC_METHODS).not.toContain("logoutSession");
        expectTypeOf<MissingMethod>().toEqualTypeOf<never>();
        expectTypeOf<ExtraMethod>().toEqualTypeOf<never>();
        expectTypeOf<TransportLeak>().toEqualTypeOf<never>();
        expectTypeOf<UntypedFailureLeak>().toEqualTypeOf<never>();
        expectTypeOf<AllLogoutIdentityLeak>().toEqualTypeOf<never>();
    });

    it("should correlate every approved input and outcome", () => {
        expectTypeOf<NonCorrelatedInputMethod>().toEqualTypeOf<never>();
        expectTypeOf<NonCorrelatedOutcomeMethod>().toEqualTypeOf<never>();
        expect(resetWithExistingSession.currentRefreshToken).toBe("opaque-current-session");
    });

    it("should publish an operation-specific input and outcome pair for every method", () => {
        expectTypeOf<SsoRpcInput<"getJwks">>().toEqualTypeOf<GetJwksRpcInput>();
        expectTypeOf<SsoRpcOutcome<"getJwks">>().toEqualTypeOf<GetJwksRpcOutcome>();
        expectTypeOf<SsoRpcInput<"login">>().toEqualTypeOf<LoginRpcInput>();
        expectTypeOf<SsoRpcOutcome<"login">>().toEqualTypeOf<LoginRpcOutcome>();
        expectTypeOf<SsoRpcInput<"signup">>().toEqualTypeOf<SignupRpcInput>();
        expectTypeOf<SsoRpcOutcome<"signup">>().toEqualTypeOf<SignupRpcOutcome>();
        expectTypeOf<SsoRpcInput<"signupMember">>().toEqualTypeOf<SignupMemberRpcInput>();
        expectTypeOf<SsoRpcOutcome<"signupMember">>().toEqualTypeOf<SignupMemberRpcOutcome>();
        expectTypeOf<SsoRpcInput<"refreshCurrentSession">>().toEqualTypeOf<RefreshCurrentRpcInput>();
        expectTypeOf<SsoRpcOutcome<"refreshCurrentSession">>().toEqualTypeOf<RefreshCurrentRpcOutcome>();
        expectTypeOf<SsoRpcInput<"changeOrganization">>().toEqualTypeOf<ChangeOrganizationRpcInput>();
        expectTypeOf<SsoRpcOutcome<"changeOrganization">>().toEqualTypeOf<ChangeOrganizationRpcOutcome>();
        expectTypeOf<SsoRpcInput<"logoutCurrentSession">>().toEqualTypeOf<CurrentLogoutRpcInput>();
        expectTypeOf<SsoRpcOutcome<"logoutCurrentSession">>().toEqualTypeOf<CurrentLogoutRpcOutcome>();
        expectTypeOf<SsoRpcInput<"logoutAllSessions">>().toEqualTypeOf<AllLogoutRpcInput>();
        expectTypeOf<SsoRpcOutcome<"logoutAllSessions">>().toEqualTypeOf<AllLogoutRpcOutcome>();
        expectTypeOf<SsoRpcInput<"listOrganizations">>().toEqualTypeOf<ListOrganizationsRpcInput>();
        expectTypeOf<SsoRpcOutcome<"listOrganizations">>().toEqualTypeOf<OrganizationListRpcOutcome>();
        expectTypeOf<SsoRpcInput<"createInvite">>().toEqualTypeOf<CreateInviteRpcInput>();
        expectTypeOf<SsoRpcOutcome<"createInvite">>().toEqualTypeOf<CreateInviteRpcOutcome>();
        expectTypeOf<SsoRpcInput<"acceptInvite">>().toEqualTypeOf<AcceptInviteRpcInput>();
        expectTypeOf<SsoRpcOutcome<"acceptInvite">>().toEqualTypeOf<AcceptInviteRpcOutcome>();
        expectTypeOf<SsoRpcInput<"cancelInvite">>().toEqualTypeOf<CancelInviteRpcInput>();
        expectTypeOf<SsoRpcOutcome<"cancelInvite">>().toEqualTypeOf<CancelInviteRpcOutcome>();
        expectTypeOf<SsoRpcInput<"resendInvite">>().toEqualTypeOf<ResendInviteRpcInput>();
        expectTypeOf<SsoRpcOutcome<"resendInvite">>().toEqualTypeOf<ResendInviteRpcOutcome>();
        expectTypeOf<SsoRpcInput<"requestVerification">>().toEqualTypeOf<RequestVerificationRpcInput>();
        expectTypeOf<SsoRpcOutcome<"requestVerification">>().toEqualTypeOf<RequestVerificationRpcOutcome>();
        expectTypeOf<SsoRpcInput<"verifyEmail">>().toEqualTypeOf<VerifyEmailRpcInput>();
        expectTypeOf<SsoRpcOutcome<"verifyEmail">>().toEqualTypeOf<VerifyEmailRpcOutcome>();
        expectTypeOf<SsoRpcInput<"forgotPassword">>().toEqualTypeOf<ForgotPasswordRpcInput>();
        expectTypeOf<SsoRpcOutcome<"forgotPassword">>().toEqualTypeOf<ForgotPasswordRpcOutcome>();
        expectTypeOf<SsoRpcInput<"resetPassword">>().toEqualTypeOf<ResetPasswordRpcInput>();
        expectTypeOf<SsoRpcOutcome<"resetPassword">>().toEqualTypeOf<ResetPasswordRpcOutcome>();
        expectTypeOf<SsoRpcInput<"getIdentity">>().toEqualTypeOf<GetIdentityRpcInput>();
        expectTypeOf<SsoRpcOutcome<"getIdentity">>().toEqualTypeOf<IdentityRpcOutcome>();
    });

    it("should keep current-session and all-session logout contracts distinct", () => {
        expectTypeOf<CurrentLogoutRpcInput>().not.toEqualTypeOf<AllLogoutRpcInput>();
        expectTypeOf<CurrentLogoutRpcOutcome>().not.toEqualTypeOf<AllLogoutRpcOutcome>();
        expectTypeOf<CurrentLogoutCrossScopeLeak>().toEqualTypeOf<never>();
        expectTypeOf<AllLogoutCrossScopeLeak>().toEqualTypeOf<never>();

        const current: CurrentLogoutRpcOutcome = {
            correlationId,
            kind: "current_revoked",
        };
        const all: AllLogoutRpcOutcome = {
            correlationId,
            kind: "all_already_ended",
        };

        expect(current.kind).toBe("current_revoked");
        expect(all.kind).toBe("all_already_ended");
    });
});
