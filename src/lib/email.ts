import type { Env } from "../types";
import { escapeHrefAttr, escapeHtmlAttr } from "./escape";

export interface EmailPayload {
  to: string;
  subject: string;
  html: string;
  text: string;
}

export const EMAIL_SEND_TIMEOUT_MS = 5_000;

export type EmailStatus = "sent" | "failed";
export type EmailFailureReason = "timeout" | "provider_rejected" | "exception" | "lookup_failed";

const ERROR_CODE_PATTERN = /^[A-Z0-9_]{1,40}$/;
const ERROR_NAME_PATTERN = /^[A-Za-z0-9_]{1,60}$/;

/**
 * Log a delivery failure with a closed field set only. Free-text error messages are never
 * logged: cross-worker RPC errors can echo the recipient and the accept URL (raw token).
 */
export function logEmailFailure(
  inviteId: string,
  reason: EmailFailureReason,
  detail: { errorCode?: unknown; errorName?: unknown } = {},
): void {
  const entry: Record<string, string> = { msg: "[SSO] Invite email not delivered", inviteId, reason };
  if (typeof detail.errorCode === "string" && ERROR_CODE_PATTERN.test(detail.errorCode)) {
    entry.errorCode = detail.errorCode;
  }
  if (typeof detail.errorName === "string" && ERROR_NAME_PATTERN.test(detail.errorName)) {
    entry.errorName = detail.errorName;
  }
  console.error(JSON.stringify(entry));
}

/**
 * Send an email and report the result. Bounded by EMAIL_SEND_TIMEOUT_MS; never throws.
 * Returns "sent" only when the provider resolves with `success === true`. The underlying
 * RPC is kept alive via ctx.waitUntil so it can finish after a timeout.
 */
export async function sendEmailWithStatus(
  env: Env,
  payload: EmailPayload,
  ctx: ExecutionContext,
  log: { inviteId: string },
): Promise<EmailStatus> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    const emailPromise = Promise.resolve(env.EMAIL_SERVICE.sendEmail({
      to: payload.to,
      subject: payload.subject,
      html: payload.html,
      text: payload.text,
    }));
    // Attach the handler immediately so a late rejection is never unhandled.
    const settled = emailPromise.then(
      (result) => ({ ok: true as const, result }),
      (error: unknown) => ({ ok: false as const, error }),
    );
    ctx.waitUntil(settled);

    const timeout = new Promise<{ timedOut: true }>((resolve) => {
      timer = setTimeout(() => resolve({ timedOut: true }), EMAIL_SEND_TIMEOUT_MS);
    });
    const outcome = await Promise.race([settled, timeout]);

    if ("timedOut" in outcome) {
      logEmailFailure(log.inviteId, "timeout");
      return "failed";
    }
    if (!outcome.ok) {
      const error = outcome.error as { name?: unknown } | null | undefined;
      logEmailFailure(log.inviteId, "exception", { errorName: error?.name });
      return "failed";
    }
    const result = outcome.result as { success?: unknown; errorCode?: unknown } | null | undefined;
    if (result?.success === true) return "sent";
    logEmailFailure(log.inviteId, "provider_rejected", { errorCode: result?.errorCode });
    return "failed";
  } catch (error) {
    logEmailFailure(log.inviteId, "exception", { errorName: (error as { name?: unknown } | null)?.name });
    return "failed";
  } finally {
    if (timer !== undefined) clearTimeout(timer);
  }
}

/**
 * Send an email via the email-worker service binding.
 *
 * Uses Promise.race for a user-facing timeout (5s) so the caller never hangs.
 * The underlying RPC completes in the background even if the timeout fires
 * (tracked via ctx.waitUntil to keep the Worker alive).
 * Errors are logged but never thrown to avoid blocking the HTTP response.
 */
export async function sendEmail(env: Env, payload: EmailPayload, ctx?: ExecutionContext): Promise<void> {
  try {
    const emailPromise = env.EMAIL_SERVICE.sendEmail({
      to: payload.to,
      subject: payload.subject,
      html: payload.html,
      text: payload.text,
    });

    if (ctx) {
      ctx.waitUntil(emailPromise.then(() => {
        console.log(JSON.stringify({ msg: "[SSO] Email delivered", to: payload.to }));
      }).catch((err: Error) => {
        console.error(JSON.stringify({ msg: "[SSO] Email delivery failed", error: err.message }));
      }));
    }

    const res = await Promise.race([
      emailPromise,
      new Promise<never>((_, reject) =>
        setTimeout(() => reject(new Error("Email send timed out")), EMAIL_SEND_TIMEOUT_MS)
      ),
    ]).catch(() => undefined);

    if (res && !res.success) {
      console.error(`[SSO] Email delivery failed: ${res.errorCode} ${res.error}`);
    }
  } catch (err) {
    console.error("[SSO] Email delivery setup failed:", err);
  }
}

/** Build an invite email */
export function inviteEmail(
  inviterEmail: string,
  orgName: string,
  acceptUrl: string,
): { subject: string; html: string; text: string } {
  return {
    subject: `You've been invited to ${orgName}`,
    html: `
      <p>${escapeHtmlAttr(inviterEmail)} has invited you to join <strong>${escapeHtmlAttr(orgName)}</strong>.</p>
      <p><a href="${escapeHrefAttr(acceptUrl)}">Accept Invitation</a></p>
      <p>This invitation expires in 7 days.</p>
    `.trim(),
    text: `${inviterEmail} has invited you to join ${orgName}.\nAccept: ${acceptUrl}\n\nThis invitation expires in 7 days.`,
  };
}


