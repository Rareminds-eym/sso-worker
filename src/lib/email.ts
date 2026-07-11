import type { Env } from "../types";
import { escapeHrefAttr, escapeHtmlAttr } from "./escape";

export interface EmailPayload {
  to: string;
  subject: string;
  html: string;
  text: string;
}

const EMAIL_SEND_TIMEOUT_MS = 5_000;

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


