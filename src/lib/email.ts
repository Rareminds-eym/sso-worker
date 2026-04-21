import type { Env } from "../types";
import { escapeHtmlAttr, escapeHrefAttr } from "./escape";

export interface EmailPayload {
  to: string;
  subject: string;
  html: string;
  text: string;
}

/**
 * Send an email via the email-worker service binding.
 *
 * Non-blocking — designed to be called inside ctx.waitUntil().
 * Errors are logged but never thrown to avoid blocking the HTTP response.
 */
export async function sendEmail(env: Env, payload: EmailPayload): Promise<void> {
  try {
    const res = await env.EMAIL_SERVICE.fetch(
      new Request("https://internal/send", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-Internal-Api-Key": env.EMAIL_API_KEY,
        },
        body: JSON.stringify({
          to: payload.to,
          subject: payload.subject,
          html: payload.html,
          text: payload.text,
        }),
      }),
    );
    if (!res.ok) {
      const err = await res.text().catch(() => "unknown");
      console.error(`[SSO] Email delivery failed: ${res.status} ${err}`);
    }
  } catch (err) {
    console.error("[SSO] Email delivery error:", err);
  }
}

/** Build a password reset email */
export function passwordResetEmail(resetUrl: string): { subject: string; html: string; text: string } {
  return {
    subject: "Reset your password",
    html: `
      <p>You requested a password reset. Click the link below to set a new password:</p>
      <p><a href="${escapeHrefAttr(resetUrl)}">Reset Password</a></p>
      <p>This link expires in 1 hour. If you didn't request this, you can safely ignore this email.</p>
    `.trim(),
    text: `You requested a password reset. Click the link below to set a new password:\n${resetUrl}\n\nThis link expires in 1 hour. If you didn't request this, you can safely ignore this email.`,
  };
}

/** Build an email verification email */
export function verificationEmail(verifyUrl: string): { subject: string; html: string; text: string } {
  return {
    subject: "Verify your email address",
    html: `
      <p>Please verify your email address by clicking the link below:</p>
      <p><a href="${escapeHrefAttr(verifyUrl)}">Verify Email</a></p>
      <p>This link expires in 24 hours.</p>
    `.trim(),
    text: `Please verify your email address by clicking the link below:\n${verifyUrl}\n\nThis link expires in 24 hours.`,
  };
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
