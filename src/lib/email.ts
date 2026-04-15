import type { Env } from "../types";

interface EmailPayload {
  to: string;
  subject: string;
  html: string;
}

/**
 * Send an email via the configured provider.
 *
 * Currently logs to console. Replace the body of this function
 * with your Amazon SES integration when ready.
 *
 * Non-blocking — designed to be called inside ctx.waitUntil().
 */
export async function sendEmail(_env: Env, payload: EmailPayload): Promise<void> {
  // TODO: Replace with Amazon SES integration
  console.log(
    `[SSO] Email → ${payload.to} | Subject: ${payload.subject}`,
  );
}

/** Build a password reset email */
export function passwordResetEmail(resetUrl: string): { subject: string; html: string } {
  return {
    subject: "Reset your password",
    html: `
      <p>You requested a password reset. Click the link below to set a new password:</p>
      <p><a href="${resetUrl}">${resetUrl}</a></p>
      <p>This link expires in 1 hour. If you didn't request this, you can safely ignore this email.</p>
    `.trim(),
  };
}

/** Build an email verification email */
export function verificationEmail(verifyUrl: string): { subject: string; html: string } {
  return {
    subject: "Verify your email address",
    html: `
      <p>Please verify your email address by clicking the link below:</p>
      <p><a href="${verifyUrl}">${verifyUrl}</a></p>
      <p>This link expires in 24 hours.</p>
    `.trim(),
  };
}

/** Build an invite email */
export function inviteEmail(
  inviterEmail: string,
  orgName: string,
  acceptUrl: string,
): { subject: string; html: string } {
  return {
    subject: `You've been invited to ${orgName}`,
    html: `
      <p>${inviterEmail} has invited you to join <strong>${orgName}</strong>.</p>
      <p><a href="${acceptUrl}">Accept Invitation</a></p>
      <p>This invitation expires in 7 days.</p>
    `.trim(),
  };
}
