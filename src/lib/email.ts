import type { Env } from "../types";
import { escapeHrefAttr, escapeHtmlAttr } from "./escape";

export interface EmailPayload {
  to: string;
  subject: string;
  html: string;
  text: string;
}

interface EmailTemplate {
  html: string;
  subject: string;
  text: string;
  [key: string]: JsonPrimitive | JsonObject | JsonArray;
}

type JsonPrimitive = string | number | boolean | null;
type JsonObject = { [key: string]: JsonPrimitive | JsonObject | JsonArray };
type JsonArray = (JsonPrimitive | JsonObject | JsonArray)[];

/**
 * Type guard to validate email template structure
 */
function isValidEmailTemplate(data: JsonObject): data is EmailTemplate {
  return (
    typeof data === 'object' &&
    data !== null &&
    !Array.isArray(data) &&
    'html' in data &&
    'subject' in data &&
    'text' in data &&
    typeof data.html === 'string' &&
    typeof data.subject === 'string' &&
    typeof data.text === 'string'
  );
}

/**
 * Send an email via the email-worker service binding.
 *
 * Non-blocking — designed to be called inside ctx.waitUntil().
 * Errors are logged but never thrown to avoid blocking the HTTP response.
 */
export async function sendEmail(env: Env, payload: EmailPayload): Promise<void> {
  try {
    const res = await env.EMAIL_SERVICE.sendEmail({
      to: payload.to,
      subject: payload.subject,
      html: payload.html,
      text: payload.text,
    });
    if (!res.success) {
      console.error(`[SSO] Email delivery failed: ${res.errorCode} ${res.error}`);
    }
  } catch (err) {
    console.error("[SSO] Email delivery error:", err);
  }
}




/**
 * Send welcome email using simple template
 */
export async function sendWelcomeEmail(
  env: Env,
  to: string,
  name: string,
  baseUrl: string,
): Promise<void> {
  try {
    const subject = "Welcome to SkillPassport!";
    const html = `
      <p>Hello ${escapeHtmlAttr(name)},</p>
      <p>Welcome to SkillPassport! Your account has been created successfully.</p>
      <p><a href="${escapeHrefAttr(baseUrl)}/login">Login now</a></p>
    `.trim();
    const text = `Hello ${name},\n\nWelcome to SkillPassport! Your account has been created successfully.\n\nLogin: ${baseUrl}/login`;

    await sendEmail(env, { to, subject, html, text });
  } catch (error) {
    console.error(`[SSO] Failed to send welcome email:`, error);
    throw new Error(`Welcome email failed: ${error instanceof Error ? error.message : String(error)}`);
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


