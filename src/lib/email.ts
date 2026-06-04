import type { Env } from "../types";
import { escapeHtmlAttr, escapeHrefAttr } from "./escape";

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
      const err = await res.text().catch(() => "Response body unreadable");
      console.error(`[SSO] Email delivery failed: ${res.status} ${err}`);
    }
  } catch (err) {
    console.error("[SSO] Email delivery error:", err);
  }
}



/**
 * Send email verification - fetches template via SkillPassport service binding
 */
export async function sendVerificationEmail(
  env: Env,
  to: string,
  verifyUrl: string,
): Promise<void> {
  try {
    if (!env.SKILLPASSPORT_SERVICE) {
      throw new Error('SKILLPASSPORT_SERVICE binding is not configured');
    }

    const templateResponse = await env.SKILLPASSPORT_SERVICE.fetch(
      new Request('https://internal/api/email/verification', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ 
          to, 
          verifyUrl,
          templateOnly: true 
        }),
      })
    );

    if (!templateResponse.ok) {
      const errorText = await templateResponse.text().catch(() => "Response body unreadable");
      throw new Error(`Failed to fetch verification email template from SkillPassport service: ${templateResponse.status} ${templateResponse.statusText} - ${errorText}`);
    }

    const rawData = await templateResponse.json();

    const validated = rawData as JsonObject;
    if (!isValidEmailTemplate(validated)) {
      throw new Error('Invalid template response structure from SkillPassport service');
    }

    const templateData: EmailTemplate = validated;
    
    // Send email via service binding to email-worker
    await sendEmail(env, { 
      to, 
      subject: templateData.subject, 
      html: templateData.html, 
      text: templateData.text 
    });
  } catch (error) {
    console.error(`[SSO] Failed to send verification email:`, error);
    throw new Error(`Email verification failed: ${error instanceof Error ? error.message : String(error)}`);
  }
}

/**
 * Send password reset - fetches template via SkillPassport service binding
 */
export async function sendPasswordResetEmail(
  env: Env,
  to: string,
  resetUrl: string,
): Promise<void> {
  try {
    if (!env.SKILLPASSPORT_SERVICE) {
      throw new Error('SKILLPASSPORT_SERVICE binding is not configured');
    }

    const templateResponse = await env.SKILLPASSPORT_SERVICE.fetch(
      new Request('https://internal/api/email/password-reset', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ 
          to, 
          resetUrl,
          templateOnly: true 
        }),
      })
    );

    if (!templateResponse.ok) {
      const errorText = await templateResponse.text().catch(() => "Response body unreadable");
      throw new Error(`Failed to fetch password reset email template from SkillPassport service: ${templateResponse.status} ${templateResponse.statusText} - ${errorText}`);
    }

    const rawData = await templateResponse.json();

    const validated = rawData as JsonObject;
    if (!isValidEmailTemplate(validated)) {
      throw new Error('Invalid template response structure from SkillPassport service');
    }

    const templateData: EmailTemplate = validated;
    
    // Send email via service binding to email-worker
    await sendEmail(env, { 
      to, 
      subject: templateData.subject, 
      html: templateData.html, 
      text: templateData.text 
    });
  } catch (error) {
    console.error(`[SSO] Failed to send password reset email:`, error);
    throw new Error(`Password reset email failed: ${error instanceof Error ? error.message : String(error)}`);
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


