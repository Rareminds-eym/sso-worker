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

/**
 * Send email verification using SkillPassport's beautiful template
 * Falls back to simple template if SkillPassport API is not available
 * 
 * Retries up to 3 times with exponential backoff to handle timing issues
 * during startup when the Pages function might not be ready yet.
 */
export async function sendVerificationEmail(
  env: Env,
  to: string,
  verifyUrl: string,
): Promise<void> {
  const skillpassportApiUrl = env.SKILLPASSPORT_API_URL || 'https://skillpassport.rareminds.in';
  const maxRetries = 3;
  
  // Try multiple times with exponential backoff
  for (let attempt = 1; attempt <= maxRetries; attempt++) {
    try {
      console.log(`[SSO] Attempt ${attempt}/${maxRetries}: Sending verification via SkillPassport: ${skillpassportApiUrl}/api/email/verification`);
      
      const res = await fetch(`${skillpassportApiUrl}/api/email/verification`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ to, verifyUrl }),
      });

      if (res.ok) {
        console.log('[SSO] Verification email sent via SkillPassport template ✅');
        return;
      } else {
        const errorText = await res.text().catch(() => 'unknown');
        console.warn(`[SSO] SkillPassport template API failed (${res.status}): ${errorText}`);
        
        // Don't retry on 4xx errors (client errors)
        if (res.status >= 400 && res.status < 500) {
          console.warn('[SSO] Client error, skipping retries');
          break;
        }
      }
    } catch (err) {
      console.warn(`[SSO] SkillPassport template API error (attempt ${attempt}/${maxRetries}):`, err);
    }
    
    // Wait before retrying (exponential backoff: 100ms, 200ms, 400ms)
    if (attempt < maxRetries) {
      const delay = 100 * Math.pow(2, attempt - 1);
      console.log(`[SSO] Waiting ${delay}ms before retry...`);
      await new Promise(resolve => setTimeout(resolve, delay));
    }
  }

  // Fallback to simple inline template after all retries
  console.log('[SSO] All retries exhausted, using simple verification template (fallback)');
  const { subject, html, text } = verificationEmail(verifyUrl);
  await sendEmail(env, { to, subject, html, text });
}

/**
 * Send password reset using SkillPassport's beautiful template
 * Falls back to simple template if SkillPassport API is not available
 * 
 * Retries up to 3 times with exponential backoff to handle timing issues.
 */
export async function sendPasswordResetEmail(
  env: Env,
  to: string,
  resetUrl: string,
): Promise<void> {
  console.error('=== PASSWORD RESET EMAIL FUNCTION CALLED ===');
  console.error('Environment check:', {
    hasSkillpassportUrl: !!env.SKILLPASSPORT_API_URL,
    skillpassportUrl: env.SKILLPASSPORT_API_URL || 'NOT SET (will use default)',
    to,
    resetUrl
  });
  
  const skillpassportApiUrl = env.SKILLPASSPORT_API_URL || 'https://skillpassport.rareminds.in';
  const maxRetries = 3;
  
  // Try multiple times with exponential backoff
  for (let attempt = 1; attempt <= maxRetries; attempt++) {
    try {
      console.error(`Attempt ${attempt}/${maxRetries}: Sending password reset via SkillPassport: ${skillpassportApiUrl}/api/email/password-reset`);
      
      const res = await fetch(`${skillpassportApiUrl}/api/email/password-reset`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ to, resetUrl }),
      });

      console.error(`SkillPassport API response status: ${res.status}`);

      if (res.ok) {
        console.error('Password reset email sent via SkillPassport template ✅');
        return;
      } else {
        const errorText = await res.text().catch(() => 'unknown');
        console.warn(`SkillPassport template API failed (${res.status}): ${errorText}`);
        
        // Don't retry on 4xx errors (client errors)
        if (res.status >= 400 && res.status < 500) {
          console.warn('Client error, skipping retries');
          break;
        }
      }
    } catch (err) {
      console.error(`SkillPassport template API error (attempt ${attempt}/${maxRetries}):`, err);
    }
    
    // Wait before retrying (exponential backoff: 100ms, 200ms, 400ms)
    if (attempt < maxRetries) {
      const delay = 100 * Math.pow(2, attempt - 1);
      console.error(`Waiting ${delay}ms before retry...`);
      await new Promise(resolve => setTimeout(resolve, delay));
    }
  }

  // Fallback to simple inline template after all retries
  console.error('All retries exhausted, using simple password reset template (fallback)');
  const { subject, html, text } = passwordResetEmail(resetUrl);
  await sendEmail(env, { to, subject, html, text });
}

/**
 * Send welcome email using SkillPassport's beautiful template
 * Falls back to simple template if SkillPassport API is not available
 * 
 * Retries up to 3 times with exponential backoff to handle timing issues.
 */
export async function sendWelcomeEmail(
  env: Env,
  to: string,
  name: string,
  role: string,
  baseUrl: string,
): Promise<void> {
  const skillpassportApiUrl = env.SKILLPASSPORT_API_URL || 'https://skillpassport.rareminds.in';
  const maxRetries = 3;
  
  // Try multiple times with exponential backoff
  for (let attempt = 1; attempt <= maxRetries; attempt++) {
    try {
      console.log(`[SSO] Attempt ${attempt}/${maxRetries}: Sending welcome email via SkillPassport: ${skillpassportApiUrl}/api/email/welcome`);
      
      const res = await fetch(`${skillpassportApiUrl}/api/email/welcome`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ to, name, role, baseUrl }),
      });

      if (res.ok) {
        console.log('[SSO] Welcome email sent via SkillPassport template ✅');
        return;
      } else {
        const errorText = await res.text().catch(() => 'unknown');
        console.warn(`[SSO] SkillPassport welcome API failed (${res.status}): ${errorText}`);
        
        // Don't retry on 4xx errors (client errors)
        if (res.status >= 400 && res.status < 500) {
          console.warn('[SSO] Client error, skipping retries');
          break;
        }
      }
    } catch (err) {
      console.warn(`[SSO] SkillPassport welcome API error (attempt ${attempt}/${maxRetries}):`, err);
    }
    
    // Wait before retrying (exponential backoff: 100ms, 200ms, 400ms)
    if (attempt < maxRetries) {
      const delay = 100 * Math.pow(2, attempt - 1);
      console.log(`[SSO] Waiting ${delay}ms before retry...`);
      await new Promise(resolve => setTimeout(resolve, delay));
    }
  }

  // Fallback to simple inline template after all retries
  console.log('[SSO] All retries exhausted, using simple welcome template (fallback)');
  const subject = "Welcome to SkillPassport!";
  const html = `
    <p>Hello ${name},</p>
    <p>Welcome to SkillPassport! Your account has been created successfully.</p>
    <p><a href="${baseUrl}/login">Login now</a></p>
  `.trim();
  const text = `Hello ${name},\n\nWelcome to SkillPassport! Your account has been created successfully.\n\nLogin: ${baseUrl}/login`;
  
  await sendEmail(env, { to, subject, html, text });
}

/** Build a password reset email (simple fallback template) */
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

/** Build an email verification email (simple fallback template) */
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
