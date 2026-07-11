import { escapeHrefAttr } from "./escape";

export function generateVerificationEmailTemplate(verifyUrl: string) {
  return {
    subject: 'Verify your email',
    html: `
      <!DOCTYPE html>
      <html>
        <head>
          <meta charset="UTF-8">
          <meta name="viewport" content="width=device-width, initial-scale=1.0">
          <title>Verify your email</title>
        </head>
        <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
          <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
            <h2 style="color: #2563eb;">Welcome to SkillPassport</h2>
            <p>Thank you for signing up! Please verify your email address by clicking the button below:</p>
            <div style="text-align: center; margin: 30px 0;">
              <a href="${escapeHrefAttr(verifyUrl)}" style="background-color: #2563eb; color: white; padding: 12px 24px; text-decoration: none; border-radius: 4px; display: inline-block;">Verify Email</a>
            </div>
            <p>Or copy and paste this link into your browser:</p>
            <p style="word-break: break-all; color: #666;">${verifyUrl}</p>
            <p style="margin-top: 30px; font-size: 14px; color: #666;">This link will expire in 24 hours.</p>
          </div>
        </body>
      </html>
    `,
    text: `Welcome to SkillPassport!

Please verify your email address by visiting:
${verifyUrl}

This link will expire in 24 hours.`,
  };
}

export function generatePasswordResetEmailTemplate(resetUrl: string) {
  return {
    subject: 'Reset your password',
    html: `
      <!DOCTYPE html>
      <html>
        <head>
          <meta charset="UTF-8">
          <meta name="viewport" content="width=device-width, initial-scale=1.0">
          <title>Reset your password</title>
        </head>
        <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
          <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
            <h2 style="color: #2563eb;">Reset your password</h2>
            <p>We received a request to reset your password. Click the button below to reset it:</p>
            <div style="text-align: center; margin: 30px 0;">
              <a href="${escapeHrefAttr(resetUrl)}" style="background-color: #2563eb; color: white; padding: 12px 24px; text-decoration: none; border-radius: 4px; display: inline-block;">Reset Password</a>
            </div>
            <p>Or copy and paste this link into your browser:</p>
            <p style="word-break: break-all; color: #666;">${resetUrl}</p>
            <p style="margin-top: 30px; font-size: 14px; color: #666;">This link will expire in 1 hour.</p>
            <p style="font-size: 14px; color: #666;">If you didn't request this password reset, please ignore this email.</p>
          </div>
        </body>
      </html>
    `,
    text: `Reset your password

We received a request to reset your password. Visit the link below to reset it:
${resetUrl}

This link will expire in 1 hour.

If you didn't request this password reset, please ignore this email.`
  };
}
