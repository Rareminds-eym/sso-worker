import { error } from "./response";

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const PASSWORD_MIN = 8;
const PASSWORD_MAX = 72; // bcrypt silently truncates at 72 bytes

/** Validate email format. Returns an error Response or null if valid. */
export function validateEmail(email: unknown): Response | null {
  if (typeof email !== "string" || !EMAIL_RE.test(email)) {
    return error("Invalid email format");
  }
  return null;
}

/** Validate password strength. Returns an error Response or null if valid. */
export function validatePassword(password: unknown): Response | null {
  if (typeof password !== "string") {
    return error("Password is required");
  }
  if (password.length < PASSWORD_MIN) {
    return error(`Password must be at least ${PASSWORD_MIN} characters`);
  }
  if (password.length > PASSWORD_MAX) {
    return error(`Password must be at most ${PASSWORD_MAX} characters`);
  }
  return null;
}
