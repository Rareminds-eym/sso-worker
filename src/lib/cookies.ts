import { ACCESS_TOKEN_MAX_AGE, SESSION_TTL_MS } from "./constants";

const COOKIE_OPTIONS = "HttpOnly; Secure; Path=/; SameSite=None";
const REFRESH_MAX_AGE = Math.floor(SESSION_TTL_MS / 1000);

/** Set access + refresh token cookies on a Response */
export function setAuthCookies(
  res: Response,
  accessToken: string,
  refreshToken: string,
): void {
  res.headers.append(
    "Set-Cookie",
    `access_token=${accessToken}; ${COOKIE_OPTIONS}; Max-Age=${ACCESS_TOKEN_MAX_AGE}`,
  );
  res.headers.append(
    "Set-Cookie",
    `refresh_token=${refreshToken}; ${COOKIE_OPTIONS}; Max-Age=${REFRESH_MAX_AGE}`,
  );
}

/** Clear auth cookies — attributes must match the ones that set them */
export function clearCookies(res: Response): void {
  res.headers.append("Set-Cookie", `access_token=; Max-Age=0; ${COOKIE_OPTIONS}`);
  res.headers.append("Set-Cookie", `refresh_token=; Max-Age=0; ${COOKIE_OPTIONS}`);
}

/** Parse a specific cookie value from the Cookie header */
export function getCookie(req: Request, name: string): string | null {
  const header = req.headers.get("Cookie");
  if (!header) return null;

  for (const part of header.split(";")) {
    const trimmed = part.trim();
    // Exact name match: "name=" not "name_other="
    if (trimmed.startsWith(`${name}=`)) {
      const idx = trimmed.indexOf("=");
      return idx === -1 ? null : trimmed.slice(idx + 1).trim();
    }
  }
  return null;
}
