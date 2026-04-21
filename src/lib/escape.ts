/**
 * Output encoding utilities per OWASP XSS Prevention Cheat Sheet.
 *
 * For URL contexts (href, src attributes), OWASP requires:
 *   1. URL-encode the value first
 *   2. Then HTML-attribute-encode the result
 *
 * This double-encoding prevents both:
 *   - javascript: protocol injection (caught by URL encoding)
 *   - Attribute breakout via " or ' (caught by HTML-attr encoding)
 */

/** HTML attribute encoding — escapes &, <, >, ", ' */
export function escapeHtmlAttr(v: string): string {
  return v
    .replace(/&/g, "&amp;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#x27;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
}

/**
 * Combined encoding for href/src attributes per OWASP:
 * URL-encode first, then HTML-attribute-encode.
 */
export function escapeHrefAttr(v: string): string {
  return escapeHtmlAttr(encodeURIComponent(v));
}
