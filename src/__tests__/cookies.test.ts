import { describe, expect, it } from 'vitest';
import { refreshCookie, clearRefreshCookie, getCookie, COOKIE_BASE_ATTRS, REFRESH_MAX_AGE } from '../lib/cookies';
import type { CookieConfig } from '../lib/cookies';

const TOKEN = 'test-refresh-token-value';
const MAX_AGE = 3600;

function parseSetCookie(value: string): Record<string, string> {
  const parts = value.split(';').map(p => p.trim());
  const [nameVal, ...attrs] = parts;
  const eqIdx = nameVal.indexOf('=');
  const name = eqIdx === -1 ? nameVal : nameVal.slice(0, eqIdx);
  const val = eqIdx === -1 ? '' : nameVal.slice(eqIdx + 1);
  const map: Record<string, string> = { name, val };
  for (const attr of attrs) {
    const a = attr.split('=').map(s => s.trim());
    map[a[0].toLowerCase()] = a[1] ?? 'true';
  }
  return map;
}

describe('refreshCookie', () => {
  it('uses __Secure- prefix with cross-subdomain Domain', () => {
    const cfg: CookieConfig = { domain: '.rareminds.in' };
    const result = refreshCookie(TOKEN, MAX_AGE, cfg);
    expect(result).toContain('__Secure-refresh_token=');
    expect(result).toContain('Secure');
    expect(result).toContain('SameSite=None');
    expect(result).toContain('Domain=.rareminds.in');
    expect(result).toContain('Path=/');
    expect(result).toContain('HttpOnly');
  });

  it('uses __Host- prefix when no Domain (host-only)', () => {
    const cfg: CookieConfig = {};
    const result = refreshCookie(TOKEN, MAX_AGE, cfg);
    expect(result).toContain('__Host-refresh_token=');
    expect(result).toContain('Secure');
    expect(result).toContain('SameSite=None');
    expect(result).not.toContain('Domain=');
    expect(result).toContain('Path=/');
  });

  it('omits prefixes in dev mode (no Secure flag)', () => {
    const cfg: CookieConfig = { environment: 'dev' };
    const result = refreshCookie(TOKEN, MAX_AGE, cfg);
    expect(result).toContain('refresh_token=');
    expect(result).not.toContain('__Secure-refresh_token');
    expect(result).not.toContain('__Host-refresh_token');
    expect(result).not.toContain('Secure');
    expect(result).toContain('SameSite=Lax');
  });

  it('omits prefix in dev mode even with domain', () => {
    const cfg: CookieConfig = { domain: '.rareminds.in', environment: 'dev' };
    const result = refreshCookie(TOKEN, MAX_AGE, cfg);
    expect(result).toContain('refresh_token=');
    expect(result).not.toContain('__Secure-refresh_token');
    expect(result).not.toContain('Secure');
    expect(result).toContain('SameSite=Lax');
    expect(result).toContain('Domain=.rareminds.in');
  });

  it('produces parsable Set-Cookie value', () => {
    const cfg: CookieConfig = { domain: '.test.com' };
    const result = refreshCookie(TOKEN, MAX_AGE, cfg);
    const parsed = parseSetCookie(result);
    expect(parsed.name).toBe('__Secure-refresh_token');
    expect(parsed.val).toBe(TOKEN);
    expect(parsed.domain).toBe('.test.com');
    expect(parsed.path).toBe('/');
    expect(parsed['max-age']).toBe(String(MAX_AGE));
  });
});

describe('clearRefreshCookie', () => {
  it('matches prefix of the set cookie with domain', () => {
    const cfg: CookieConfig = { domain: '.rareminds.in' };
    const result = clearRefreshCookie(cfg);
    expect(result).toContain('__Secure-refresh_token=');
    expect(result).toContain('Max-Age=0');
    expect(result).toContain('Domain=.rareminds.in');
  });

  it('matches prefix of the set cookie without domain', () => {
    const cfg: CookieConfig = {};
    const result = clearRefreshCookie(cfg);
    expect(result).toContain('__Host-refresh_token=');
    expect(result).toContain('Max-Age=0');
    expect(result).not.toContain('Domain=');
  });

  it('unprefixed in dev mode', () => {
    const cfg: CookieConfig = { environment: 'dev' };
    const result = clearRefreshCookie(cfg);
    expect(result).toContain('refresh_token=');
    expect(result).not.toContain('__Secure-refresh_token');
    expect(result).not.toContain('__Host-refresh_token');
  });
});

describe('getCookie', () => {
  const makeRequest = (cookie: string): Request =>
    new Request('http://localhost', { headers: { Cookie: cookie } });

  it('finds bare refresh_token', () => {
    const req = makeRequest('refresh_token=abc123; other=val');
    expect(getCookie(req, 'refresh_token')).toBe('abc123');
  });

  it('finds __Secure- prefixed refresh_token', () => {
    const req = makeRequest('__Secure-refresh_token=abc123; other=val');
    expect(getCookie(req, 'refresh_token')).toBe('abc123');
  });

  it('finds __Host- prefixed refresh_token', () => {
    const req = makeRequest('__Host-refresh_token=abc123');
    expect(getCookie(req, 'refresh_token')).toBe('abc123');
  });

  it('prefers __Secure- over bare when both present', () => {
    const req = makeRequest('refresh_token=old; __Secure-refresh_token=new');
    expect(getCookie(req, 'refresh_token')).toBe('new');
  });

  it('prefers __Host- over __Secure- and bare', () => {
    const req = makeRequest('refresh_token=old; __Secure-refresh_token=newer; __Host-refresh_token=newest');
    expect(getCookie(req, 'refresh_token')).toBe('newest');
  });

  it('returns null when no variant present', () => {
    const req = makeRequest('other=val');
    expect(getCookie(req, 'refresh_token')).toBeNull();
  });

  it('returns null on empty Cookie header', () => {
    const req = makeRequest('');
    expect(getCookie(req, 'refresh_token')).toBeNull();
  });

  it('handles whitespace around cookie parts', () => {
    const req = makeRequest('  __Secure-refresh_token=abc123 ; other=val');
    expect(getCookie(req, 'refresh_token')).toBe('abc123');
  });

  it('does not match partial names', () => {
    const req = makeRequest('__Secure-refresh_token_old=abc123; refresh_token=real');
    expect(getCookie(req, 'refresh_token')).toBe('real');
  });
});
