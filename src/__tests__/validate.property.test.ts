import fc from "fast-check";
import { describe, expect, it } from "vitest";
import { resolveAppUrl } from "../lib/validate";

describe("resolveAppUrl — bug condition exploration", () => {
    /**
     * Property 1: BUG CONDITION — resolveAppUrl with no redirectUrl MUST return SKILLPASSPORT_URL
     *
     * This test is EXPECTED TO FAIL on unfixed code.
     * Failure proves the bug exists: resolveAppUrl returns the first ALLOWED_APP_URLS entry
     * (localhost) instead of SKILLPASSPORT_URL.
     *
     * Validates: Requirements 1.1, 1.2, 1.3, 1.4, 2.1, 2.2, 2.3, 2.4
     */
    it("P1: returns SKILLPASSPORT_URL (not localhost) when redirectUrl is undefined", () => {
        // Concrete counterexample first
        const env = {
            ALLOWED_APP_URLS: "http://localhost:3000,https://skillpassport.rareminds.in",
            SKILLPASSPORT_URL: "https://skillpassport.rareminds.in",
        };
        const result = resolveAppUrl(undefined, env);
        expect(result).toBe("https://skillpassport.rareminds.in");
        expect(result).not.toMatch(/^http:\/\/localhost/);
    });

    it("P1-b: returns SKILLPASSPORT_URL for various canonical URL values", () => {
        fc.assert(
            fc.property(
                fc.constantFrom(
                    "https://skillpassport.rareminds.in",
                    "https://skillpassport.rareminds.in/",
                    "https://courses.rareminds.in",
                    "http://localhost:8788",
                ),
                (skillpassportUrl) => {
                    const env = {
                        ALLOWED_APP_URLS: "http://localhost:3000,https://skillpassport.rareminds.in",
                        SKILLPASSPORT_URL: skillpassportUrl,
                    };
                    const result = resolveAppUrl(undefined, env);
                    const expected = skillpassportUrl.replace(/\/+$/, "");
                    expect(result).toBe(expected);
                },
            ),
        );
    });

    it("P1-c (secondary bug): returns localhost silently when SKILLPASSPORT_URL absent (should throw)", () => {
        // Documents secondary bug: no explicit error thrown when SKILLPASSPORT_URL is absent
        const env = {
            ALLOWED_APP_URLS: "http://localhost:3000",
            // SKILLPASSPORT_URL: deliberately absent
        };
        // On unfixed code: returns "http://localhost:3000" silently instead of throwing
        // On fixed code: throws "SKILLPASSPORT_URL is required for email delivery"
        try {
            const result = resolveAppUrl(undefined, env);
            // If we reach here, the function did NOT throw — document this as the buggy behavior
            expect(result).toBe("http://localhost:3000"); // documents current (wrong) behavior
            // Mark as counterexample
            throw new Error(`Bug confirmed: resolveAppUrl returned "${result}" instead of throwing`);
        } catch (e: any) {
            if (e.message.includes("Bug confirmed")) throw e;
            // If it throws with the correct message, the fix is in place
            expect(e.message).toContain("SKILLPASSPORT_URL is required for email delivery");
        }
    });
});

describe("resolveAppUrl — preservation (explicit redirectUrl)", () => {
    /**
     * Property 2: PRESERVATION — explicit redirect_url in ALLOWED_APP_URLS is returned unchanged
     *
     * These tests SHOULD PASS on unfixed code (establishes baseline behavior to preserve).
     *
     * Validates: Requirements 3.1, 3.2, 3.3, 3.4, 3.6, 3.7
     */
    it("P2: explicit exact-match redirect_url returned unchanged", () => {
        fc.assert(
            fc.property(
                fc.constantFrom(
                    "https://skillpassport.rareminds.in",
                    "https://courses.rareminds.in",
                    "http://localhost:3000",
                    "http://localhost:8788",
                ),
                (redirectUrl) => {
                    const env = {
                        ALLOWED_APP_URLS: `${redirectUrl},https://extra.rareminds.in`,
                        SKILLPASSPORT_URL: "https://skillpassport.rareminds.in",
                    };
                    const result = resolveAppUrl(redirectUrl, env);
                    expect(result).toBe(redirectUrl.replace(/\/+$/, ""));
                },
            ),
        );
    });

    it("P2-b: trailing slash on explicit redirect_url is stripped", () => {
        const result = resolveAppUrl("https://skillpassport.rareminds.in/", {
            ALLOWED_APP_URLS: "https://skillpassport.rareminds.in",
            SKILLPASSPORT_URL: "https://skillpassport.rareminds.in",
        });
        expect(result).toBe("https://skillpassport.rareminds.in");
    });

    it("P2-c: wildcard pattern match — explicit redirect_url returned unchanged", () => {
        const result = resolveAppUrl("https://my-branch.rareminds.in", {
            ALLOWED_APP_URLS: "https://skillpassport.rareminds.in,https://*.rareminds.in",
            SKILLPASSPORT_URL: "https://skillpassport.rareminds.in",
        });
        expect(result).toBe("https://my-branch.rareminds.in");
    });

    it("P2-d: dev environment — SKILLPASSPORT_URL=localhost:8788, no redirect", () => {
        // After fix: returns SKILLPASSPORT_URL (http://localhost:8788), dev experience preserved
        const env = {
            ALLOWED_APP_URLS: "http://localhost:8788,http://localhost:3000",
            SKILLPASSPORT_URL: "http://localhost:8788",
        };
        const result = resolveAppUrl(undefined, env);
        expect(result).toBe("http://localhost:8788");
    });

    it("P2-e: explicit redirect NOT in allowlist throws", () => {
        expect(() =>
            resolveAppUrl("https://evil.com", {
                ALLOWED_APP_URLS: "https://skillpassport.rareminds.in",
                SKILLPASSPORT_URL: "https://skillpassport.rareminds.in",
            }),
        ).toThrow();
    });
});
