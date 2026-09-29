import { describe, expect, it } from "vitest";
import { resolveAppUrl } from "../lib/validate";

const prodEnv = {
    ALLOWED_APP_URLS: "https://skillpassport.rareminds.in,https://*.rareminds.in,https://*.pages.dev,http://localhost:3000,http://localhost:8788",
    SKILLPASSPORT_URL: "https://skillpassport.rareminds.in",
};

describe("resolveAppUrl — unit tests", () => {
    it("no redirect + SKILLPASSPORT_URL set → returns canonical URL", () => {
        expect(resolveAppUrl(undefined, prodEnv)).toBe("https://skillpassport.rareminds.in");
    });

    it("no redirect + SKILLPASSPORT_URL has trailing slash → strips it", () => {
        const env = { ...prodEnv, SKILLPASSPORT_URL: "https://skillpassport.rareminds.in/" };
        expect(resolveAppUrl(undefined, env)).toBe("https://skillpassport.rareminds.in");
    });

    it("no redirect + SKILLPASSPORT_URL absent → throws correct error", () => {
        const env = { ALLOWED_APP_URLS: prodEnv.ALLOWED_APP_URLS };
        expect(() => resolveAppUrl(undefined, env)).toThrow(
            "SKILLPASSPORT_URL is required for email delivery",
        );
    });

    it("explicit redirect in allowlist → returns that URL, not SKILLPASSPORT_URL", () => {
        const result = resolveAppUrl("https://skillpassport.rareminds.in", prodEnv);
        expect(result).toBe("https://skillpassport.rareminds.in");
    });

    it("explicit redirect NOT in allowlist → throws allowlist-rejection error", () => {
        expect(() => resolveAppUrl("https://evil.com", prodEnv)).toThrow(
            "redirect_url",
        );
    });

    it("ALLOWED_APP_URLS missing when redirect provided → throws configuration error", () => {
        const env = { SKILLPASSPORT_URL: "https://skillpassport.rareminds.in" };
        expect(() => resolveAppUrl("https://skillpassport.rareminds.in", env)).toThrow(
            "ALLOWED_APP_URLS is required when redirect_url is provided",
        );
    });

    it("trailing slash on explicit redirect_url → stripped in return value", () => {
        const result = resolveAppUrl("https://skillpassport.rareminds.in/", prodEnv);
        expect(result).toBe("https://skillpassport.rareminds.in");
    });

    it("wildcard pattern match with explicit redirect_url → matched URL returned", () => {
        const result = resolveAppUrl("https://my-branch.rareminds.in", prodEnv);
        expect(result).toBe("https://my-branch.rareminds.in");
    });

    it("dev environment: SKILLPASSPORT_URL=localhost:8788, no redirect → returns localhost:8788", () => {
        const devEnv = {
            ALLOWED_APP_URLS: "http://localhost:8788,http://localhost:3000",
            SKILLPASSPORT_URL: "http://localhost:8788",
        };
        expect(resolveAppUrl(undefined, devEnv)).toBe("http://localhost:8788");
    });
});
