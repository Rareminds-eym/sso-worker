import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { resolveEffectiveRoles } from "../roles";

describe("resolveEffectiveRoles", () => {
  let consoleErrorSpy: any;
  let consoleWarnSpy: any;

  beforeEach(() => {
    consoleErrorSpy = vi.spyOn(console, "error").mockImplementation(() => {});
    consoleWarnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("should return authoritative claims roles if present", () => {
    const result = resolveEffectiveRoles({
      claims: { roles: ["admin", "editor"] },
      userMetadata: { role: "learner" },
      explicitRole: "owner",
    });
    expect(result).toEqual(["admin", "editor"]);
    expect(consoleErrorSpy).not.toHaveBeenCalled();
    expect(consoleWarnSpy).not.toHaveBeenCalled();
  });

  it("should prioritize explicitRole if claims is missing", () => {
    const result = resolveEffectiveRoles({
      claims: null,
      userMetadata: { role: "learner" },
      explicitRole: "owner",
    });
    expect(result).toEqual(["owner"]);
    expect(consoleErrorSpy).toHaveBeenCalledWith(
      expect.stringContaining("claims is null or undefined")
    );
  });

  it("should fall back to userMetadata role if claims is missing and explicitRole is absent", () => {
    const result = resolveEffectiveRoles({
      claims: null,
      userMetadata: { role: "college_admin" },
    });
    expect(result).toEqual(["college_admin"]);
    expect(consoleErrorSpy).toHaveBeenCalled();
  });

  it("should fall back to userMetadata roles array first element if claims is missing and role is absent", () => {
    const result = resolveEffectiveRoles({
      claims: undefined,
      userMetadata: { roles: ["school_admin", "learner"] },
    });
    expect(result).toEqual(["school_admin"]);
    expect(consoleErrorSpy).toHaveBeenCalled();
  });

  it("should fall back to fallbackRole if everything is missing", () => {
    const result = resolveEffectiveRoles({
      claims: null,
      fallbackRole: "member",
    });
    expect(result).toEqual(["member"]);
    expect(consoleErrorSpy).toHaveBeenCalled();
  });

  it("should default to learner fallback if fallbackRole is not provided and everything is missing", () => {
    const result = resolveEffectiveRoles({
      claims: null,
    });
    expect(result).toEqual(["learner"]);
    expect(consoleErrorSpy).toHaveBeenCalled();
  });

  it("should prioritize explicitRole if claims is present but empty", () => {
    const result = resolveEffectiveRoles({
      claims: { roles: [] },
      userMetadata: { role: "learner" },
      explicitRole: "owner",
    });
    expect(result).toEqual(["owner"]);
    expect(consoleWarnSpy).toHaveBeenCalledWith(
      expect.stringContaining("claims has no roles")
    );
  });

  it("should fall back to userMetadata role if claims is empty and explicitRole is absent", () => {
    const result = resolveEffectiveRoles({
      claims: { roles: [] },
      userMetadata: { role: "college_admin" },
    });
    expect(result).toEqual(["college_admin"]);
    expect(consoleWarnSpy).toHaveBeenCalled();
  });
});
