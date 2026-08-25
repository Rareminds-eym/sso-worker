/**
 * Resolves the effective roles for a user session, prioritizing claims from the DB,
 * then an explicit role (e.g. from a signup form), then role metadata from the user record,
 * and finally falling back to a default role.
 */
export function resolveEffectiveRoles(params: {
  claims?: { roles?: string[] } | null;
  userMetadata?: Record<string, unknown> | null;
  explicitRole?: string | null;
  fallbackRole?: string;
}): string[] {
  const fallback = params.fallbackRole ?? "learner";

  // Case 1: Claims is entirely null or undefined (e.g. RPC failure/empty)
  if (params.claims === undefined || params.claims === null) {
    console.error("[SSO] resolveEffectiveRoles: claims is null or undefined. get_jwt_claims RPC failed.");
    
    if (params.explicitRole) {
      return [params.explicitRole];
    }
    if (params.userMetadata) {
      const userRole = (params.userMetadata.role as string | undefined)
        ?? (params.userMetadata.roles as string[] | undefined)?.[0];
      if (userRole) {
        return [userRole];
      }
    }
    return [fallback];
  }

  // Case 2: Claims object is present, but roles array is empty or undefined
  if (!params.claims.roles || params.claims.roles.length === 0) {
    console.warn("[SSO] resolveEffectiveRoles: claims has no roles. Falling back to explicit or userMetadata role.");
    
    if (params.explicitRole) {
      return [params.explicitRole];
    }
    if (params.userMetadata) {
      const userRole = (params.userMetadata.role as string | undefined)
        ?? (params.userMetadata.roles as string[] | undefined)?.[0];
      if (userRole) {
        return [userRole];
      }
    }
    return [fallback];
  }

  // Case 3: Authoritative claims has roles
  return params.claims.roles;
}
