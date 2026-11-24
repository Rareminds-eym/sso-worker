import configuration from '../../../config/subscriptions/catalog-audiences.json';
import type { CatalogOwnerInputs } from './catalog-owner-inputs';
import { invalid, record, text } from './validation';

export interface CatalogAudienceConfiguration {
  readonly platformOrganizationAudience: string;
  /** organizations.metadata.organization_type -> catalog audience */
  readonly organizationTypes: ReadonlyMap<string, string>;
}

export function validateCatalogAudiences(value: unknown, inputs: CatalogOwnerInputs): CatalogAudienceConfiguration {
  const input = record(value, 'catalogAudiences', ['schemaVersion', 'source', 'platformOrganizationAudience', 'organizationTypes']);
  if (input.schemaVersion !== 1) invalid('catalogAudiences.schemaVersion', 'unsupported schema version');
  text(input.source, 'catalogAudiences.source');
  const known = (audience: string, path: string) => { if (!inputs.audiences.has(audience)) invalid(path, 'unknown owner audience'); return audience; };
  const platformOrganizationAudience = known(text(input.platformOrganizationAudience, 'catalogAudiences.platformOrganizationAudience'), 'catalogAudiences.platformOrganizationAudience');
  const types = record(input.organizationTypes, 'catalogAudiences.organizationTypes',
    input.organizationTypes && typeof input.organizationTypes === 'object' ? Object.keys(input.organizationTypes) : []);
  const organizationTypes = new Map(Object.entries(types).map(([type, audience]) =>
    [text(type, 'catalogAudiences.organizationTypes'), known(text(audience, `catalogAudiences.organizationTypes.${type}`), `catalogAudiences.organizationTypes.${type}`)] as const));
  if (!organizationTypes.size) invalid('catalogAudiences.organizationTypes', 'explicit organization type mapping required');
  return Object.freeze({ platformOrganizationAudience, organizationTypes });
}
export function loadCatalogAudiences(inputs: CatalogOwnerInputs) { return validateCatalogAudiences(configuration, inputs); }

/**
 * The single audience whose published plans this actor may browse, or null when none applies.
 * The organization comes from the signed token and live owner row; roles are the live canonical roles.
 * No plan name, price or client hint participates.
 */
export function resolveCatalogAudience(organization: { metadata: unknown } | null, roles: readonly string[],
  inputs: CatalogOwnerInputs, config: CatalogAudienceConfiguration): string | null {
  if (!organization) return null;
  const metadata = organization.metadata && typeof organization.metadata === 'object' && !Array.isArray(organization.metadata)
    ? organization.metadata as Record<string, unknown> : {};
  const audience = metadata.is_platform_org === true ? config.platformOrganizationAudience
    : typeof metadata.organization_type === 'string' ? config.organizationTypes.get(metadata.organization_type) ?? null : null;
  if (!audience) return null;
  const owner = inputs.audiences.get(audience);
  return owner && roles.some(role => owner.managerRoles.includes(role) || owner.memberRoles.includes(role)) ? audience : null;
}
