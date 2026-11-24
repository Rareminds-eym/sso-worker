import configuration from '../../../config/subscriptions/brd-catalog.json';
import { array, choice, integer, invalid, record, text } from './validation';

/** Source preparation only. These cells are neither FeatureGrant nor publication permission. */
export interface BrdCatalogCell {
  readonly row: number;
  readonly label: string;
  readonly text: string;
  readonly interpretation: 'source_only' | 'policy_required';
  readonly policyRequirement: string | null;
}

export interface BrdCatalogProfile {
  /** Source coordinates, never a canonical plan identity or executable tier name. */
  readonly reference: string;
  readonly section: number;
  readonly column: number;
  readonly displayName: string;
  readonly price: {
    readonly kind: 'fixed' | 'starting_at';
    readonly amountMinor: number;
    /** Free public prices do not specify a subscription duration. */
    readonly intervalUnit: 'month' | 'year' | null;
  };
  readonly cells: readonly BrdCatalogCell[];
}

export interface BrdRoleAvailability {
  readonly section: number;
  readonly interpretation: 'source_only';
  readonly audiences: readonly string[];
  readonly roles: readonly { readonly role: string; readonly terms: readonly string[] }[];
  readonly sharedSeatRows: readonly { readonly section: number; readonly row: number; readonly label: string; readonly roles: readonly string[] }[];
  readonly requiredOwnerInputs: readonly string[];
}

export interface BrdCatalog {
  readonly schemaVersion: 1;
  readonly purpose: 'configuration_preparation';
  readonly source: { readonly title: string; readonly version: string; readonly sections: readonly number[] };
  readonly currency: { readonly code: string; readonly minorUnit: number };
  readonly retainedOffer: {
    readonly displayName: string;
    readonly resolution: 'existing_owner_binding_required';
    readonly preserveHistory: true;
  };
  readonly profiles: readonly BrdCatalogProfile[];
  readonly roleAvailability: BrdRoleAvailability;
  readonly decisions: readonly {
    readonly reference: string;
    readonly area: string;
    readonly requirement: string;
    readonly status: 'policy_required';
  }[];
  readonly publicationRequirements: readonly string[];
}

function nonempty<T>(values: T[], path: string): readonly T[] {
  if (!values.length) invalid(path, 'expected non-empty configuration');
  return Object.freeze(values);
}

function unique(values: readonly (string | number)[], path: string): void {
  if (new Set(values).size !== values.length) invalid(path, 'duplicate configuration reference');
}

function cell(value: unknown, path: string, expectedRow: number): BrdCatalogCell {
  const input = record(value, path, ['row', 'label', 'text', 'interpretation', 'policyRequirement']);
  const row = integer(input.row, `${path}.row`, 1);
  if (row !== expectedRow) invalid(path, 'source rows must be complete and ordered');
  const interpretation = choice(input.interpretation, `${path}.interpretation`, ['source_only', 'policy_required']);
  const policyRequirement = interpretation === 'policy_required' ? text(input.policyRequirement, `${path}.policyRequirement`) : null;
  if (interpretation === 'source_only' && input.policyRequirement !== null) invalid(path, 'source-only cells require explicit null policy requirement');
  return Object.freeze({ row, label: text(input.label, `${path}.label`), text: text(input.text, `${path}.text`), interpretation, policyRequirement });
}

function profile(value: unknown, path: string, sections: readonly number[]): BrdCatalogProfile {
  const input = record(value, path, ['reference', 'section', 'column', 'displayName', 'price', 'cells']);
  const section = integer(input.section, `${path}.section`, 1);
  const column = integer(input.column, `${path}.column`, 1);
  if (!sections.includes(section)) invalid(path, 'unregistered source section');
  const reference = text(input.reference, `${path}.reference`);
  if (reference !== `brd:${section}:${column}`) invalid(path, 'source reference differs from coordinates');
  const priceInput = record(input.price, `${path}.price`, ['kind', 'amountMinor', 'intervalUnit']);
  const amountMinor = integer(priceInput.amountMinor, `${path}.price.amountMinor`);
  const intervalUnit = priceInput.intervalUnit === null ? null : choice(priceInput.intervalUnit, `${path}.price.intervalUnit`, ['month', 'year']);
  if (amountMinor > 0 && intervalUnit === null) invalid(path, 'paid public pricing requires its stated interval');
  const price = Object.freeze({ kind: choice(priceInput.kind, `${path}.price.kind`, ['fixed', 'starting_at']), amountMinor, intervalUnit });
  const cells = nonempty(array(input.cells, `${path}.cells`).map((value, index) => cell(value, `${path}.cells[${index}]`, index + 1)), `${path}.cells`);
  unique(cells.map(value => value.label), `${path}.cells`);
  return Object.freeze({ reference, section, column, displayName: text(input.displayName, `${path}.displayName`), price, cells });
}

/** Retain BRD commercial terms and shared source pools; this is not an RBAC grant. */
function roleAvailability(value: unknown, profiles: readonly BrdCatalogProfile[]): BrdRoleAvailability {
  const path = 'brdCatalog.roleAvailability';
  const input = record(value, path, ['section', 'interpretation', 'audiences', 'roles', 'sharedSeatRows', 'requiredOwnerInputs']);
  if (input.interpretation !== 'source_only') invalid(path, 'role source terms cannot grant permissions');
  const texts = (value: unknown, field: string) => Object.freeze(array(value, `${path}.${field}`)
    .map((entry, index) => text(entry, `${path}.${field}[${index}]`)));
  const audiences = texts(input.audiences, 'audiences');
  if (!audiences.length) invalid(path, 'audience columns required');
  unique(audiences, `${path}.audiences`);
  const roles = nonempty(array(input.roles, `${path}.roles`).map((value, index) => {
    const row = record(value, `${path}.roles[${index}]`, ['role', 'terms']);
    const terms = texts(row.terms, `roles[${index}].terms`);
    if (terms.length !== audiences.length) invalid(path, 'role row must cover every audience');
    return Object.freeze({ role: text(row.role, `${path}.roles[${index}].role`), terms });
  }), `${path}.roles`);
  unique(roles.map(row => row.role), `${path}.roles`);
  const sharedSeatRows = Object.freeze(array(input.sharedSeatRows, `${path}.sharedSeatRows`).map((value, index) => {
    const row = record(value, `${path}.sharedSeatRows[${index}]`, ['section', 'row', 'label', 'roles']);
    const section = integer(row.section, `${path}.sharedSeatRows.section`, 1);
    const sourceRow = integer(row.row, `${path}.sharedSeatRows.row`, 1);
    const label = text(row.label, `${path}.sharedSeatRows.label`);
    const members = texts(row.roles, `sharedSeatRows[${index}].roles`);
    if (members.length < 2 || members.some(role => !roles.some(row => row.role === role))) invalid(path, 'shared pool requires registered source roles');
    unique(members, `${path}.sharedSeatRows.roles`);
    const matching = profiles.filter(profile => profile.section === section);
    if (!matching.length || matching.some(profile => profile.cells.find(cell => cell.row === sourceRow)?.label !== label)) {
      invalid(path, 'shared pool must bind an exact source row');
    }
    return Object.freeze({ section, row: sourceRow, label, roles: members });
  }));
  unique(sharedSeatRows.map(row => `${row.section}:${row.row}`), `${path}.sharedSeatRows`);
  const requiredOwnerInputs = texts(input.requiredOwnerInputs, 'requiredOwnerInputs');
  unique(requiredOwnerInputs, `${path}.requiredOwnerInputs`);
  return Object.freeze({ section: integer(input.section, `${path}.section`, 1), interpretation: 'source_only', audiences, roles, sharedSeatRows, requiredOwnerInputs });
}

/** Validates shape and internal consistency; source fidelity is checked independently against the BRD. */
export function validateBrdCatalog(value: unknown): BrdCatalog {
  const input = record(value, 'brdCatalog', ['schemaVersion', 'purpose', 'source', 'currency', 'retainedOffer', 'profiles', 'roleAvailability', 'decisions', 'publicationRequirements']);
  if (input.schemaVersion !== 1 || input.purpose !== 'configuration_preparation') invalid('brdCatalog', 'expected source preparation schema 1');
  const sourceInput = record(input.source, 'brdCatalog.source', ['title', 'version', 'sections']);
  const sections = nonempty(array(sourceInput.sections, 'brdCatalog.source.sections').map((value, index) => integer(value, `brdCatalog.source.sections[${index}]`, 1)), 'brdCatalog.source.sections');
  unique(sections, 'brdCatalog.source.sections');
  const source = Object.freeze({ title: text(sourceInput.title, 'brdCatalog.source.title'), version: text(sourceInput.version, 'brdCatalog.source.version'), sections });
  const currencyInput = record(input.currency, 'brdCatalog.currency', ['code', 'minorUnit']);
  const code = text(currencyInput.code, 'brdCatalog.currency.code');
  if (!/^[A-Z]{3}$/.test(code)) invalid('brdCatalog.currency.code', 'expected currency code');
  const minorUnit = integer(currencyInput.minorUnit, 'brdCatalog.currency.minorUnit');
  const currency = Object.freeze({ code, minorUnit });
  const retainedInput = record(input.retainedOffer, 'brdCatalog.retainedOffer', ['displayName', 'resolution', 'preserveHistory']);
  if (retainedInput.resolution !== 'existing_owner_binding_required' || retainedInput.preserveHistory !== true) invalid('brdCatalog.retainedOffer', 'existing owner binding and history preservation are required');
  const retainedOffer = Object.freeze({ displayName: text(retainedInput.displayName, 'brdCatalog.retainedOffer.displayName'), resolution: 'existing_owner_binding_required' as const, preserveHistory: true as const });
  const profiles = nonempty(array(input.profiles, 'brdCatalog.profiles').map((value, index) => profile(value, `brdCatalog.profiles[${index}]`, sections)), 'brdCatalog.profiles');
  unique(profiles.map(value => value.reference), 'brdCatalog.profiles');
  for (const section of sections) {
    const sectionProfiles = profiles.filter(value => value.section === section).sort((a, b) => a.column - b.column);
    if (!sectionProfiles.length || sectionProfiles.some((value, index) => value.column !== index + 1)) invalid('brdCatalog.profiles', 'source columns must be complete');
    const labels = JSON.stringify(sectionProfiles[0].cells.map(value => value.label));
    if (sectionProfiles.some(value => JSON.stringify(value.cells.map(cell => cell.label)) !== labels)) invalid('brdCatalog.profiles', 'section profiles require identical source rows');
  }
  const decisions = nonempty(array(input.decisions, 'brdCatalog.decisions').map((value, index) => {
    const path = `brdCatalog.decisions[${index}]`;
    const decision = record(value, path, ['reference', 'area', 'requirement', 'status']);
    if (decision.status !== 'policy_required') invalid(path, 'source decisions cannot represent approval');
    return Object.freeze({ reference: text(decision.reference, `${path}.reference`), area: text(decision.area, `${path}.area`), requirement: text(decision.requirement, `${path}.requirement`), status: 'policy_required' as const });
  }), 'brdCatalog.decisions');
  unique(decisions.map(value => value.reference), 'brdCatalog.decisions');
  unique(decisions.map(value => value.area), 'brdCatalog.decisions');
  const publicationRequirements = nonempty(array(input.publicationRequirements, 'brdCatalog.publicationRequirements').map((value, index) => text(value, `brdCatalog.publicationRequirements[${index}]`)), 'brdCatalog.publicationRequirements');
  unique(publicationRequirements, 'brdCatalog.publicationRequirements');
  return Object.freeze({ schemaVersion: 1, purpose: 'configuration_preparation', source, currency, retainedOffer, profiles,
    roleAvailability: roleAvailability(input.roleAvailability, profiles), decisions, publicationRequirements });
}

/** Bundled source configuration; no database writes, fallback, grants or identities. */
export function loadBrdCatalog(): BrdCatalog {
  return validateBrdCatalog(configuration);
}

/** Lookup only by source reference; display names have no selection or permission semantics. */
export function readBrdCatalogProfile(catalog: BrdCatalog, reference: string): BrdCatalogProfile {
  const key = text(reference, 'brdCatalog.reference');
  const matches = catalog.profiles.filter(value => value.reference === key);
  if (matches.length !== 1) invalid('brdCatalog.reference', 'source profile must resolve exactly once');
  return matches[0];
}
