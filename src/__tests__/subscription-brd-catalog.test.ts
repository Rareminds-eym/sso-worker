import { describe, expect, it } from 'vitest';
import configuration from '../../config/subscriptions/brd-catalog.json';
import brdSource from '../../../.unlazy/subscription-visual-update/brd-source.md?raw';
import { loadBrdCatalog, readBrdCatalogProfile, validateBrdCatalog, type BrdCatalog } from '../lib/subscriptions/brd-catalog';

const source: string = brdSource;
const sections = [6, 7, 8, 9, 10];

/** Independent oracle reads the BRD, not the generated configuration's row/column counts. */
function sourceTable(section: number): string[][] {
  const lines = source.split('\n');
  const start = lines.findIndex(line => line.startsWith(`# **${section}\\.`));
  expect(start).toBeGreaterThan(-1);
  const next = lines.findIndex((line, index) => index > start && line.startsWith('# '));
  const rows = lines.slice(start + 1, next < 0 ? undefined : next).filter(line => line.startsWith('| '))
    .map(line => line.trim().slice(1, -1).split('|').map(cell => cell.trim().replace(/\\([+\-])/g, '$1')));
  expect(rows.length).toBeGreaterThan(2);
  expect(rows[1].every(cell => /^:?-+/.test(cell))).toBe(true);
  return [rows[0], ...rows.slice(2)];
}

const expectedProfiles = sections.flatMap(section => {
  const [head, ...rows] = sourceTable(section);
  return head.slice(1).map((displayName, index) => ({
    reference: `brd:${section}:${index + 1}`, section, column: index + 1, displayName,
    cells: rows.map((row, rowIndex) => ({ row: rowIndex + 1, label: row[0], text: row[index + 1] })),
  }));
});

function assertSourceFidelity(catalog: BrdCatalog): void {
  expect(catalog.source.sections).toEqual(sections);
  expect(catalog.profiles.map(profile => ({
    reference: profile.reference, section: profile.section, column: profile.column,
    displayName: profile.displayName,
    cells: profile.cells.map(({ row, label, text }) => ({ row, label, text })),
  }))).toEqual(expectedProfiles);
  expect(catalog.currency).toEqual({ code: 'INR', minorUnit: 2 });
  for (const profile of catalog.profiles) {
    const sourceProfile = expectedProfiles.find(value => value.reference === profile.reference)!;
    const rawPrice = sourceProfile.cells.find(cell => cell.label === 'Public price')!.text;
    const match = /^(From )?INR ([\d,]+)(\/year)?$/.exec(rawPrice);
    expect(match).not.toBeNull();
    expect(profile.price).toEqual({
      kind: match![1] ? 'starting_at' : 'fixed', amountMinor: Number(match![2].replaceAll(',', '')) * 100,
      intervalUnit: match![3] ? 'year' : null,
    });
  }
  const [, ...decisions] = sourceTable(21);
  expect(catalog.decisions).toEqual(decisions.map((row, index) => ({
    reference: `brd:21:${index + 1}`, area: row[0], requirement: row[1], status: 'policy_required',
  })));
  const [roleHeader, ...roleRows] = sourceTable(11);
  expect(catalog.roleAvailability.section).toBe(11);
  expect(catalog.roleAvailability.interpretation).toBe('source_only');
  expect(catalog.roleAvailability.audiences).toEqual(roleHeader.slice(1));
  expect(catalog.roleAvailability.roles).toEqual(roleRows.map(([role, ...terms]) => ({ role, terms })));
}

describe('BRD configuration fidelity without executable grants', () => {
  it('preserves every role cell from section 11 without inventing executable permissions or seat counts', () => {
    const catalog = loadBrdCatalog();
    assertSourceFidelity(catalog);
    expect(catalog.roleAvailability.requiredOwnerInputs).not.toHaveLength(0);
    for (const row of catalog.roleAvailability.roles) {
      expect(row).not.toHaveProperty('enabled'); expect(row).not.toHaveProperty('limit');
    }
  });

  it('retains source-shared faculty/mentor and placement/counsellor pools', () => {
    const catalog = loadBrdCatalog();
    for (const shared of catalog.roleAvailability.sharedSeatRows) {
      const [, ...rows] = sourceTable(shared.section);
      const sourceRow = rows[shared.row - 1];
      expect(sourceRow[0]).toBe(shared.label);
      expect(sourceRow[0]).toMatch(/\//);
      expect(shared.roles).toHaveLength(2);
      expect(shared.roles.every(role => catalog.roleAvailability.roles.some(row => row.role === role))).toBe(true);
      expect(shared.roles.every(role => sourceRow[0].toLowerCase().includes(role.split(/[ /]/)[0].toLowerCase()))).toBe(true);
    }
    expect(catalog.roleAvailability.sharedSeatRows.map(row => [row.section, row.row])).toEqual([[8, 4], [8, 5], [9, 4], [9, 5]]);
  });

  it('detects changed and omitted role terms independently of structural validation', () => {
    const changed = structuredClone(configuration); changed.roleAvailability.roles[0].terms[0] = 'Altered permission';
    expect(() => assertSourceFidelity(validateBrdCatalog(changed))).toThrow();
    const omitted = structuredClone(configuration); omitted.roleAvailability.roles.pop();
    expect(() => assertSourceFidelity(validateBrdCatalog(omitted))).toThrow();
    const ragged = structuredClone(configuration); ragged.roleAvailability.roles[0].terms.pop();
    expect(() => validateBrdCatalog(ragged)).toThrow();
    const executable = structuredClone(configuration); Object.assign(executable.roleAvailability.roles[0], { enabled: true });
    expect(() => validateBrdCatalog(executable)).toThrow('unsupported field');
  });
  it('preserves every section 6–10 profile/cell and independently decodes every public price', () => {
    assertSourceFidelity(loadBrdCatalog());
  });

  it.each(expectedProfiles)('detects omitted profile $reference', profile => {
    const value = structuredClone(configuration);
    value.profiles = value.profiles.filter(item => item.reference !== profile.reference);
    expect(() => assertSourceFidelity(validateBrdCatalog(value))).toThrow();
  });

  const cells = expectedProfiles.flatMap(profile => profile.cells.map(cell => ({ reference: profile.reference, row: cell.row })));
  it.each(cells)('detects altered source cell $reference row $row', ({ reference, row }) => {
    const value = structuredClone(configuration);
    value.profiles.find(profile => profile.reference === reference)!.cells[row - 1].text += ' altered';
    // A structurally valid commercial alteration must still fail the independent BRD oracle.
    expect(() => assertSourceFidelity(validateBrdCatalog(value))).toThrow();
  });

  it.each(expectedProfiles)('detects altered structured price $reference', ({ reference }) => {
    const value = structuredClone(configuration);
    value.profiles.find(profile => profile.reference === reference)!.price.amountMinor += 1;
    expect(() => assertSourceFidelity(validateBrdCatalog(value))).toThrow();
  });

  it('rejects omitted cells, altered From flags and fabricated free durations', () => {
    const omitted = structuredClone(configuration); omitted.profiles[0].cells.pop();
    expect(() => assertSourceFidelity(validateBrdCatalog(omitted))).toThrow();
    const from = structuredClone(configuration); from.profiles.find(profile => profile.price.kind === 'starting_at')!.price.kind = 'fixed';
    expect(() => assertSourceFidelity(validateBrdCatalog(from))).toThrow();
    const duration = structuredClone(configuration); duration.profiles[0].price.intervalUnit = 'year';
    expect(() => assertSourceFidelity(validateBrdCatalog(duration))).toThrow();
  });

  it('detects semantic swaps and whole-section omission even when configuration shape remains valid', () => {
    const swap = structuredClone(configuration);
    [swap.profiles[0].cells[2].text, swap.profiles[1].cells[2].text] = [swap.profiles[1].cells[2].text, swap.profiles[0].cells[2].text];
    expect(() => assertSourceFidelity(validateBrdCatalog(swap))).toThrow();
    const omitted = structuredClone(configuration);
    omitted.source.sections = omitted.source.sections.slice(1); omitted.profiles = omitted.profiles.filter(profile => profile.section !== 6);
    expect(() => assertSourceFidelity(validateBrdCatalog(omitted))).toThrow();
  });

  it('keeps all section 21 decisions unresolved; omission and altered policy cannot self-certify', () => {
    const omitted = structuredClone(configuration); omitted.decisions.pop();
    expect(() => assertSourceFidelity(validateBrdCatalog(omitted))).toThrow();
    const changed = structuredClone(configuration); changed.decisions[0].requirement += ' Approved';
    expect(() => assertSourceFidelity(validateBrdCatalog(changed))).toThrow();
    const approved = structuredClone(configuration); approved.decisions[0].status = 'approved';
    expect(() => validateBrdCatalog(approved)).toThrow('cannot represent approval');
  });

  it('preserves qualifiers as policy requirements without inventing zero, unlimited or granted access', () => {
    for (const profile of loadBrdCatalog().profiles) {
      for (const cell of profile.cells) {
        if (/custom|limited|by policy|retake policy|contract|add-on/i.test(cell.text) && cell.label !== 'Public price') {
          expect(cell.interpretation).toBe('policy_required');
          expect(cell.policyRequirement).toBeTruthy();
        }
        expect(cell).not.toHaveProperty('enabled');
        expect(cell).not.toHaveProperty('limit');
      }
      expect(profile).not.toHaveProperty('plan');
      expect(profile).not.toHaveProperty('id');
      expect(profile).not.toHaveProperty('code');
      expect(profile).not.toHaveProperty('features');
    }
    expect(loadBrdCatalog().retainedOffer).toEqual({ displayName: 'Hybrid', resolution: 'existing_owner_binding_required', preserveHistory: true });
  });
});

describe('strict source catalog boundary', () => {
  it('returns immutable detached configuration and resolves only source references', () => {
    const input = structuredClone(configuration), catalog = validateBrdCatalog(input);
    input.profiles[0].cells[0].text = 'changed';
    expect(catalog.profiles[0].cells[0].text).toBe('INR 0');
    expect(Object.isFrozen(catalog.profiles[0].cells[0])).toBe(true);
    expect(Object.isFrozen(catalog.profiles[0].price)).toBe(true);
    expect(Object.isFrozen(catalog.decisions[0])).toBe(true);
    expect(Object.isFrozen(catalog.source.sections)).toBe(true);
    expect(Object.isFrozen(catalog.profiles)).toBe(true);
    expect(Object.isFrozen(catalog.publicationRequirements)).toBe(true);
    expect(readBrdCatalogProfile(catalog, 'brd:6:1')).toBe(catalog.profiles[0]);
    expect(() => readBrdCatalogProfile(catalog, catalog.profiles[0].displayName)).toThrow('resolve exactly once');
    expect(() => readBrdCatalogProfile(catalog, 'brd:100:1')).toThrow('resolve exactly once');
  });

  it('does not branch on display labels or claim label edits are BRD-conformant', () => {
    const input = structuredClone(configuration); input.profiles[0].displayName = 'Synthetic editable label';
    expect(readBrdCatalogProfile(validateBrdCatalog(input), 'brd:6:1').displayName).toBe('Synthetic editable label');
    expect(() => assertSourceFidelity(validateBrdCatalog(input))).toThrow();
  });

  it('keeps configured currency precision separate from independent BRD fidelity', () => {
    const input = structuredClone(configuration); input.currency.minorUnit = 7;
    expect(validateBrdCatalog(input).currency.minorUnit).toBe(7);
    expect(() => assertSourceFidelity(validateBrdCatalog(input))).toThrow();
  });

  it.each([
    { purpose: 'published' }, { schemaVersion: 2 }, { profiles: [] }, { profiles: new Array(1) },
    { source: { title: 'x', version: 'x', sections: [] } }, { currency: { code: 'INR', minorUnit: -1 } },
    { retainedOffer: { displayName: 'Hybrid', resolution: 'replace', preserveHistory: true } },
    { publicationRequirements: [] }, { decisions: [] }, { published: true },
  ])('rejects malformed configuration %j', patch => {
    expect(() => validateBrdCatalog({ ...configuration, ...patch })).toThrow();
  });

  it('rejects duplicate references, ragged rows, forged coordinates and executable terms', () => {
    const duplicate = structuredClone(configuration); duplicate.profiles.push(duplicate.profiles[0]);
    expect(() => validateBrdCatalog(duplicate)).toThrow('duplicate');
    const coordinate = structuredClone(configuration); coordinate.profiles[0].column = 90;
    expect(() => validateBrdCatalog(coordinate)).toThrow('coordinates');
    const row = structuredClone(configuration); row.profiles[0].cells[0].row = 2;
    expect(() => validateBrdCatalog(row)).toThrow('ordered');
    const terms = structuredClone(configuration);
    Object.assign(terms.profiles[0].cells[0], { enabled: true });
    expect(() => validateBrdCatalog(terms)).toThrow('unsupported field');
    const missingReason = structuredClone(configuration);
    missingReason.profiles.flatMap(profile => profile.cells).find(cell => cell.interpretation === 'policy_required')!.policyRequirement = null;
    expect(() => validateBrdCatalog(missingReason)).toThrow('policyRequirement');
  });
});
