import configuration from '../../../config/subscriptions/tax-policy.json';
import { array, choice, integer, invalid, record, text } from './validation';

export interface TaxComponent { readonly name: string; readonly rateBasisPoints: number }
export interface TaxPolicy {
  readonly kind: 'gst';
  readonly rateBasisPoints: number;
  readonly supplierStateCode: string;
  readonly intraState: readonly TaxComponent[];
  readonly interState: readonly TaxComponent[];
  readonly priceDisplay: 'exclusive' | 'inclusive';
  /** Owner inputs; invoice issuing requires both (Task 46). Display does not. */
  readonly supplierGstin: string | null;
  readonly sacCode: string | null;
}

function components(value: unknown, path: string, rate: number): TaxComponent[] {
  const items = array(value, path).map((item, index) => {
    const row = record(item, `${path}[${index}]`, ['name', 'rateBasisPoints']);
    return Object.freeze({ name: text(row.name, `${path}[${index}].name`), rateBasisPoints: integer(row.rateBasisPoints, `${path}[${index}].rateBasisPoints`, 1) });
  });
  if (!items.length || items.reduce((sum, item) => sum + item.rateBasisPoints, 0) !== rate) invalid(path, 'components must sum to the configured rate');
  return items;
}

export function validateTaxPolicy(value: unknown): TaxPolicy {
  const input = record(value, 'taxPolicy', ['schemaVersion', 'source', 'kind', 'rateBasisPoints', 'supplierStateCode', 'intraState', 'interState', 'priceDisplay', 'supplierGstin', 'sacCode']);
  if (input.schemaVersion !== 1) invalid('taxPolicy.schemaVersion', 'unsupported schema version');
  text(input.source, 'taxPolicy.source');
  const rate = integer(input.rateBasisPoints, 'taxPolicy.rateBasisPoints', 1);
  if (rate > 10000) invalid('taxPolicy.rateBasisPoints', 'rate cannot exceed 100%');
  const state = text(input.supplierStateCode, 'taxPolicy.supplierStateCode');
  if (!/^\d{2}$/.test(state)) invalid('taxPolicy.supplierStateCode', 'two-digit GST state code required');
  const gstin = input.supplierGstin === null ? null : text(input.supplierGstin, 'taxPolicy.supplierGstin');
  if (gstin !== null && (!/^\d{2}[0-9A-Z]{13}$/.test(gstin) || gstin.slice(0, 2) !== state)) invalid('taxPolicy.supplierGstin', 'GSTIN must match the supplier state');
  return Object.freeze({
    kind: choice(input.kind, 'taxPolicy.kind', ['gst'] as const), rateBasisPoints: rate, supplierStateCode: state,
    intraState: components(input.intraState, 'taxPolicy.intraState', rate), interState: components(input.interState, 'taxPolicy.interState', rate),
    priceDisplay: choice(input.priceDisplay, 'taxPolicy.priceDisplay', ['exclusive', 'inclusive'] as const),
    supplierGstin: gstin, sacCode: input.sacCode === null ? null : text(input.sacCode, 'taxPolicy.sacCode'),
  });
}
export function loadTaxPolicy(): TaxPolicy { return validateTaxPolicy(configuration); }
