import { describe, expect, it } from 'vitest';
import configuration from '../../config/subscriptions/tax-policy.json';
import { loadTaxPolicy, validateTaxPolicy } from '../lib/subscriptions/tax-policy';

const with_ = (patch: Record<string, unknown>) => ({ ...configuration, ...patch });
describe('owner tax policy', () => {
  it('loads the approved GST policy: 18%, Karnataka supplier, CGST+SGST or IGST, GST-exclusive display', () => {
    const tax = loadTaxPolicy();
    expect(tax).toMatchObject({ kind: 'gst', rateBasisPoints: 1800, supplierStateCode: '29', priceDisplay: 'exclusive', supplierGstin: null, sacCode: null });
    expect(tax.intraState.map(c => c.name)).toEqual(['CGST', 'SGST']);
    expect(tax.interState).toEqual([{ name: 'IGST', rateBasisPoints: 1800 }]);
  });
  it('rejects components that do not sum to the rate, a GSTIN from another state, and missing fields', () => {
    expect(() => validateTaxPolicy(with_({ intraState: [{ name: 'CGST', rateBasisPoints: 900 }] }))).toThrow('sum');
    expect(() => validateTaxPolicy(with_({ supplierGstin: '27AAAAA0000A1Z5' }))).toThrow('supplier state');
    expect(validateTaxPolicy(with_({ supplierGstin: '29AAAAA0000A1Z5' })).supplierGstin).toBe('29AAAAA0000A1Z5');
    const { priceDisplay: _, ...missing } = configuration;
    expect(() => validateTaxPolicy(missing)).toThrow();
    expect(() => validateTaxPolicy(with_({ rateBasisPoints: 20000 }))).toThrow();
  });
});
