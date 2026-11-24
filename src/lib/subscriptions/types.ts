/** Internal catalog contracts. A validated draft is not a published offer or an access grant. */
export interface PlanIdentity {
  readonly id: string;
  readonly code: string;
  readonly productId: string;
}

export type FeatureType = 'boolean' | 'numeric_limit' | 'metered' | 'enum';

export type ConfiguredLimit =
  | { readonly kind: 'finite'; readonly value: number }
  | { readonly kind: 'unlimited' }
  | { readonly kind: 'contract_required' };

export type FeatureGrant =
  | { readonly key: string; readonly type: 'enum'; readonly enabled: boolean; readonly value: string | null }
  | { readonly key: string; readonly type: 'boolean'; readonly enabled: boolean }
  | { readonly key: string; readonly type: 'numeric_limit'; readonly enabled: boolean; readonly limit: ConfiguredLimit }
  | { readonly key: string; readonly type: 'metered'; readonly enabled: boolean; readonly limit: ConfiguredLimit | { readonly kind: 'allocation_policy' } };

export interface PriceOption {
  readonly id: string;
  readonly currency: string;
  readonly minorUnit: number;
  readonly amountMinor: number;
  readonly intervalUnit: 'month' | 'year';
  readonly intervalCount: number;
  readonly quantityBasis: 'subscription' | 'seat';
  readonly audiences: readonly string[];
}

export interface PlanRevisionDraft {
  readonly schemaVersion: 1 | 2;
  readonly id: string;
  readonly plan: PlanIdentity;
  readonly revisionNumber: number;
  readonly name: string;
  readonly audiences: readonly string[];
  readonly purchaseMode: 'free' | 'self_service' | 'contact_sales';
  readonly prices: readonly PriceOption[];
  readonly features: readonly FeatureGrant[];
}

/** Registries must come from the trusted catalog owner, never the submitting client. */
export interface CatalogRegistry {
  readonly productIds: ReadonlySet<string>;
  readonly audienceKeys: ReadonlySet<string>;
  readonly currencies: ReadonlyMap<string, number>;
  readonly featureTypes: ReadonlyMap<string, FeatureType>;
  /** Required for every enum feature; absence never supplies an implicit domain. */
  readonly featureOptions?: ReadonlyMap<string, ReadonlySet<string>>;
}

export interface EntryPlanBinding {
  readonly productId: string;
  readonly audience: string;
  readonly planId: string;
}

export interface EntryPlanCandidate {
  readonly id: string;
  readonly productId: string;
  readonly audiences: readonly string[];
  readonly isActive: boolean;
  readonly publishedRevisionId: string;
}

export interface EntryPlanReference {
  readonly planId: string;
  readonly revisionId: string;
}
