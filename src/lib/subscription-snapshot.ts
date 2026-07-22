import type { Env } from "../types";
import type { LteSubscriptionSnapshot } from "../types/sso-code";
import { db } from "./db";

interface SubscriptionRow {
  id: string;
  user_id: string;
  organization_id: string | null;
  plan_id: string | null;
  plan_code: string | null;
  plan_type: string | null;
  plan_amount: number | string | null;
  billing_cycle: string | null;
  status: string;
  features: unknown;
  product_id: string | null;
  subscription_start_date: string | null;
  subscription_end_date: string | null;
  updated_at: string | null;
  created_at: string | null;
}

interface PlanRow {
  id: string;
  name: string | null;
  plan_code: string | null;
  product_id: string | null;
  base_features: unknown;
}

const LTE_FEATURE_KEYS = new Set([
  "course_lte_access",
  "lte_course_assignment",
  "lte_assignment_and_tracking",
]);

export async function getLteSubscriptionSnapshot(
  env: Env,
  userId: string,
): Promise<LteSubscriptionSnapshot | null> {
  const database = db(env);
  const lteProduct = await database.queryOne<{ id: string }>(
    "products?code=eq.lte&select=id&limit=1",
  );

  const subscriptions = await database.query<SubscriptionRow>(
    `subscriptions?user_id=eq.${encodeURIComponent(userId)}&status=in.(active,pending)&order=created_at.desc`,
  );

  // Batch-fetch all plan records at once to avoid N+1 queries in the loop
  const planIds = subscriptions
    .map((s) => s.plan_id)
    .filter((id): id is string => typeof id === "string");

  let plans: PlanRow[] = [];
  if (planIds.length > 0) {
    plans = await database.query<PlanRow>(
      `plans?id=in.(${planIds.map((id) => encodeURIComponent(id)).join(",")})&select=id,name,plan_code,product_id,base_features`,
    ) ?? [];
  }
  const planMap = new Map<string, PlanRow>(plans.map((p) => [p.id, p]));

  let selectedSubscription: SubscriptionRow | null = null;
  let selectedPlan: PlanRow | null = null;

  // First, try to find an LTE-specific subscription
  for (const subscription of subscriptions) {
    const plan = subscription.plan_id
      ? planMap.get(subscription.plan_id) || null
      : null;

    if (
      (lteProduct && subscription.product_id === lteProduct.id) ||
      hasLteFeature(subscription.features) ||
      hasLteFeature(plan?.base_features)
    ) {
      selectedSubscription = subscription;
      selectedPlan = plan;
      break;
    }
  }

  // If no LTE-specific subscription found, but user has LTE access,
  // use their most recent active subscription (this function is only called
  // after LTE entitlement has been verified)
  if (!selectedSubscription && subscriptions.length > 0) {
    selectedSubscription = subscriptions[0]; // Most recent by created_at desc
    if (selectedSubscription.plan_id) {
      selectedPlan = planMap.get(selectedSubscription.plan_id) || null;
    }
  }

  if (!selectedSubscription) return null;

  return {
    id: selectedSubscription.id,
    user_id: selectedSubscription.user_id,
    organization_id: selectedSubscription.organization_id,
    plan_id: selectedSubscription.plan_id,
    plan_code: selectedSubscription.plan_code ?? selectedPlan?.plan_code ?? null,
    plan_name: selectedPlan?.name ?? null,
    plan_type: selectedSubscription.plan_type,
    plan_amount: toNullableNumber(selectedSubscription.plan_amount),
    billing_cycle: selectedSubscription.billing_cycle,
    status: selectedSubscription.status,
    features: toFeatureArray(selectedSubscription.features),
    product_code: "lte",
    product_id: selectedSubscription.product_id ?? selectedPlan?.product_id ?? lteProduct?.id ?? null,
    subscription_start_date: selectedSubscription.subscription_start_date,
    subscription_end_date: selectedSubscription.subscription_end_date,
    updated_at: selectedSubscription.updated_at ?? new Date().toISOString(),
  };
}

function toNullableNumber(value: number | string | null): number | null {
  if (typeof value === "number") {
    return value;
  }

  if (typeof value === "string") {
    const parsed = Number(value);
    return Number.isFinite(parsed) ? parsed : null;
  }

  return null;
}

function hasLteFeature(features: unknown): boolean {
  return toFeatureArray(features).some((feature) => (
    typeof feature === "string" && LTE_FEATURE_KEYS.has(feature)
  ));
}

function toFeatureArray(features: unknown): unknown[] {
  return Array.isArray(features) ? features : [];
}
