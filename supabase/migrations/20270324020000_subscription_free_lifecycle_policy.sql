-- Prepared only; exact local target and revised batch require explicit approval.
-- Complements verified-free-entry without rewriting its stopped-attempt source.
BEGIN;
SET LOCAL lock_timeout='2s';
SET LOCAL statement_timeout='15s';

CREATE FUNCTION public.assert_free_subscription_lifecycle_policy(p_policy jsonb, p_product uuid)
RETURNS void LANGUAGE plpgsql SET search_path=pg_catalog,public AS $$
BEGIN
  IF jsonb_typeof(p_policy) IS DISTINCT FROM 'object' THEN RAISE EXCEPTION 'Explicit free lifecycle policy required'; END IF;
  IF (SELECT array_agg(key ORDER BY key) FROM jsonb_object_keys(p_policy) key) IS DISTINCT FROM
    ARRAY['billing','cancellationAccess','expiredAccess','graceAccess','graceDurationMs','id','immediateDowngradeAllowed',
      'paymentFailureAfterAccess','paymentFailureRestrictedMs','paymentRetryOffsetsMs','productId','reactivationApprovalRequired',
      'readOnlyDurationMs','suspensionApprovalRequired','version']::text[]
    OR p_policy->>'billing' IS DISTINCT FROM 'not_applicable'
    OR p_policy->>'productId' IS DISTINCT FROM p_product::text
    OR (p_policy->>'cancellationAccess' IN ('read_only','suspended')) IS DISTINCT FROM true
    OR p_policy->>'graceAccess' IS DISTINCT FROM 'read_only' OR p_policy->>'expiredAccess' IS DISTINCT FROM 'read_only'
    OR p_policy->'paymentFailureRestrictedMs' IS DISTINCT FROM 'null'::jsonb
    OR p_policy->'paymentFailureAfterAccess' IS DISTINCT FROM 'null'::jsonb
    OR p_policy->'paymentRetryOffsetsMs' IS DISTINCT FROM '[]'::jsonb
    OR p_policy->'immediateDowngradeAllowed' IS DISTINCT FROM 'false'::jsonb
    OR jsonb_typeof(p_policy->'suspensionApprovalRequired') IS DISTINCT FROM 'boolean'
    OR jsonb_typeof(p_policy->'reactivationApprovalRequired') IS DISTINCT FROM 'boolean' THEN
    RAISE EXCEPTION 'Complete approved free lifecycle terms required';
  END IF;
  IF (p_policy->>'id')::uuid IS NULL THEN RAISE EXCEPTION 'Lifecycle policy identity required'; END IF;
  IF EXISTS(SELECT 1 FROM jsonb_each(p_policy) x WHERE key IN ('version','graceDurationMs','readOnlyDurationMs')
    AND CASE WHEN jsonb_typeof(value)='number' THEN (value#>>'{}')::numeric NOT BETWEEN 1 AND 9007199254740991
      OR (value#>>'{}')::numeric<>trunc((value#>>'{}')::numeric) ELSE true END)
    OR (p_policy->>'graceDurationMs')::numeric>(p_policy->>'readOnlyDurationMs')::numeric THEN
    RAISE EXCEPTION 'Invalid free lifecycle retention durations';
  END IF;
END;
$$;
REVOKE ALL ON FUNCTION public.assert_free_subscription_lifecycle_policy(jsonb,uuid) FROM PUBLIC,anon,authenticated,service_role;

CREATE FUNCTION public.guard_free_subscription_lifecycle_policy()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,public AS $$
BEGIN
  IF TG_TABLE_NAME='subscription_plan_publication_events' THEN
    IF EXISTS(SELECT 1 FROM public.subscription_plan_drafts d WHERE d.id=NEW.revision_id AND d.plan_id=NEW.plan_id
      AND d.snapshot->>'purchaseMode'='free') THEN
      PERFORM public.assert_free_subscription_lifecycle_policy(NEW.canonical_plan#>'{configuration,subscription_lifecycle}',
        (NEW.canonical_plan->>'productId')::uuid);
    END IF;
  ELSIF NEW.lifecycle_policy->>'billing'='not_applicable' THEN
    PERFORM public.assert_free_subscription_lifecycle_policy(NEW.lifecycle_policy,NEW.product_id);
    IF NEW.auto_renew IS DISTINCT FROM false OR NEW.lifecycle_state->'paymentFailedAt' IS DISTINCT FROM 'null'::jsonb
      OR NEW.lifecycle_state->'scheduledChange' IS DISTINCT FROM 'null'::jsonb
      OR NOT EXISTS(SELECT 1 FROM public.subscription_plan_drafts d WHERE d.id=NEW.plan_revision_id AND d.plan_id=NEW.plan_id
        AND d.snapshot->>'purchaseMode'='free' AND d.snapshot->'prices'='[]'::jsonb) THEN
      RAISE EXCEPTION 'Billing operations are inapplicable to a free offer';
    END IF;
    IF TG_OP='UPDATE' AND OLD.lifecycle_policy->>'billing'='not_applicable'
      AND (NEW.subscription_start_date IS DISTINCT FROM OLD.subscription_start_date
        OR NEW.subscription_end_date IS DISTINCT FROM OLD.subscription_end_date
        OR NEW.plan_revision_id IS DISTINCT FROM OLD.plan_revision_id) THEN
      RAISE EXCEPTION 'Free offer requires an explicit commercial transition owner';
    END IF;
  END IF;
  RETURN NEW;
END;
$$;
REVOKE ALL ON FUNCTION public.guard_free_subscription_lifecycle_policy() FROM PUBLIC,anon,authenticated,service_role;
CREATE TRIGGER subscription_free_policy_publication BEFORE INSERT ON public.subscription_plan_publication_events
  FOR EACH ROW EXECUTE FUNCTION public.guard_free_subscription_lifecycle_policy();
CREATE TRIGGER subscription_free_policy_state BEFORE INSERT OR UPDATE ON public.subscriptions
  FOR EACH ROW EXECUTE FUNCTION public.guard_free_subscription_lifecycle_policy();
COMMIT;
