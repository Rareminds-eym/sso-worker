-- Prepared only: requires explicit target-specific deployment approval.
-- Authoring snapshots only. No published pointer, active-plan writes or catalog seeds.
BEGIN;

CREATE TABLE public.subscription_plan_drafts (
  id uuid PRIMARY KEY,
  plan_id uuid NOT NULL REFERENCES public.plans(id) ON DELETE RESTRICT,
  revision_number bigint NOT NULL CHECK (revision_number BETWEEN 1 AND 9007199254740991),
  snapshot jsonb NOT NULL,
  included_credits jsonb,
  staged_by uuid NOT NULL REFERENCES public.users(id) ON DELETE RESTRICT,
  staged_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  CONSTRAINT subscription_plan_drafts_plan_revision_key UNIQUE (plan_id, revision_number),
  CONSTRAINT subscription_plan_drafts_snapshot_identity CHECK ((
    jsonb_typeof(snapshot) = 'object'
    AND snapshot->'schemaVersion' IN ('1'::jsonb, '2'::jsonb)
    AND snapshot->>'id' = id::text
    AND snapshot#>>'{plan,id}' = plan_id::text
    AND snapshot#>>'{plan,code}' ~ '^pln_[0-9a-f]{32}$'
    AND snapshot->'revisionNumber' = to_jsonb(revision_number)
  ) IS TRUE),
  CONSTRAINT subscription_plan_drafts_credit_binding CHECK ((
    (snapshot->'schemaVersion' = '1'::jsonb AND included_credits IS NULL)
    OR (snapshot->'schemaVersion' = '2'::jsonb
      AND jsonb_typeof(included_credits) = 'object'
      AND included_credits->'schemaVersion' = '1'::jsonb
      AND included_credits->>'funding' = 'included'
      AND included_credits->>'revisionId' = id::text
      AND jsonb_typeof(included_credits->'rules') = 'array')
  ) IS TRUE)
);

-- The plan/revision unique index covers plan_id; actor references need their own index.
CREATE INDEX subscription_plan_drafts_staged_by_idx ON public.subscription_plan_drafts (staged_by);

-- Existing defaults can grant broad table privileges: revoke explicitly, including TRUNCATE.
ALTER TABLE public.subscription_plan_drafts ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON TABLE public.subscription_plan_drafts FROM PUBLIC, anon, authenticated, service_role;
GRANT SELECT ON TABLE public.subscription_plan_drafts TO service_role;

CREATE FUNCTION public.reject_subscription_plan_draft_mutation()
RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
BEGIN
  RAISE EXCEPTION 'Subscription plan drafts are immutable';
END;
$$;

CREATE TRIGGER subscription_plan_drafts_immutable_rows
BEFORE UPDATE OR DELETE ON public.subscription_plan_drafts
FOR EACH ROW EXECUTE FUNCTION public.reject_subscription_plan_draft_mutation();
CREATE TRIGGER subscription_plan_drafts_immutable_truncate
BEFORE TRUNCATE ON public.subscription_plan_drafts
FOR EACH STATEMENT EXECUTE FUNCTION public.reject_subscription_plan_draft_mutation();
REVOKE ALL ON FUNCTION public.reject_subscription_plan_draft_mutation() FROM PUBLIC, anon, authenticated, service_role;

CREATE FUNCTION public.stage_subscription_plan_draft(p_draft jsonb, p_staged_by uuid, p_included_credits jsonb DEFAULT NULL)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE
  v_id uuid;
  v_plan_id uuid;
  v_product_id uuid;
  v_revision bigint;
  v_plan public.plans%ROWTYPE;
  v_stored public.subscription_plan_drafts%ROWTYPE;
  v_next bigint;
BEGIN
  -- Commercial/feature registry validation belongs to the trusted worker module.
  -- This service-only RPC additionally enforces storage shape and canonical identity.
  IF p_draft IS NULL OR jsonb_typeof(p_draft) IS DISTINCT FROM 'object'
    OR p_staged_by IS NULL THEN
    RAISE EXCEPTION 'Invalid subscription plan draft';
  END IF;
  IF (SELECT count(*) FROM jsonb_object_keys(p_draft)) <> 9
    OR NOT p_draft ?& ARRAY['schemaVersion','id','plan','revisionNumber','name','audiences','purchaseMode','prices','features']
    OR (p_draft->'schemaVersion' IN ('1'::jsonb, '2'::jsonb)) IS DISTINCT FROM true
    OR jsonb_typeof(p_draft->'plan') IS DISTINCT FROM 'object' THEN
    RAISE EXCEPTION 'Invalid subscription plan draft';
  END IF;
  IF (SELECT count(*) FROM jsonb_object_keys(p_draft->'plan')) <> 3
    OR NOT (p_draft->'plan') ?& ARRAY['id','code','productId']
    OR (p_draft#>>'{plan,code}' ~ '^pln_[0-9a-f]{32}$') IS DISTINCT FROM true
    OR jsonb_typeof(p_draft->'revisionNumber') IS DISTINCT FROM 'number'
    OR (p_draft->>'revisionNumber' ~ '^[1-9][0-9]{0,15}$') IS DISTINCT FROM true
    OR jsonb_typeof(p_draft->'name') IS DISTINCT FROM 'string'
    OR length(btrim(p_draft->>'name')) = 0
    OR (p_draft->>'purchaseMode' IN ('self_service','contact_sales')) IS DISTINCT FROM true
    OR jsonb_typeof(p_draft->'audiences') IS DISTINCT FROM 'array'
    OR jsonb_typeof(p_draft->'prices') IS DISTINCT FROM 'array'
    OR jsonb_typeof(p_draft->'features') IS DISTINCT FROM 'array' THEN
    RAISE EXCEPTION 'Invalid subscription plan draft';
  END IF;
  BEGIN
    v_id := (p_draft->>'id')::uuid;
    v_plan_id := (p_draft#>>'{plan,id}')::uuid;
    v_product_id := (p_draft#>>'{plan,productId}')::uuid;
    v_revision := (p_draft->>'revisionNumber')::bigint;
  EXCEPTION WHEN invalid_text_representation OR numeric_value_out_of_range THEN
    RAISE EXCEPTION 'Invalid subscription plan draft identity';
  END;
  IF v_id IS NULL OR v_plan_id IS NULL OR v_product_id IS NULL
    OR v_revision NOT BETWEEN 1 AND 9007199254740991 THEN
    RAISE EXCEPTION 'Invalid subscription plan draft identity';
  END IF;

  -- Schema 1 is explicitly unbundled; schema 2 must bind both snapshots in this row.
  IF p_draft->'schemaVersion' = '1'::jsonb THEN
    IF p_included_credits IS NOT NULL THEN RAISE EXCEPTION 'Schema 1 cannot carry bundled credits'; END IF;
  ELSE
    IF p_included_credits IS NULL OR jsonb_typeof(p_included_credits) IS DISTINCT FROM 'object' THEN
      RAISE EXCEPTION 'Schema 2 requires included credit terms';
    END IF;
    IF (SELECT count(*) FROM jsonb_object_keys(p_included_credits)) <> 5
      OR NOT p_included_credits ?& ARRAY['schemaVersion','id','revisionId','funding','rules']
      OR p_included_credits->'schemaVersion' IS DISTINCT FROM '1'::jsonb
      OR p_included_credits->>'funding' IS DISTINCT FROM 'included'
      OR p_included_credits->>'revisionId' IS DISTINCT FROM v_id::text
      OR jsonb_typeof(p_included_credits->'rules') IS DISTINCT FROM 'array' THEN
      RAISE EXCEPTION 'Invalid included credit binding';
    END IF;
    BEGIN
      IF (p_included_credits->>'id')::uuid IS NULL THEN RAISE EXCEPTION 'Invalid included credit identity'; END IF;
    EXCEPTION WHEN invalid_text_representation THEN
      RAISE EXCEPTION 'Invalid included credit identity';
    END;
  END IF;

  -- Serialize writers for one canonical plan; concurrent different plans remain independent.
  SELECT * INTO v_plan FROM public.plans WHERE id = v_plan_id FOR UPDATE;
  IF NOT FOUND OR v_plan.plan_code IS DISTINCT FROM p_draft#>>'{plan,code}'
    OR v_plan.product_id IS DISTINCT FROM v_product_id THEN
    RAISE EXCEPTION 'Subscription plan identity does not match the canonical catalog';
  END IF;

  SELECT * INTO v_stored FROM public.subscription_plan_drafts WHERE id = v_id;
  IF FOUND THEN
    IF v_stored.snapshot IS DISTINCT FROM p_draft OR v_stored.staged_by IS DISTINCT FROM p_staged_by
      OR v_stored.included_credits IS DISTINCT FROM p_included_credits THEN
      RAISE EXCEPTION 'Subscription plan draft replay conflicts with stored evidence';
    END IF;
  ELSE
    SELECT coalesce(max(revision_number), 0) + 1 INTO v_next
      FROM public.subscription_plan_drafts WHERE plan_id = v_plan_id;
    IF v_revision <> v_next THEN
      RAISE EXCEPTION 'Subscription plan draft must use the next revision number';
    END IF;
    INSERT INTO public.subscription_plan_drafts (id, plan_id, revision_number, snapshot, included_credits, staged_by)
      VALUES (v_id, v_plan_id, v_revision, p_draft, p_included_credits, p_staged_by)
      RETURNING * INTO v_stored;
  END IF;
  IF v_stored.included_credits IS NOT NULL THEN
    RETURN jsonb_build_object('draft', v_stored.snapshot, 'includedCredits', v_stored.included_credits,
      'stagedBy', v_stored.staged_by, 'stagedAt', v_stored.staged_at);
  END IF;
  RETURN jsonb_build_object('draft', v_stored.snapshot, 'stagedBy', v_stored.staged_by, 'stagedAt', v_stored.staged_at);
END;
$$;

REVOKE ALL ON FUNCTION public.stage_subscription_plan_draft(jsonb, uuid, jsonb) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.stage_subscription_plan_draft(jsonb, uuid, jsonb) TO service_role;

COMMIT;
