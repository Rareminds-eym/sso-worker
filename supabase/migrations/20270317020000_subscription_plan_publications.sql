-- PREPARED ONLY. Requires separate explicit approval for the exact SSO database target.
-- Advances a canonical catalog revision pointer; never activates a plan/subscription or changes customers.
BEGIN;
SET LOCAL lock_timeout = '2s';
SET LOCAL statement_timeout = '15s';

CREATE TABLE public.subscription_plan_publications (
  plan_id uuid PRIMARY KEY REFERENCES public.plans(id) ON DELETE RESTRICT,
  revision_id uuid NOT NULL UNIQUE REFERENCES public.subscription_plan_drafts(id) ON DELETE RESTRICT,
  previous_revision_id uuid REFERENCES public.subscription_plan_drafts(id) ON DELETE RESTRICT,
  published_by uuid NOT NULL REFERENCES public.users(id) ON DELETE RESTRICT,
  published_at timestamptz NOT NULL,
  CHECK (revision_id IS DISTINCT FROM previous_revision_id)
);
CREATE INDEX subscription_plan_publications_previous_idx ON public.subscription_plan_publications(previous_revision_id);
CREATE INDEX subscription_plan_publications_actor_idx ON public.subscription_plan_publications(published_by);

CREATE TABLE public.subscription_plan_publication_events (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  plan_id uuid NOT NULL REFERENCES public.plans(id) ON DELETE RESTRICT,
  revision_id uuid NOT NULL REFERENCES public.subscription_plan_drafts(id) ON DELETE RESTRICT,
  previous_revision_id uuid REFERENCES public.subscription_plan_drafts(id) ON DELETE RESTRICT,
  published_by uuid NOT NULL REFERENCES public.users(id) ON DELETE RESTRICT,
  published_at timestamptz NOT NULL,
  canonical_plan jsonb NOT NULL CHECK (jsonb_typeof(canonical_plan) = 'object'),
  UNIQUE(plan_id, revision_id),
  CHECK (revision_id IS DISTINCT FROM previous_revision_id)
);
CREATE INDEX subscription_plan_publication_events_revision_idx ON public.subscription_plan_publication_events(revision_id);
CREATE INDEX subscription_plan_publication_events_previous_idx ON public.subscription_plan_publication_events(previous_revision_id);
CREATE INDEX subscription_plan_publication_events_actor_idx ON public.subscription_plan_publication_events(published_by);

CREATE FUNCTION public.reject_subscription_publication_event_mutation()
RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
BEGIN
  RAISE EXCEPTION 'Subscription publication audit events are immutable';
END;
$$;
CREATE TRIGGER subscription_plan_publication_events_immutable_rows
BEFORE UPDATE OR DELETE ON public.subscription_plan_publication_events
FOR EACH ROW EXECUTE FUNCTION public.reject_subscription_publication_event_mutation();
CREATE TRIGGER subscription_plan_publication_events_immutable_truncate
BEFORE TRUNCATE ON public.subscription_plan_publication_events
FOR EACH STATEMENT EXECUTE FUNCTION public.reject_subscription_publication_event_mutation();
REVOKE ALL ON FUNCTION public.reject_subscription_publication_event_mutation() FROM PUBLIC, anon, authenticated, service_role;
REVOKE ALL ON TABLE public.subscription_plan_publications, public.subscription_plan_publication_events
  FROM PUBLIC, anon, authenticated, service_role;
GRANT SELECT ON TABLE public.subscription_plan_publications, public.subscription_plan_publication_events TO service_role;

CREATE FUNCTION public.publish_subscription_plan_revision(
  p_plan_id uuid, p_revision_id uuid, p_expected_previous_revision_id uuid,
  p_actor_id uuid, p_expected_plan jsonb
) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE
  v_plan public.plans%ROWTYPE;
  v_draft public.subscription_plan_drafts%ROWTYPE;
  v_current public.subscription_plan_publications%ROWTYPE;
  v_previous_number bigint;
  v_time timestamptz;
  v_canonical jsonb;
BEGIN
  -- The signed/live worker derives actor, checks complete commercial terms, and independently
  -- reads the immutable application projection. SQL serializes only the SSO-owned transition.
  IF p_plan_id IS NULL OR p_revision_id IS NULL OR p_actor_id IS NULL
    OR p_expected_plan IS NULL OR jsonb_typeof(p_expected_plan) IS DISTINCT FROM 'object' THEN
    RAISE EXCEPTION 'Invalid subscription publication request';
  END IF;
  -- Same plan lock used by draft staging; concurrent plan/draft/publication writers serialize.
  SELECT * INTO v_plan FROM public.plans WHERE id = p_plan_id FOR UPDATE;
  IF NOT FOUND THEN RAISE EXCEPTION 'Canonical plan does not exist'; END IF;
  v_canonical := jsonb_build_object('id', v_plan.id, 'code', v_plan.plan_code,
    'productId', v_plan.product_id, 'audiences', to_jsonb(v_plan.applicable_entities), 'configuration', v_plan.entity_config);
  IF v_canonical IS DISTINCT FROM p_expected_plan THEN
    RAISE EXCEPTION 'Canonical publication configuration changed';
  END IF;
  SELECT * INTO v_draft FROM public.subscription_plan_drafts WHERE id = p_revision_id AND plan_id = p_plan_id;
  IF NOT FOUND OR v_draft.snapshot->'schemaVersion' IS DISTINCT FROM '2'::jsonb
    OR v_draft.snapshot#>>'{plan,code}' IS DISTINCT FROM v_plan.plan_code
    OR v_draft.snapshot#>>'{plan,productId}' IS DISTINCT FROM v_plan.product_id::text
    OR v_draft.included_credits IS NULL THEN
    RAISE EXCEPTION 'Publication requires this canonical plan bundled revision';
  END IF;
  SELECT * INTO v_current FROM public.subscription_plan_publications WHERE plan_id = p_plan_id;
  IF FOUND AND v_current.revision_id = p_revision_id THEN
    IF v_current.previous_revision_id IS DISTINCT FROM p_expected_previous_revision_id
      OR v_current.published_by IS DISTINCT FROM p_actor_id THEN
      RAISE EXCEPTION 'Publication replay conflicts with recorded transition';
    END IF;
    RETURN jsonb_build_object('planId', v_current.plan_id, 'revisionId', v_current.revision_id,
      'previousRevisionId', v_current.previous_revision_id, 'publishedBy', v_current.published_by, 'publishedAt', v_current.published_at);
  END IF;
  IF v_current.revision_id IS DISTINCT FROM p_expected_previous_revision_id THEN
    RAISE EXCEPTION 'Published revision changed since request';
  END IF;
  IF v_current.revision_id IS NOT NULL THEN
    SELECT revision_number INTO v_previous_number FROM public.subscription_plan_drafts WHERE id = v_current.revision_id;
    IF v_previous_number IS NULL OR v_draft.revision_number <= v_previous_number THEN
      RAISE EXCEPTION 'Publication must advance the immutable revision sequence';
    END IF;
  END IF;
  v_time := clock_timestamp();
  INSERT INTO public.subscription_plan_publications(plan_id, revision_id, previous_revision_id, published_by, published_at)
    VALUES(p_plan_id, p_revision_id, p_expected_previous_revision_id, p_actor_id, v_time)
    ON CONFLICT(plan_id) DO UPDATE SET revision_id = EXCLUDED.revision_id,
      previous_revision_id = EXCLUDED.previous_revision_id, published_by = EXCLUDED.published_by, published_at = EXCLUDED.published_at;
  INSERT INTO public.subscription_plan_publication_events(plan_id, revision_id, previous_revision_id,
    published_by, published_at, canonical_plan)
    VALUES(p_plan_id, p_revision_id, p_expected_previous_revision_id, p_actor_id, v_time, v_canonical);
  RETURN jsonb_build_object('planId', p_plan_id, 'revisionId', p_revision_id,
    'previousRevisionId', p_expected_previous_revision_id, 'publishedBy', p_actor_id, 'publishedAt', v_time);
END;
$$;
REVOKE ALL ON FUNCTION public.publish_subscription_plan_revision(uuid,uuid,uuid,uuid,jsonb)
  FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.publish_subscription_plan_revision(uuid,uuid,uuid,uuid,jsonb) TO service_role;

COMMIT;
