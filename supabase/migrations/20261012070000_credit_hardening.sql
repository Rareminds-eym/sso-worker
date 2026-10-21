-- Forward credit accounting fixes; no historical migration edits.

CREATE OR REPLACE FUNCTION public.begin_career_operation(
  p_user_id uuid, p_operation_id text, p_execution_id text,
  p_session_id uuid, p_action text, p_payload_hash text
)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_product uuid; v_acct public.user_ai_credit_accounts%ROWTYPE;
  v_dup public.ai_credit_operations%ROWTYPE; v_exec public.ai_credit_operations%ROWTYPE;
  v_policy public.ai_credit_policies%ROWTYPE; v_op public.ai_credit_operations%ROWTYPE;
BEGIN
  IF p_operation_id IS NULL OR p_operation_id = '' OR length(p_operation_id) > 128
     OR p_execution_id IS NULL OR p_execution_id = '' OR length(p_execution_id) > 128
     OR p_action IS NULL OR p_action = '' OR p_payload_hash IS NULL OR p_payload_hash = '' THEN
    RETURN jsonb_build_object('ok', false, 'error', 'INVALID_INPUT');
  END IF;
  SELECT id INTO v_product FROM public.products WHERE code = 'skillpassport';
  IF NOT FOUND THEN
    RETURN jsonb_build_object('ok', false, 'error', 'NO_PRODUCT');
  END IF;
  PERFORM public.ensure_career_credit_account(p_user_id);
  SELECT * INTO v_acct FROM public.user_ai_credit_accounts
  WHERE user_id = p_user_id AND product_id = v_product AND scope = 'career_ai'
  FOR UPDATE;
  -- Stable-identity replay: same turn returns its original context, no new guard.
  SELECT * INTO v_dup FROM public.ai_credit_operations
  WHERE account_id = v_acct.id AND operation_id = p_operation_id;
  IF FOUND THEN
    IF v_dup.payload_hash IS DISTINCT FROM p_payload_hash
       OR v_dup.execution_id IS DISTINCT FROM p_execution_id
       OR v_dup.session_id IS DISTINCT FROM p_session_id
       OR v_dup.action IS DISTINCT FROM p_action THEN
      RETURN jsonb_build_object('ok', false, 'error', 'IDENTITY_CONFLICT');
    END IF;
    RETURN jsonb_build_object(
      'ok', true, 'duplicate', true,
      'account_id', v_acct.id, 'operation_record_id', v_dup.id,
      'policy_id', v_dup.policy_id, 'execution_id', v_dup.execution_id,
      'revision', v_acct.revision);
  END IF;
  -- Same execution under a different turn id must never fork accounting.
  SELECT * INTO v_exec FROM public.ai_credit_operations
  WHERE account_id = v_acct.id AND execution_id = p_execution_id;
  IF FOUND THEN
    RETURN jsonb_build_object('ok', false, 'error', 'IDENTITY_CONFLICT');
  END IF;
  IF v_acct.active_operation_id IS NOT NULL THEN
    RETURN jsonb_build_object('ok', false, 'error', 'IN_PROGRESS',
      'active_operation_id', v_acct.active_operation_id);
  END IF;
  IF v_acct.spent_credits >= v_acct.granted_credits THEN
    RETURN jsonb_build_object('ok', false, 'error', 'EXHAUSTED',
      'spent_credits', v_acct.spent_credits::text,
      'granted_credits', v_acct.granted_credits::text);
  END IF;
  SELECT * INTO v_policy FROM public.ai_credit_policies
  WHERE product_id = v_product AND scope = 'career_ai' AND active = true;
  IF NOT FOUND THEN
    RETURN jsonb_build_object('ok', false, 'error', 'NO_POLICY');
  END IF;
  INSERT INTO public.ai_credit_operations
    (account_id, operation_id, execution_id, session_id, action, payload_hash, policy_id, state)
  VALUES (v_acct.id, p_operation_id, p_execution_id, p_session_id, p_action, p_payload_hash, v_policy.id, 'active')
  RETURNING * INTO v_op;
  UPDATE public.user_ai_credit_accounts
  SET active_operation_id = p_operation_id, active_execution_id = p_execution_id,
      revision = revision + 1, updated_at = now()
  WHERE id = v_acct.id;
  RETURN jsonb_build_object(
    'ok', true, 'duplicate', false,
    'account_id', v_acct.id, 'operation_record_id', v_op.id,
    'policy_id', v_policy.id, 'execution_id', p_execution_id,
    'revision', v_acct.revision + 1);
END;
$$;

CREATE OR REPLACE FUNCTION public.settle_career_invocation(
  p_invocation_id uuid, p_log_id text, p_cost_usd text,
  p_input_tokens bigint, p_output_tokens bigint,
  p_invocation_status text, p_duration_ms bigint, p_cost_state text DEFAULT 'resolved'
)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_use public.user_ai_usage%ROWTYPE; v_op public.ai_credit_operations%ROWTYPE;
  v_acct public.user_ai_credit_accounts%ROWTYPE; v_policy public.ai_credit_policies%ROWTYPE;
  v_cost numeric(24,12); v_credits numeric(24,12); v_clash uuid;
BEGIN
  IF p_invocation_status NOT IN ('succeeded', 'failed', 'timed_out', 'cancelled', 'unknown', 'not_dispatched')
     OR p_cost_state NOT IN ('resolved', 'unresolved', 'not_applicable') THEN
    RETURN jsonb_build_object('ok', false, 'error', 'INVALID_INPUT');
  END IF;
  IF p_cost_state = 'resolved' AND (p_cost_usd IS NULL OR p_log_id IS NULL) THEN
    RETURN jsonb_build_object('ok', false, 'error', 'EVIDENCE_REQUIRED');
  END IF;
  IF p_cost_state <> 'resolved' AND (p_cost_usd IS NOT NULL OR p_log_id IS NOT NULL) THEN
    RETURN jsonb_build_object('ok', false, 'error', 'EVIDENCE_FORBIDDEN');
  END IF;
  IF p_cost_usd IS NOT NULL THEN
    IF p_cost_usd !~ '^\d+(\.\d{1,12})?$' THEN
      RETURN jsonb_build_object('ok', false, 'error', 'COST_PRECISION');
    END IF;
    v_cost := round(p_cost_usd::numeric, 12);
    IF v_cost < 0 THEN
      RETURN jsonb_build_object('ok', false, 'error', 'NEGATIVE_COST');
    END IF;
  END IF;
  IF (p_input_tokens IS NOT NULL AND p_input_tokens < 0)
     OR (p_output_tokens IS NOT NULL AND p_output_tokens < 0)
     OR (p_duration_ms IS NOT NULL AND p_duration_ms < 0) THEN
    RETURN jsonb_build_object('ok', false, 'error', 'NEGATIVE_COUNTER');
  END IF;
  SELECT a.* INTO v_acct FROM public.user_ai_credit_accounts a
  JOIN public.ai_credit_operations o ON o.account_id = a.id
  JOIN public.user_ai_usage u ON u.operation_record_id = o.id
  WHERE u.id = p_invocation_id FOR UPDATE OF a;
  IF NOT FOUND THEN
    RETURN jsonb_build_object('ok', false, 'error', 'NO_USAGE');
  END IF;
  SELECT * INTO v_use FROM public.user_ai_usage WHERE id = p_invocation_id FOR UPDATE;
  SELECT * INTO v_op FROM public.ai_credit_operations WHERE id = v_use.operation_record_id FOR UPDATE;
  SELECT * INTO v_policy FROM public.ai_credit_policies WHERE id = v_op.policy_id;
  IF v_policy.product_id <> v_acct.product_id OR v_policy.scope <> 'career_ai' THEN
    RETURN jsonb_build_object('ok', false, 'error', 'POLICY_MISMATCH');
  END IF;
  -- Idempotent replay: same evidence returns the recorded debit, never re-debits.
  IF v_use.cost_state = 'resolved' AND v_use.log_id IS NOT DISTINCT FROM p_log_id THEN
    IF p_cost_state <> 'resolved' OR v_use.ai_cost_usd IS DISTINCT FROM v_cost THEN
      RETURN jsonb_build_object('ok', false, 'error', 'EVIDENCE_CONFLICT');
    END IF;
    RETURN jsonb_build_object('ok', true, 'duplicate', true,
      'credits_used', v_use.credits_used::text,
      'spent_credits', v_acct.spent_credits::text,
      'remaining_credits', GREATEST(0::numeric, v_acct.granted_credits - v_acct.spent_credits)::text,
      'revision', v_acct.revision);
  END IF;
  IF v_use.cost_state IN ('resolved', 'waived') THEN
    RETURN jsonb_build_object('ok', false, 'error', 'EVIDENCE_CONFLICT');
  END IF;
  -- Same Gateway log must never settle two invocations.
  IF p_log_id IS NOT NULL THEN
    SELECT id INTO v_clash FROM public.user_ai_usage
    WHERE log_id = p_log_id AND id <> p_invocation_id;
    IF FOUND THEN
      RETURN jsonb_build_object('ok', false, 'error', 'EVIDENCE_CONFLICT', 'clash_usage_id', v_clash);
    END IF;
  END IF;
  IF p_cost_state = 'resolved' THEN
    -- Formula pinned to the operation's policy, not the currently active one.
    v_credits := round(v_cost * (1 + v_policy.markup_percent / 100) / v_policy.usd_per_credit, 12);
    UPDATE public.user_ai_usage SET
      invocation_status = p_invocation_status, input_tokens = p_input_tokens,
      output_tokens = p_output_tokens, duration_ms = p_duration_ms,
      log_id = p_log_id, ai_cost_usd = v_cost, cost_state = 'resolved',
      credits_used = v_credits, revision = revision + 1, settled_at = now()
    WHERE id = p_invocation_id;
    UPDATE public.user_ai_credit_accounts SET
      spent_credits = spent_credits + v_credits, revision = revision + 1, updated_at = now()
    WHERE id = v_acct.id
    RETURNING * INTO v_acct;
    INSERT INTO public.ai_credit_ledger (account_id, usage_id, kind, credit_delta, idempotency_key)
    VALUES (v_acct.id, p_invocation_id, 'debit', -v_credits, 'debit:' || p_invocation_id::text)
    ON CONFLICT (idempotency_key) DO NOTHING;
    INSERT INTO public.ai_credit_sync_outbox (account_id, revision)
    VALUES (v_acct.id, v_acct.revision);
    RETURN jsonb_build_object('ok', true, 'duplicate', false,
      'credits_used', v_credits::text,
      'spent_credits', v_acct.spent_credits::text,
      'remaining_credits', GREATEST(0::numeric, v_acct.granted_credits - v_acct.spent_credits)::text,
      'revision', v_acct.revision);
  ELSE
    -- unresolved / not_applicable: no debit, guard stays until resolved or waived.
    UPDATE public.user_ai_usage SET
      invocation_status = p_invocation_status, input_tokens = p_input_tokens,
      output_tokens = p_output_tokens, duration_ms = p_duration_ms,
      cost_state = p_cost_state, revision = revision + 1
    WHERE id = p_invocation_id;
    IF v_op.state = 'active' THEN
      UPDATE public.ai_credit_operations SET state = 'pending_cost', updated_at = now()
      WHERE id = v_op.id;
    END IF;
    RETURN jsonb_build_object('ok', true, 'duplicate', false, 'cost_state', p_cost_state,
      'revision', v_acct.revision);
  END IF;
END;
$$;

CREATE OR REPLACE FUNCTION public.finish_career_operation(
  p_operation_record_id uuid, p_state text
)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE v_op public.ai_credit_operations%ROWTYPE; v_acct public.user_ai_credit_accounts%ROWTYPE;
  v_open integer; v_cleared integer;
BEGIN
  IF p_state NOT IN ('completed', 'failed_no_dispatch', 'resolved_unbillable') THEN
    RETURN jsonb_build_object('ok', false, 'error', 'INVALID_INPUT');
  END IF;
  SELECT a.* INTO v_acct FROM public.user_ai_credit_accounts a
  JOIN public.ai_credit_operations o ON o.account_id = a.id
  WHERE o.id = p_operation_record_id FOR UPDATE OF a;
  IF NOT FOUND THEN
    RETURN jsonb_build_object('ok', false, 'error', 'NO_OPERATION');
  END IF;
  SELECT * INTO v_op FROM public.ai_credit_operations WHERE id = p_operation_record_id FOR UPDATE;
  IF v_op.state NOT IN ('active', 'pending_cost') THEN
    RETURN jsonb_build_object('ok', true, 'duplicate', true, 'state', v_op.state);
  END IF;
  IF p_state = 'failed_no_dispatch' THEN
    -- Proven-unsent only: every invocation must be undispatched.
    SELECT count(*) INTO v_open FROM public.user_ai_usage
    WHERE operation_record_id = p_operation_record_id AND started_at IS NOT NULL
      AND cost_state IN ('pending', 'unresolved');
    IF v_open > 0 THEN
      RETURN jsonb_build_object('ok', false, 'error', 'PENDING_COST');
    END IF;
    UPDATE public.user_ai_usage SET
      invocation_status = 'not_dispatched', cost_state = 'not_applicable',
      revision = revision + 1
    WHERE operation_record_id = p_operation_record_id AND cost_state = 'pending';
  ELSE
    SELECT count(*) INTO v_open FROM public.user_ai_usage
    WHERE operation_record_id = p_operation_record_id
      AND cost_state IN ('pending', 'unresolved');
    IF v_open > 0 THEN
      RETURN jsonb_build_object('ok', false, 'error', 'PENDING_COST', 'open_invocations', v_open);
    END IF;
  END IF;

  -- Release only our own guard; never another operation's.
  UPDATE public.user_ai_credit_accounts SET
    active_operation_id = NULL, active_execution_id = NULL,
    revision = revision + 1, updated_at = now()
  WHERE id = v_acct.id AND active_operation_id = v_op.operation_id;
  GET DIAGNOSTICS v_cleared = ROW_COUNT;
  IF v_cleared = 0 THEN
    RETURN jsonb_build_object('ok', false, 'error', 'GUARD_MISMATCH');
  END IF;
  UPDATE public.ai_credit_operations SET state = p_state, updated_at = now(), finished_at = now()
  WHERE id = p_operation_record_id;
  INSERT INTO public.ai_credit_sync_outbox (account_id, revision)
  SELECT id, revision FROM public.user_ai_credit_accounts WHERE id = v_acct.id;
  RETURN jsonb_build_object('ok', true, 'state', p_state);
END;
$$;

CREATE OR REPLACE FUNCTION public.waive_career_invocation(
  p_invocation_id uuid, p_operator text, p_reason text
)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE v_use public.user_ai_usage%ROWTYPE;
BEGIN
  IF p_operator IS NULL OR p_operator = '' OR p_reason IS NULL OR p_reason = '' THEN
    RETURN jsonb_build_object('ok', false, 'error', 'OPERATOR_REQUIRED');
  END IF;
  PERFORM 1 FROM public.user_ai_credit_accounts a
  JOIN public.ai_credit_operations o ON o.account_id = a.id
  JOIN public.user_ai_usage u ON u.operation_record_id = o.id
  WHERE u.id = p_invocation_id FOR UPDATE OF a;
  PERFORM 1 FROM public.ai_credit_operations o
  JOIN public.user_ai_usage u ON u.operation_record_id = o.id
  WHERE u.id = p_invocation_id FOR UPDATE OF o;
  SELECT * INTO v_use FROM public.user_ai_usage WHERE id = p_invocation_id FOR UPDATE;
  IF NOT FOUND THEN
    RETURN jsonb_build_object('ok', false, 'error', 'NO_USAGE');
  END IF;
  IF v_use.cost_state <> 'unresolved' THEN
    RETURN jsonb_build_object('ok', false, 'error', 'NOT_UNRESOLVED', 'cost_state', v_use.cost_state);
  END IF;
  UPDATE public.user_ai_usage SET
    cost_state = 'waived', credits_used = 0, revision = revision + 1, settled_at = now(),
    resolved_by = p_operator, resolution_reason = p_reason
  WHERE id = p_invocation_id;
  INSERT INTO public.ai_credit_ledger (account_id, usage_id, kind, credit_delta, idempotency_key)
  SELECT o.account_id, p_invocation_id, 'correction', 0, 'waive:' || p_invocation_id::text
  FROM public.ai_credit_operations o WHERE o.id = v_use.operation_record_id
  ON CONFLICT (idempotency_key) DO NOTHING;
  RETURN jsonb_build_object('ok', true, 'cost_state', 'waived');
END;
$$;
CREATE OR REPLACE FUNCTION public.protect_ai_credit_policy()
RETURNS trigger LANGUAGE plpgsql SET search_path = public AS $$
BEGIN
  IF EXISTS (SELECT 1 FROM public.ai_credit_operations WHERE policy_id = OLD.id) THEN
    IF TG_OP = 'DELETE' THEN RAISE EXCEPTION 'Referenced credit policies cannot be deleted'; END IF;
    IF (NEW.id, NEW.product_id, NEW.scope, NEW.markup_percent, NEW.usd_per_credit, NEW.created_at)
       IS DISTINCT FROM (OLD.id, OLD.product_id, OLD.scope, OLD.markup_percent, OLD.usd_per_credit, OLD.created_at) THEN
      RAISE EXCEPTION 'Referenced credit policy identity and rates are immutable';
    END IF;
  END IF;
  IF TG_OP = 'DELETE' THEN RETURN OLD; END IF;
  RETURN NEW;
END;
$$;
CREATE TRIGGER protect_ai_credit_policy BEFORE UPDATE OR DELETE ON public.ai_credit_policies
FOR EACH ROW EXECUTE FUNCTION public.protect_ai_credit_policy();

CREATE OR REPLACE FUNCTION public.protect_ai_credit_ledger()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'Credit ledger is append-only'; END;
$$;
CREATE TRIGGER protect_ai_credit_ledger BEFORE UPDATE OR DELETE ON public.ai_credit_ledger
FOR EACH ROW EXECUTE FUNCTION public.protect_ai_credit_ledger();
