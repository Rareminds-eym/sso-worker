-- Request lifecycle ends independently from immutable usage accounting.
ALTER TABLE public.ai_credit_operations DROP CONSTRAINT ai_credit_operations_state_check;
ALTER TABLE public.ai_credit_operations ADD CONSTRAINT ai_credit_operations_state_check
 CHECK(state IN ('active','pending_cost','completed','failed_no_dispatch','resolved_unbillable','cancelled'));
CREATE OR REPLACE FUNCTION public.finish_career_operation(
  p_operation_record_id uuid, p_state text
)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE v_op public.ai_credit_operations%ROWTYPE; v_acct public.user_ai_credit_accounts%ROWTYPE;
  v_open integer; v_cleared integer;
BEGIN
  IF p_state NOT IN ('completed', 'failed_no_dispatch', 'resolved_unbillable', 'cancelled') THEN
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
  IF p_state = 'cancelled' THEN
    NULL; -- Cost recovery remains independent; do not change usage.
  ELSIF p_state = 'failed_no_dispatch' THEN
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
  WHERE id = v_acct.id AND active_operation_id = v_op.operation_id AND active_execution_id = v_op.execution_id;
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
    IF EXISTS (SELECT 1 FROM public.ai_credit_operations
      WHERE account_id = v_acct.id AND operation_id = v_acct.active_operation_id AND state = 'pending_cost') THEN
      RETURN jsonb_build_object('ok', false, 'error', 'PENDING_COST');
    END IF;
    RETURN jsonb_build_object('ok', false, 'error', 'IN_PROGRESS',
      'active_operation_id', v_acct.active_operation_id);
  END IF;
  IF (SELECT count(*) FROM public.ai_credit_operations o
      WHERE o.account_id = v_acct.id AND o.state = 'cancelled'
      AND EXISTS (SELECT 1 FROM public.user_ai_usage u WHERE u.operation_record_id = o.id
        AND u.cost_state IN ('pending', 'unresolved'))) >= 3 THEN
    RETURN jsonb_build_object('ok', false, 'error', 'PENDING_COST');
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

CREATE OR REPLACE FUNCTION public.cancel_career_execution(p_user_id uuid, p_execution_id text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=public AS $$
DECLARE op uuid;
BEGIN
 SELECT o.id INTO op FROM public.ai_credit_operations o
 JOIN public.user_ai_credit_accounts a ON a.id=o.account_id
 WHERE a.user_id=p_user_id AND o.execution_id=p_execution_id AND a.scope='career_ai'
 AND a.product_id=(SELECT id FROM public.products WHERE code='skillpassport');
 IF op IS NULL THEN RETURN jsonb_build_object('ok',true,'duplicate',true); END IF;
 RETURN public.finish_career_operation(op,'cancelled');
END $$;
REVOKE ALL ON FUNCTION public.cancel_career_execution(uuid,text) FROM PUBLIC,anon,authenticated;
GRANT EXECUTE ON FUNCTION public.cancel_career_execution(uuid,text) TO service_role;
