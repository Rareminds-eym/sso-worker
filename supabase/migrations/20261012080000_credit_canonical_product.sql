-- Return canonical product identity without local UUID configuration.
CREATE OR REPLACE FUNCTION public.career_credit_balance_json(p_account_id uuid)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE v_acct public.user_ai_credit_accounts%ROWTYPE; v_pending boolean;
BEGIN
  SELECT * INTO v_acct FROM public.user_ai_credit_accounts WHERE id = p_account_id;
  IF NOT FOUND THEN
    RETURN jsonb_build_object('ok', false, 'error', 'NO_ACCOUNT');
  END IF;
  SELECT EXISTS (
    SELECT 1 FROM public.user_ai_usage u
    JOIN public.ai_credit_operations o ON o.id = u.operation_record_id
    WHERE o.account_id = p_account_id
      AND o.state IN ('active', 'pending_cost')
      AND u.cost_state IN ('pending', 'unresolved')
  ) INTO v_pending;
  RETURN jsonb_build_object(
    'ok', true,
    'account_id', v_acct.id,
    'product_id', v_acct.product_id,
    'granted_credits', v_acct.granted_credits::text,
    'spent_credits', v_acct.spent_credits::text,
    'remaining_credits', GREATEST(0::numeric, v_acct.granted_credits - v_acct.spent_credits)::text,
    'revision', v_acct.revision,
    'active_operation_id', v_acct.active_operation_id,
    'has_pending_cost', v_pending
  );
END;
$$;
