-- Prepared only: requires explicit target-specific deployment approval.
-- Keep subscription activation and its immutable payment evidence in one
-- transaction. Existing completed transactions remain the replay authority.
BEGIN;

CREATE FUNCTION public.fulfill_subscription_payment(p_input jsonb)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE
  buyer uuid := (p_input->>'user_id')::uuid;
  selected_plan uuid := (p_input->>'plan_id')::uuid;
  org uuid := nullif(p_input->>'organization_id','')::uuid;
  payment_id text := p_input->>'razorpay_payment_id';
  order_id text := p_input->>'razorpay_order_id';
  paid numeric := (p_input->>'amount')::numeric;
  cycle text := p_input->>'billing_cycle';
  catalog public.plans;
  subscription_row public.subscriptions;
  transaction_row public.transactions;
  existing_count integer;
  upgraded boolean := false;
  org_purchase boolean;
  seat_capacity integer := coalesce((p_input->>'seat_count')::integer,1);
  configured_capacity integer;
BEGIN
  IF buyer IS NULL OR selected_plan IS NULL OR nullif(btrim(payment_id),'') IS NULL
    OR nullif(btrim(order_id),'') IS NULL OR paid IS NULL OR paid <= 0
    OR paid::text IN ('NaN','Infinity','-Infinity') OR paid <> round(paid,2)
    OR cycle IS NULL OR cycle NOT IN ('monthly','yearly')
    OR p_input->>'currency' IS DISTINCT FROM 'INR' THEN
    RAISE EXCEPTION 'Invalid verified subscription payment';
  END IF;

  -- Serialize every activation path by payment, then by buyer. Both browser
  -- verification and captured-payment webhooks call this function.
  PERFORM pg_advisory_xact_lock(hashtextextended('subscription-payment:' || payment_id, 0));
  PERFORM pg_advisory_xact_lock(hashtextextended('subscription-order:' || order_id, 0));
  PERFORM pg_advisory_xact_lock(hashtextextended('subscription-buyer:' || buyer::text, 0));

  SELECT count(*) INTO existing_count FROM public.transactions WHERE razorpay_payment_id = payment_id;
  IF existing_count > 1 THEN RAISE EXCEPTION 'Payment requires transaction reconciliation'; END IF;
  SELECT * INTO transaction_row FROM public.transactions WHERE razorpay_payment_id = payment_id FOR UPDATE;
  IF FOUND THEN
    IF transaction_row.status <> 'completed' OR transaction_row.transaction_type NOT IN ('subscription','upgrade')
      OR transaction_row.user_id <> buyer OR transaction_row.razorpay_order_id IS DISTINCT FROM order_id
      OR transaction_row.organization_id IS DISTINCT FROM org OR transaction_row.amount <> paid
      OR transaction_row.currency <> 'INR'
      OR transaction_row.metadata#>>'{plan,id}' IS DISTINCT FROM selected_plan::text THEN
      RAISE EXCEPTION 'Payment fulfillment identity or terms mismatch';
    END IF;
    SELECT * INTO subscription_row FROM public.subscriptions WHERE id = transaction_row.subscription_id;
    IF NOT FOUND OR subscription_row.user_id <> buyer OR subscription_row.organization_id IS DISTINCT FROM org THEN
      RAISE EXCEPTION 'Payment fulfillment subscription mismatch';
    END IF;
    RETURN jsonb_build_object('subscription', to_jsonb(subscription_row), 'transaction_id', transaction_row.id,
      'already_fulfilled', true, 'is_upgrade', transaction_row.transaction_type = 'upgrade',
      'receipt_url', transaction_row.receipt_url);
  END IF;

  SELECT * INTO catalog FROM public.plans WHERE id = selected_plan AND is_active = true;
  IF NOT FOUND OR catalog.business_type NOT IN ('b2b','b2c') THEN RAISE EXCEPTION 'Selected plan is unavailable'; END IF;
  org_purchase := catalog.business_type = 'b2b';
  IF org_purchase <> (org IS NOT NULL) THEN RAISE EXCEPTION 'Subscription audience mismatch'; END IF;
  IF seat_capacity = 1 AND jsonb_typeof(catalog.entity_config) = 'object' THEN
    SELECT (entry.value->>'max_users')::integer INTO configured_capacity
      FROM jsonb_each(catalog.entity_config) AS entry
      WHERE entry.value->>'max_users' IS NOT NULL LIMIT 1;
    IF configured_capacity IS NOT NULL THEN seat_capacity := configured_capacity; END IF;
  END IF;
  IF seat_capacity < 1 THEN RAISE EXCEPTION 'Invalid catalogue seat capacity'; END IF;

  -- A reused order must never become another subscription transaction.
  IF EXISTS (SELECT 1 FROM public.transactions WHERE razorpay_order_id = order_id AND transaction_type IN ('subscription','upgrade')) THEN
    RAISE EXCEPTION 'Order already has a different subscription payment';
  END IF;
  SELECT * INTO subscription_row FROM public.subscriptions
    WHERE user_id = buyer AND is_organization_subscription IS NOT DISTINCT FROM org_purchase
      AND is_bulk_purchase IS NOT TRUE AND organization_id IS NOT DISTINCT FROM org
      AND product_id IS NOT DISTINCT FROM catalog.product_id
      AND status IN ('active','pending','grace_period')
    ORDER BY subscription_start_date DESC NULLS LAST LIMIT 1 FOR UPDATE;
  IF FOUND THEN
    -- Missing transaction evidence is an explicit reconciliation error; do
    -- not guess that a different historical payment is new or fulfilled.
    IF subscription_row.razorpay_payment_id = payment_id THEN RAISE EXCEPTION 'Payment requires transaction reconciliation'; END IF;
    IF subscription_row.status = 'pending' THEN RAISE EXCEPTION 'Existing subscription is still activating'; END IF;
    IF subscription_row.plan_id = selected_plan OR subscription_row.plan_amount IS NULL OR paid <= subscription_row.plan_amount THEN
      RAISE EXCEPTION 'Cannot downgrade or lateral move';
    END IF;
    upgraded := true;
    UPDATE public.subscriptions SET plan_id = catalog.id, plan_code = catalog.plan_code, plan_type = catalog.name,
      plan_amount = paid, billing_cycle = cycle, features = catalog.base_features, seat_count = seat_capacity,
      razorpay_order_id = order_id, razorpay_payment_id = payment_id,
      subscription_start_date = now(), subscription_end_date = now() + make_interval(months => CASE cycle WHEN 'yearly' THEN 12 ELSE 1 END),
      status = 'active', auto_renew = true, receipt_url = NULL, updated_at = now()
      WHERE id = subscription_row.id RETURNING * INTO subscription_row;
  ELSE
    INSERT INTO public.subscriptions(user_id,plan_id,plan_code,plan_type,plan_amount,billing_cycle,features,full_name,email,
      organization_id,organization_type,is_organization_subscription,is_bulk_purchase,seat_count,product_id,
      razorpay_order_id,razorpay_payment_id,subscription_start_date,subscription_end_date,status,auto_renew)
    VALUES(buyer,catalog.id,catalog.plan_code,catalog.name,paid,cycle,catalog.base_features,
      p_input->>'full_name',p_input->>'email',org,p_input->>'organization_type',org_purchase,false,
      seat_capacity,catalog.product_id,order_id,payment_id,now(),
      now() + make_interval(months => CASE cycle WHEN 'yearly' THEN 12 ELSE 1 END),'active',true)
    RETURNING * INTO subscription_row;
  END IF;

  INSERT INTO public.transactions(subscription_id,user_id,organization_id,organization_type,product_id,seat_count,is_bulk_purchase,
    razorpay_order_id,razorpay_payment_id,razorpay_signature,amount,currency,status,transaction_type,payment_method,metadata)
  VALUES(subscription_row.id,buyer,org,p_input->>'organization_type',catalog.product_id,subscription_row.seat_count,false,order_id,payment_id,
    p_input->>'razorpay_signature',paid,'INR','completed',CASE WHEN upgraded THEN 'upgrade' ELSE 'subscription' END,
    p_input->>'payment_method',jsonb_build_object('plan',jsonb_build_object('id',catalog.id,'code',catalog.plan_code,'name',catalog.name,'billing_cycle',cycle)))
  RETURNING * INTO transaction_row;
  RETURN jsonb_build_object('subscription',to_jsonb(subscription_row),'transaction_id',transaction_row.id,
    'already_fulfilled',false,'is_upgrade',upgraded);
END; $$;

REVOKE ALL ON FUNCTION public.fulfill_subscription_payment(jsonb) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.fulfill_subscription_payment(jsonb) TO service_role;
COMMIT;
