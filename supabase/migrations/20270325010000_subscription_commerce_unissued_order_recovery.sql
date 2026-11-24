-- Explicit recovery for order reservations that never reached the payment provider.
-- Expand-only: adds one owner RPC and tightens complete_subscription_commerce_order.
-- No rows are changed by this migration. Applying it to any environment requires
-- explicit approval for that target.
--
-- Trigger (user-approved): a checkout status read finds the exact reserved order
-- operation with no receipt and its quote with no provider order. The application
-- first reads the provider by receipt (quote id). Only when the provider has no
-- order AND the quote has expired does it call this RPC. The void receipt is
-- durable evidence that no order was issued; it never creates or replaces an order.
BEGIN;
SET LOCAL lock_timeout='2s';
SET LOCAL statement_timeout='15s';

CREATE FUNCTION public.void_unissued_subscription_commerce_order(p_identity jsonb)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE o public.subscription_commerce_operations%ROWTYPE; q public.subscription_commerce_quotes%ROWTYPE; result jsonb;
BEGIN
  SELECT * INTO o FROM public.subscription_commerce_operations WHERE operation_id=(p_identity->>'operationId')::uuid FOR UPDATE;
  IF NOT FOUND OR o.identity IS DISTINCT FROM p_identity OR p_identity#>>'{request,kind}'<>'order' THEN RAISE EXCEPTION 'Exact reserved order required'; END IF;
  IF o.receipt IS NOT NULL THEN
    IF o.receipt->>'kind'='not_issued' THEN RETURN o.receipt; END IF;
    RAISE EXCEPTION 'Order already issued';
  END IF;
  SELECT * INTO q FROM public.subscription_commerce_quotes WHERE id=(o.evidence->>'quoteId')::uuid FOR UPDATE;
  IF NOT FOUND THEN RAISE EXCEPTION 'Issued quote required'; END IF;
  -- Scope is the exact identity validated when the order was reserved, bound to this quote.
  -- assert_subscription_commerce_scope is not used: it rejects the expired quotes this RPC requires.
  IF q.order_operation_id IS DISTINCT FROM o.operation_id OR q.provider_order_id IS NOT NULL THEN RAISE EXCEPTION 'Order already issued'; END IF;
  IF (q.quote->>'validUntil')::numeric>extract(epoch FROM clock_timestamp())*1000 THEN RAISE EXCEPTION 'Quote is still valid; order may be in progress'; END IF;
  result:=jsonb_build_object('kind','not_issued','operationId',o.operation_id,'quoteId',q.id,
    'voidedAt',floor(extract(epoch FROM clock_timestamp())*1000)::bigint);
  UPDATE public.subscription_commerce_operations SET receipt=result WHERE operation_id=o.operation_id;
  RETURN result;
END;
$$;

-- Unchanged except for the not_issued guard: a voided reservation can never be
-- completed by a late provider response.
CREATE OR REPLACE FUNCTION public.complete_subscription_commerce_order(p_identity jsonb,p_order jsonb)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE o public.subscription_commerce_operations%ROWTYPE; q public.subscription_commerce_quotes%ROWTYPE; result jsonb;
BEGIN
  SELECT * INTO o FROM public.subscription_commerce_operations WHERE operation_id=(p_identity->>'operationId')::uuid FOR UPDATE;
  IF NOT FOUND OR o.identity IS DISTINCT FROM p_identity OR p_identity#>>'{request,kind}'<>'order' THEN RAISE EXCEPTION 'Exact reserved order required'; END IF;
  IF o.receipt->>'kind'='not_issued' THEN RAISE EXCEPTION 'Order reservation was voided as not issued'; END IF;
  IF o.receipt IS NOT NULL THEN RETURN o.receipt; END IF;
  SELECT * INTO q FROM public.subscription_commerce_quotes WHERE id=(o.evidence->>'quoteId')::uuid FOR UPDATE;
  PERFORM public.assert_subscription_commerce_scope(p_identity,q.quote);
  IF q.order_operation_id<>o.operation_id OR q.provider_order_id IS NOT NULL OR p_order->>'id'!~'^order_[A-Za-z0-9]+$'
    OR p_order->'amount' IS DISTINCT FROM q.quote->'amountMinor' OR p_order->'currency' IS DISTINCT FROM q.quote->'currency'
    OR p_order->>'receipt' IS DISTINCT FROM q.id::text OR p_order#>>'{notes,subscription_quote_id}' IS DISTINCT FROM q.id::text
    OR p_order#>'{notes,subscription_id}' IS DISTINCT FROM q.quote->'subscriptionId' THEN RAISE EXCEPTION 'Provider order differs'; END IF;
  result:=jsonb_build_object('kind','order','operationId',o.operation_id,'quoteId',q.id,'order',p_order);
  UPDATE public.subscription_commerce_quotes SET provider_order_id=p_order->>'id' WHERE id=q.id;
  UPDATE public.subscription_commerce_operations SET receipt=result WHERE operation_id=o.operation_id;
  RETURN result;
END;
$$;

REVOKE ALL ON FUNCTION public.void_unissued_subscription_commerce_order(jsonb),public.complete_subscription_commerce_order(jsonb,jsonb) FROM PUBLIC,anon,authenticated;
GRANT EXECUTE ON FUNCTION public.void_unissued_subscription_commerce_order(jsonb),public.complete_subscription_commerce_order(jsonb,jsonb) TO service_role;
COMMIT;
