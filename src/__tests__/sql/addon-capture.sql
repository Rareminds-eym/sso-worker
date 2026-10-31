\set ON_ERROR_STOP on
BEGIN;
DO $$
DECLARE u uuid; product uuid; addon uuid:=gen_random_uuid(); p jsonb; p2 jsonb; reserved jsonb; n integer;
BEGIN
 SELECT id INTO STRICT u FROM public.users LIMIT 1;SELECT id INTO STRICT product FROM public.products LIMIT 1;
 INSERT INTO public.addon_catalog(id,product_id,category,feature_key,feature_name,price_monthly,currency,minor_unit,monthly_enabled,monthly_label,monthly_duration_months,fulfilment_kind,target_feature_key,fulfilment_quantity,requires_organization,allow_repeat_purchase)
 VALUES(addon,product,'learning','db_test_feature','Database Test',371,'INR',2,true,'Monthly',3,'access','db_test_feature',1,false,false);
 reserved:=public.prepare_addon_checkout(u,addon,'monthly');
 IF NOT (reserved->>'checkout_created')::boolean OR reserved->>'end_date' IS NOT NULL THEN RAISE EXCEPTION 'Checkout reservation granted access prematurely'; END IF;
 p2:=public.prepare_addon_checkout(u,addon,'monthly');IF (p2->>'checkout_created')::boolean OR p2->>'id'<>reserved->>'id' THEN RAISE EXCEPTION 'Duplicate checkout reservation created'; END IF;
 -- Product configuration can change without changing the agreed purchase.
 UPDATE public.addon_catalog SET price_monthly=9999,fulfilment_quantity=4,monthly_label='Changed' WHERE id=addon;
 p:=public.record_addon_capture(u,addon,'monthly','order_capture_test','pay_capture_test',37100,'INR',p_prepared_purchase_id=>(reserved->>'id')::uuid);
 IF p->>'id'<>reserved->>'id' OR p->>'status'<>'pending' OR (p->>'price_at_purchase')::numeric<>371 OR (p->'offer'->>'quantity')::integer<>1 OR p->'offer'->>'display_name'<>'Monthly' THEN RAISE EXCEPTION 'Capture did not preserve the agreed terms'; END IF;
 p2:=public.record_addon_capture(u,addon,'monthly','order_capture_test','pay_capture_test',37100,'INR');
 IF p->>'id'<>p2->>'id' OR p->>'end_date'<>p2->>'end_date' THEN RAISE EXCEPTION 'Capture replay duplicated or extended purchase'; END IF;
 SELECT count(*) INTO n FROM public.transactions WHERE addon_purchase_id=(p->>'id')::uuid;IF n<>1 THEN RAISE EXCEPTION 'Accounting record duplicated'; END IF;
 BEGIN UPDATE public.addon_purchases SET amount_minor=1 WHERE id=(p->>'id')::uuid;RAISE EXCEPTION 'Agreed terms changed';EXCEPTION WHEN raise_exception THEN IF SQLERRM='Agreed terms changed' THEN RAISE;END IF;END;
 BEGIN PERFORM public.record_addon_capture(gen_random_uuid(),addon,'monthly','order_capture_test','pay_capture_test',37100,'INR');RAISE EXCEPTION 'Ownership mismatch accepted';EXCEPTION WHEN raise_exception THEN IF SQLERRM='Ownership mismatch accepted' THEN RAISE;END IF;END;
 BEGIN PERFORM public.record_addon_capture(u,addon,'monthly','order_wrong','pay_wrong',100,'INR');RAISE EXCEPTION 'Incorrect amount accepted';EXCEPTION WHEN raise_exception THEN IF SQLERRM='Incorrect amount accepted' THEN RAISE;END IF;END;
 IF EXISTS(SELECT 1 FROM public.addon_purchases WHERE razorpay_payment_id='pay_wrong') THEN RAISE EXCEPTION 'Rejected payment created a purchase'; END IF;
 IF to_regclass('public.addon_price_options') IS NOT NULL THEN RAISE EXCEPTION 'Draft offer table was not removed'; END IF;
 RAISE NOTICE 'PASS: existing-table reservation, snapshot stability, replay, accounting, immutable agreed terms, ownership and amount validation';
END; $$;
ROLLBACK;
