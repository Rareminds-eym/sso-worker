-- Reuses the existing catalog, purchases and transactions. No new tables.
BEGIN;
-- Current product definition and pricing configuration only. These fields never
-- contain a buyer, order, payment, selected period, or paid transaction amount.
ALTER TABLE public.addon_catalog
  ADD COLUMN IF NOT EXISTS benefits text[] NOT NULL DEFAULT '{}',
  ADD COLUMN currency varchar(3) CHECK(currency ~ '^[A-Z]{3}$'),
  ADD COLUMN minor_unit smallint CHECK(minor_unit BETWEEN 0 AND 4),
  ADD COLUMN monthly_enabled boolean NOT NULL DEFAULT false,
  ADD COLUMN annual_enabled boolean NOT NULL DEFAULT false,
  ADD COLUMN monthly_label text,
  ADD COLUMN annual_label text,
  ADD COLUMN monthly_duration_months integer CHECK(monthly_duration_months>0),
  ADD COLUMN annual_duration_months integer CHECK(annual_duration_months>0),
  ADD COLUMN fulfilment_kind text CHECK(fulfilment_kind IN ('access','credits','numeric_limit','opportunity_visibility','tenant_visibility')),
  ADD COLUMN target_feature_key text,
  ADD COLUMN fulfilment_quantity integer CHECK(fulfilment_quantity>0),
  ADD COLUMN fulfilment_duration_days integer CHECK(fulfilment_duration_days>0),
  ADD COLUMN requires_organization boolean NOT NULL DEFAULT false,
  ADD COLUMN allow_repeat_purchase boolean NOT NULL DEFAULT false;

-- Transaction facts and the immutable contract belong to the purchase itself.
ALTER TABLE public.addon_purchases
  ADD COLUMN addon_id uuid REFERENCES public.addon_catalog(id),
  ADD COLUMN organization_id uuid,
  ADD COLUMN opportunity_id bigint,
  ADD COLUMN billing_label text,
  ADD COLUMN amount_minor bigint CHECK(amount_minor>0),
  ADD COLUMN currency varchar(3),
  ADD COLUMN minor_unit smallint CHECK(minor_unit BETWEEN 0 AND 4),
  ADD COLUMN interval_months integer CHECK(interval_months>0),
  ADD COLUMN fulfilment_kind text,
  ADD COLUMN target_feature_key text,
  ADD COLUMN quantity integer CHECK(quantity>0),
  ADD COLUMN duration_days integer CHECK(duration_days>0),
  ADD COLUMN requires_organization boolean,
  ADD COLUMN allow_repeat_purchase boolean,
  ADD COLUMN target_roles text[];
CREATE INDEX addon_purchases_catalog ON public.addon_purchases(addon_id);
CREATE INDEX addon_purchases_pending_checkout ON public.addon_purchases(user_id,feature_key,created_at) WHERE status='pending';
ALTER TABLE public.transactions ADD COLUMN addon_purchase_id uuid REFERENCES public.addon_purchases(id);
CREATE UNIQUE INDEX transaction_addon_purchase ON public.transactions(addon_purchase_id) WHERE addon_purchase_id IS NOT NULL;

-- Adapts the catalog's existing monthly/annual price columns into a consistent
-- read contract. Labels, enabled choices, amounts, units and duration are DB data.
CREATE FUNCTION public.addon_checkout_options(p_addon_id uuid)
RETURNS TABLE(id text,addon_id uuid,billing_period text,display_name text,amount_minor bigint,currency text,minor_unit smallint,interval_months integer,fulfilment_kind text,target_feature_key text,quantity integer,duration_days integer,requires_organization boolean,allow_repeat_purchase boolean,is_active boolean)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $$
 SELECT a.id::text||':'||t.period,a.id,t.period,t.label,round(t.price*power(10::numeric,a.minor_unit))::bigint,a.currency::text,a.minor_unit,t.months,a.fulfilment_kind,a.target_feature_key,a.fulfilment_quantity,a.fulfilment_duration_days,a.requires_organization,a.allow_repeat_purchase,a.is_active
 FROM public.addon_catalog a CROSS JOIN LATERAL (VALUES
   ('monthly',a.price_monthly,a.monthly_label,a.monthly_duration_months,a.monthly_enabled),
   ('annual',a.price_annual,a.annual_label,a.annual_duration_months,a.annual_enabled)
 ) t(period,price,label,months,enabled)
 WHERE a.id=p_addon_id AND a.is_active AND t.enabled AND t.price>0 AND t.months>0 AND t.label IS NOT NULL AND a.currency IS NOT NULL AND a.minor_unit IS NOT NULL AND a.fulfilment_kind IS NOT NULL AND a.target_feature_key IS NOT NULL AND a.fulfilment_quantity>0
 ORDER BY t.months;
$$;
REVOKE ALL ON FUNCTION public.addon_checkout_options(uuid) FROM PUBLIC,anon,authenticated;
GRANT EXECUTE ON FUNCTION public.addon_checkout_options(uuid) TO service_role;

CREATE FUNCTION public.addon_catalog_payload(p_category text DEFAULT NULL,p_role text DEFAULT NULL,p_product_id uuid DEFAULT NULL)
RETURNS jsonb LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $$
 SELECT coalesce(jsonb_agg(to_jsonb(a)||jsonb_build_object('billing_options',coalesce((SELECT jsonb_agg(to_jsonb(o) ORDER BY o.interval_months) FROM public.addon_checkout_options(a.id) o),'[]'::jsonb)) ORDER BY a.display_order),'[]'::jsonb)
 FROM public.addon_catalog a WHERE a.is_active AND (p_category IS NULL OR a.category=p_category) AND (p_role IS NULL OR p_role=ANY(a.target_roles)) AND (p_product_id IS NULL OR a.product_id=p_product_id);
$$;
REVOKE ALL ON FUNCTION public.addon_catalog_payload(text,text,uuid) FROM PUBLIC,anon,authenticated;
GRANT EXECUTE ON FUNCTION public.addon_catalog_payload(text,text,uuid) TO service_role;

CREATE FUNCTION public.addon_purchase_contract(p public.addon_purchases) RETURNS jsonb
LANGUAGE sql STABLE SET search_path=pg_catalog,public AS $$
 SELECT to_jsonb(p)||jsonb_build_object('offer',jsonb_build_object(
   'id',p.id,'addon_id',p.addon_id,'billing_period',p.billing_period,'display_name',p.billing_label,
   'amount_minor',p.amount_minor,'currency',p.currency,'minor_unit',p.minor_unit,'interval_months',p.interval_months,
   'fulfilment_kind',p.fulfilment_kind,'target_feature_key',p.target_feature_key,'quantity',p.quantity,
   'duration_days',p.duration_days,'requires_organization',p.requires_organization,'allow_repeat_purchase',p.allow_repeat_purchase,'is_active',true));
$$;
REVOKE ALL ON FUNCTION public.addon_purchase_contract(public.addon_purchases) FROM PUBLIC,anon,authenticated;
GRANT EXECUTE ON FUNCTION public.addon_purchase_contract(public.addon_purchases) TO service_role;

CREATE FUNCTION public.recorded_addon_contract(p_payment_id text DEFAULT NULL,p_purchase_id uuid DEFAULT NULL)
RETURNS jsonb LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $$
 SELECT public.addon_purchase_contract(p) FROM public.addon_purchases p
 WHERE ((p_payment_id IS NOT NULL AND p.razorpay_payment_id=p_payment_id) OR (p_purchase_id IS NOT NULL AND p.id=p_purchase_id)) AND p.amount_minor IS NOT NULL LIMIT 1;
$$;
REVOKE ALL ON FUNCTION public.recorded_addon_contract(text,uuid) FROM PUBLIC,anon,authenticated;
GRANT EXECUTE ON FUNCTION public.recorded_addon_contract(text,uuid) TO service_role;

CREATE FUNCTION public.protect_addon_purchase_terms() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,public AS $$
BEGIN
 IF OLD.amount_minor IS NOT NULL AND ROW(NEW.user_id,NEW.product_id,NEW.feature_key,NEW.addon_id,NEW.organization_id,NEW.opportunity_id,NEW.billing_period,NEW.billing_label,NEW.amount_minor,NEW.price_at_purchase,NEW.currency,NEW.minor_unit,NEW.interval_months,NEW.fulfilment_kind,NEW.target_feature_key,NEW.quantity,NEW.duration_days,NEW.requires_organization,NEW.allow_repeat_purchase,NEW.target_roles)
 IS DISTINCT FROM ROW(OLD.user_id,OLD.product_id,OLD.feature_key,OLD.addon_id,OLD.organization_id,OLD.opportunity_id,OLD.billing_period,OLD.billing_label,OLD.amount_minor,OLD.price_at_purchase,OLD.currency,OLD.minor_unit,OLD.interval_months,OLD.fulfilment_kind,OLD.target_feature_key,OLD.quantity,OLD.duration_days,OLD.requires_organization,OLD.allow_repeat_purchase,OLD.target_roles)
 THEN RAISE EXCEPTION 'Agreed purchase terms are immutable'; END IF;
 IF (OLD.razorpay_order_id IS NOT NULL AND NEW.razorpay_order_id IS DISTINCT FROM OLD.razorpay_order_id) OR
    (OLD.razorpay_payment_id IS NOT NULL AND ROW(NEW.razorpay_payment_id,NEW.start_date,NEW.end_date) IS DISTINCT FROM ROW(OLD.razorpay_payment_id,OLD.start_date,OLD.end_date))
 THEN RAISE EXCEPTION 'Recorded payment identity and access dates are immutable'; END IF;
 RETURN NEW;
END; $$;
CREATE TRIGGER addon_purchase_terms_immutable BEFORE UPDATE ON public.addon_purchases FOR EACH ROW EXECUTE FUNCTION public.protect_addon_purchase_terms();

CREATE FUNCTION public.prepare_addon_checkout(p_user_id uuid,p_addon_id uuid,p_billing_period text,p_organization_id uuid DEFAULT NULL,p_opportunity_id bigint DEFAULT NULL)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE terms record; addon public.addon_catalog; purchase public.addon_purchases;
BEGIN
 SELECT * INTO STRICT addon FROM public.addon_catalog WHERE id=p_addon_id AND is_active;
 PERFORM pg_advisory_xact_lock(hashtextextended('addon-checkout:'||p_user_id::text||':'||addon.id::text,0));
 SELECT * INTO purchase FROM public.addon_purchases WHERE user_id=p_user_id AND product_id=addon.product_id AND feature_key=addon.feature_key AND status='pending' ORDER BY created_at LIMIT 1 FOR UPDATE;
 IF FOUND THEN RETURN public.addon_purchase_contract(purchase)||jsonb_build_object('checkout_created',false); END IF;
 SELECT * INTO STRICT terms FROM public.addon_checkout_options(p_addon_id) WHERE billing_period=p_billing_period;
 IF NOT terms.allow_repeat_purchase AND EXISTS(SELECT 1 FROM public.addon_purchases WHERE user_id=p_user_id AND feature_key=addon.feature_key AND product_id=addon.product_id AND status IN ('active','grace_period','cancelled') AND end_date>now()) THEN RAISE EXCEPTION 'Add-on is already active'; END IF;
 IF terms.requires_organization AND p_organization_id IS NULL THEN RAISE EXCEPTION 'Organization is required'; END IF;
 IF terms.fulfilment_kind='opportunity_visibility' AND p_opportunity_id IS NULL THEN RAISE EXCEPTION 'Opportunity is required'; END IF;
 INSERT INTO public.addon_purchases(user_id,product_id,feature_key,billing_period,price_at_purchase,status,end_date,auto_renew,addon_id,organization_id,opportunity_id,billing_label,amount_minor,currency,minor_unit,interval_months,fulfilment_kind,target_feature_key,quantity,duration_days,requires_organization,allow_repeat_purchase,target_roles)
 VALUES(p_user_id,addon.product_id,addon.feature_key,terms.billing_period,terms.amount_minor/power(10::numeric,terms.minor_unit),'pending',NULL,false,addon.id,p_organization_id,p_opportunity_id,terms.display_name,terms.amount_minor,terms.currency,terms.minor_unit,terms.interval_months,terms.fulfilment_kind,terms.target_feature_key,terms.quantity,terms.duration_days,terms.requires_organization,terms.allow_repeat_purchase,addon.target_roles) RETURNING * INTO purchase;
 RETURN public.addon_purchase_contract(purchase)||jsonb_build_object('checkout_created',true);
END; $$;
REVOKE ALL ON FUNCTION public.prepare_addon_checkout(uuid,uuid,text,uuid,bigint) FROM PUBLIC,anon,authenticated;
GRANT EXECUTE ON FUNCTION public.prepare_addon_checkout(uuid,uuid,text,uuid,bigint) TO service_role;

CREATE FUNCTION public.record_addon_capture(p_user_id uuid,p_addon_id uuid,p_billing_period text,p_order_id text,p_payment_id text,p_amount_minor bigint,p_currency text,p_signature text DEFAULT NULL,p_method text DEFAULT NULL,p_organization_id uuid DEFAULT NULL,p_opportunity_id bigint DEFAULT NULL,p_prepared_purchase_id uuid DEFAULT NULL)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE purchase public.addon_purchases; transaction_row public.transactions; reserved jsonb;
BEGIN
 PERFORM pg_advisory_xact_lock(hashtextextended('addon-payment:'||p_payment_id,0));
 SELECT * INTO purchase FROM public.addon_purchases WHERE razorpay_payment_id=p_payment_id OR razorpay_order_id=p_order_id OR id=p_prepared_purchase_id FOR UPDATE;
 IF NOT FOUND OR purchase.amount_minor IS NULL THEN
   -- Older captured orders are adopted only when their amount/currency agree
   -- with current catalog terms. An already-snapshotted purchase never re-prices.
   IF purchase.id IS NOT NULL THEN
     IF purchase.user_id<>p_user_id OR purchase.feature_key<>(SELECT feature_key FROM public.addon_catalog WHERE id=p_addon_id) OR purchase.billing_period<>p_billing_period THEN RAISE EXCEPTION 'Legacy purchase ownership or terms mismatch'; END IF;
     -- The pending legacy row has no contract. Fill only this explicitly reconciled payment.
     DECLARE terms record; addon public.addon_catalog;
     BEGIN
       SELECT * INTO STRICT terms FROM public.addon_checkout_options(p_addon_id) WHERE billing_period=p_billing_period;
       SELECT * INTO STRICT addon FROM public.addon_catalog WHERE id=p_addon_id;
       IF terms.amount_minor<>p_amount_minor OR terms.currency<>p_currency OR purchase.price_at_purchase<>terms.amount_minor/power(10::numeric,terms.minor_unit) THEN RAISE EXCEPTION 'Legacy payment requires price reconciliation'; END IF;
       UPDATE public.addon_purchases SET addon_id=p_addon_id,organization_id=p_organization_id,opportunity_id=p_opportunity_id,billing_label=terms.display_name,amount_minor=terms.amount_minor,currency=terms.currency,minor_unit=terms.minor_unit,interval_months=terms.interval_months,fulfilment_kind=terms.fulfilment_kind,target_feature_key=terms.target_feature_key,quantity=terms.quantity,duration_days=terms.duration_days,requires_organization=terms.requires_organization,allow_repeat_purchase=terms.allow_repeat_purchase,target_roles=addon.target_roles WHERE id=purchase.id RETURNING * INTO purchase;
     END;
   ELSE
     reserved:=public.prepare_addon_checkout(p_user_id,p_addon_id,p_billing_period,p_organization_id,p_opportunity_id);
     SELECT * INTO STRICT purchase FROM public.addon_purchases WHERE id=(reserved->>'id')::uuid FOR UPDATE;
   END IF;
 END IF;
 IF purchase.user_id<>p_user_id OR purchase.addon_id<>p_addon_id OR purchase.billing_period<>p_billing_period OR purchase.amount_minor<>p_amount_minor OR purchase.currency<>p_currency OR purchase.organization_id IS DISTINCT FROM p_organization_id OR purchase.opportunity_id IS DISTINCT FROM p_opportunity_id OR (purchase.razorpay_order_id IS NOT NULL AND purchase.razorpay_order_id<>p_order_id) OR (purchase.razorpay_payment_id IS NOT NULL AND purchase.razorpay_payment_id<>p_payment_id) THEN RAISE EXCEPTION 'Captured payment does not match the agreed purchase'; END IF;
 IF purchase.requires_organization AND p_organization_id IS NULL THEN RAISE EXCEPTION 'Organization is required'; END IF;
 IF purchase.fulfilment_kind='opportunity_visibility' AND p_opportunity_id IS NULL THEN RAISE EXCEPTION 'Opportunity is required'; END IF;
 IF purchase.razorpay_payment_id IS NULL THEN
   UPDATE public.addon_purchases SET razorpay_order_id=p_order_id,razorpay_payment_id=p_payment_id,razorpay_signature=p_signature,status='pending',start_date=now(),end_date=now()+make_interval(months=>purchase.interval_months) WHERE id=purchase.id RETURNING * INTO purchase;
 END IF;
 SELECT * INTO transaction_row FROM public.transactions WHERE razorpay_payment_id=p_payment_id FOR UPDATE;
 IF FOUND THEN
   IF transaction_row.user_id<>p_user_id OR transaction_row.razorpay_order_id IS DISTINCT FROM p_order_id OR transaction_row.amount<>purchase.price_at_purchase OR transaction_row.currency<>p_currency OR transaction_row.transaction_type<>'addon' OR (transaction_row.addon_purchase_id IS NOT NULL AND transaction_row.addon_purchase_id<>purchase.id) THEN RAISE EXCEPTION 'Payment transaction ownership or amount mismatch'; END IF;
   UPDATE public.transactions SET addon_purchase_id=purchase.id WHERE id=transaction_row.id;
 ELSE
   INSERT INTO public.transactions(user_id,product_id,organization_id,addon_purchase_id,razorpay_order_id,razorpay_payment_id,razorpay_signature,amount,currency,status,transaction_type,payment_method)
   VALUES(p_user_id,purchase.product_id,p_organization_id,purchase.id,p_order_id,p_payment_id,p_signature,purchase.price_at_purchase,p_currency,'completed','addon',p_method);
 END IF;
 RETURN public.addon_purchase_contract(purchase);
END; $$;
REVOKE ALL ON FUNCTION public.record_addon_capture(uuid,uuid,text,text,text,bigint,text,text,text,uuid,bigint,uuid) FROM PUBLIC,anon,authenticated;
GRANT EXECUTE ON FUNCTION public.record_addon_capture(uuid,uuid,text,text,text,bigint,text,text,text,uuid,bigint,uuid) TO service_role;
COMMIT;
