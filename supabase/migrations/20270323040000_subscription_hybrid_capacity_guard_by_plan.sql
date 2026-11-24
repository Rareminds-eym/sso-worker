-- After the Hybrid catalog adoption (20270323030000) Hybrid's canonical code is opaque, so new Hybrid purchases no
-- longer carry the legacy code 'hybrid'. Guard every purchase of the adopted Hybrid plan by plan id; purchases made
-- before adoption reference the same plan id and stay guarded. Replaces the function from 20270313010000.
BEGIN;
CREATE OR REPLACE FUNCTION public.guard_hybrid_capacity_reduction()
RETURNS trigger LANGUAGE plpgsql SET search_path=public,pg_temp AS $$
BEGIN
 IF OLD.plan_id IN (SELECT (receipt#>>'{plan,id}')::uuid FROM public.subscription_hybrid_offer_adoptions)
 AND NEW.seat_count IS DISTINCT FROM OLD.seat_count
 AND (NEW.seat_count IS NULL OR NEW.seat_count<OLD.seat_count) THEN
  RAISE EXCEPTION 'Seat reductions require a coordinated contract change' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END $$;
COMMIT;
