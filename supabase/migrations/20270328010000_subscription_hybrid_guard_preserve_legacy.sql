-- Preserve protection before catalog adoption as well as after opaque plan identity adoption.
-- No adoption, subscriber backfill or commercial terms change is performed here.
BEGIN;
CREATE OR REPLACE FUNCTION public.guard_hybrid_capacity_reduction()
RETURNS trigger LANGUAGE plpgsql SET search_path=public,pg_temp AS $$
BEGIN
 IF (OLD.plan_code='hybrid'
     OR OLD.plan_id IN (SELECT (receipt#>>'{plan,id}')::uuid FROM public.subscription_hybrid_offer_adoptions))
 AND NEW.seat_count IS DISTINCT FROM OLD.seat_count
 AND (NEW.seat_count IS NULL OR NEW.seat_count<OLD.seat_count) THEN
  RAISE EXCEPTION 'Seat reductions require a coordinated contract change' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END $$;
COMMIT;
