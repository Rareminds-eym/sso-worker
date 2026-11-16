-- Source/app usage is held in separate databases. Never permit a terms PATCH
-- to lower Hybrid capacity until a coordinated reduction workflow is available.
BEGIN;
CREATE OR REPLACE FUNCTION public.guard_hybrid_capacity_reduction()
RETURNS trigger LANGUAGE plpgsql SET search_path=public,pg_temp AS $$
BEGIN
 IF OLD.plan_code='hybrid' AND NEW.seat_count IS DISTINCT FROM OLD.seat_count
 AND (NEW.seat_count IS NULL OR NEW.seat_count<OLD.seat_count) THEN
  RAISE EXCEPTION 'Seat reductions require a coordinated contract change' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS guard_hybrid_capacity_reduction ON public.subscriptions;
CREATE TRIGGER guard_hybrid_capacity_reduction BEFORE UPDATE OF seat_count ON public.subscriptions
 FOR EACH ROW EXECUTE FUNCTION public.guard_hybrid_capacity_reduction();
COMMIT;
