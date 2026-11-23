-- Backend authorization and explicit grants own subscription draft access.
-- Preserve the existing service-only definer RPC and immutable evidence triggers.
BEGIN;
ALTER TABLE public.subscription_plan_drafts DISABLE ROW LEVEL SECURITY;
ALTER TABLE public.subscription_plan_drafts NO FORCE ROW LEVEL SECURITY;
REVOKE ALL ON TABLE public.subscription_plan_drafts FROM PUBLIC, anon, authenticated, service_role;
GRANT SELECT ON TABLE public.subscription_plan_drafts TO service_role;
COMMIT;
