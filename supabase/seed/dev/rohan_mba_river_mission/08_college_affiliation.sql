-- Local SSO demo college; platform membership remains unchanged.
BEGIN;
INSERT INTO public.organizations(id,name,slug,metadata) VALUES ('2fcd9dc2-9a24-5c52-8d91-8b414996f23d','Bengaluru Institute of Management','bengaluru-management-demo','{"demo":true}'::jsonb) ON CONFLICT(id) DO NOTHING;
COMMIT;
