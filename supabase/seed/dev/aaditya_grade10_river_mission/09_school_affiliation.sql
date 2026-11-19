-- Local SSO school reference; credentials and membership permissions unchanged.
BEGIN;
INSERT INTO public.organizations (id,name,slug,metadata) VALUES ('0b2582eb-ff09-495f-ace4-0c2b73d36701','Cambridge School','cambridge-school-jp-nagar','{"source":"SkillPassport production school seed","city":"Bengaluru"}'::jsonb) ON CONFLICT (id) DO NOTHING;
UPDATE public.users SET user_metadata=coalesce(user_metadata,'{}'::jsonb)||'{"schoolName":"Cambridge School"}'::jsonb, updated_at=now() WHERE id='6d1c48f6-b3a9-57fb-998c-6a7255713e0c' AND email='aaditya.raman10@example.com';
COMMIT;
