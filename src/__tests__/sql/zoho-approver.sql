-- Synthetic fixture tables are created by the disposable local test runner.
DO $$
DECLARE actor uuid:=gen_random_uuid(); membership uuid:=gen_random_uuid(); role uuid:=gen_random_uuid();
BEGIN
  ASSERT NOT public.zoho_is_active_import_approver(NULL);
  ASSERT NOT public.zoho_is_active_import_approver(actor);
  INSERT INTO public.users(id,is_blocked) VALUES(actor,false);
  INSERT INTO public.memberships(id,user_id,org_id,status) VALUES(membership,actor,'00000000-0000-0000-0000-000000000001','active');
  INSERT INTO public.roles(id,name) VALUES(role,'super_admin');
  ASSERT NOT public.zoho_is_active_import_approver(actor);
  INSERT INTO public.membership_roles(membership_id,role_id) VALUES(membership,role);
  ASSERT public.zoho_is_active_import_approver(actor);
  UPDATE public.users SET is_blocked=true WHERE id=actor;
  ASSERT NOT public.zoho_is_active_import_approver(actor);
  UPDATE public.users SET is_blocked=NULL WHERE id=actor;
  ASSERT NOT public.zoho_is_active_import_approver(actor);
  UPDATE public.users SET is_blocked=false WHERE id=actor;
  UPDATE public.memberships SET status='suspended' WHERE id=membership;
  ASSERT NOT public.zoho_is_active_import_approver(actor);
  UPDATE public.memberships SET status='active',org_id=gen_random_uuid() WHERE id=membership;
  ASSERT NOT public.zoho_is_active_import_approver(actor);
  UPDATE public.memberships SET org_id='00000000-0000-0000-0000-000000000001' WHERE id=membership;
  UPDATE public.roles SET name='admin' WHERE id=role;
  ASSERT NOT public.zoho_is_active_import_approver(actor);
  UPDATE public.roles SET name='super_admin' WHERE id=role;
  ASSERT public.zoho_is_active_import_approver(actor);
  DELETE FROM public.membership_roles WHERE membership_id=membership;
  ASSERT NOT public.zoho_is_active_import_approver(actor);
  ASSERT NOT has_function_privilege('anon','public.zoho_is_active_import_approver(uuid)','EXECUTE');
  ASSERT NOT has_function_privilege('authenticated','public.zoho_is_active_import_approver(uuid)','EXECUTE');
  ASSERT has_function_privilege('service_role','public.zoho_is_active_import_approver(uuid)','EXECUTE');
END $$;
