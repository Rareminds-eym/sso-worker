DO $$
DECLARE u uuid:=gen_random_uuid(); sess uuid:=gen_random_uuid(); inv uuid:=gen_random_uuid(); oldop uuid; newop uuid; r jsonb; aid uuid; i integer;
BEGIN
 INSERT INTO public.users(id,email,password_hash) VALUES(u,u::text||'@cancel-test.invalid','test');
 r:=public.begin_career_operation(u,'old','old-exec',sess,'chat','h'); oldop:=(r->>'operation_record_id')::uuid; aid:=(r->>'account_id')::uuid;
 PERFORM public.register_career_invocation(oldop,inv,'m1');
 r:=public.finish_career_operation(oldop,'cancelled');
 IF r->>'ok'<>'true' THEN RAISE EXCEPTION 'cancel failed: %',r; END IF;
 IF NOT EXISTS(SELECT 1 FROM public.user_ai_usage WHERE id=inv AND cost_state='pending') THEN RAISE EXCEPTION 'usage erased'; END IF;
 r:=public.begin_career_operation(u,'new','new-exec',sess,'chat','h2'); newop:=(r->>'operation_record_id')::uuid;
 IF r->>'ok'<>'true' THEN RAISE EXCEPTION 'new request blocked: %',r; END IF;
 PERFORM public.settle_career_invocation(inv,'late-'||inv::text,'0.001',10,5,'failed',40000,'resolved');
 PERFORM public.finish_career_operation(oldop,'cancelled');
 IF NOT EXISTS(SELECT 1 FROM public.user_ai_credit_accounts WHERE id=aid AND active_operation_id='new' AND spent_credits=1.2) THEN RAISE EXCEPTION 'late debit changed new guard'; END IF;
 PERFORM public.finish_career_operation(newop,'cancelled');
 FOR i IN 1..3 LOOP
  r:=public.begin_career_operation(u,'pending-'||i,'pending-exec-'||i,sess,'chat','hash-'||i);
  oldop:=(r->>'operation_record_id')::uuid;
  PERFORM public.register_career_invocation(oldop,gen_random_uuid(),'m1');
  PERFORM public.finish_career_operation(oldop,'cancelled');
 END LOOP;
 r:=public.begin_career_operation(u,'limit','limit-exec',sess,'chat','limit-hash');
 IF r->>'error'<>'PENDING_COST' THEN RAISE EXCEPTION 'unresolved cap missing: %',r; END IF;
 RAISE NOTICE 'Cancellation, late debit and unresolved cap regression passed';
END $$;
