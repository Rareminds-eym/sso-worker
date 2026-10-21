-- Run after credit migrations inside a transaction; roll back test records.
DO $$
DECLARE u uuid := gen_random_uuid(); sess uuid := gen_random_uuid(); inv uuid := gen_random_uuid();
 a uuid; op uuid; pol uuid; r jsonb; n bigint; blocked boolean := false;
BEGIN
 INSERT INTO public.users(id,email,password_hash) VALUES(u, u::text||'@credit-test.invalid','test-only');
 r := public.begin_career_operation(u,'test-op','test-exec',sess,'careerTalentStrategist.chat','hash');
 IF r->>'ok' <> 'true' THEN RAISE EXCEPTION 'admission failed: %',r; END IF;
 a := (r->>'account_id')::uuid; op := (r->>'operation_record_id')::uuid; pol := (r->>'policy_id')::uuid;
 SELECT count(*) INTO n FROM public.ai_credit_ledger WHERE account_id=a AND kind='grant';
 IF n<>1 THEN RAISE EXCEPTION 'missing initial grant'; END IF;
 r := public.begin_career_operation(u,'test-op','different-exec',sess,'careerTalentStrategist.chat','hash');
 IF r->>'error' <> 'IDENTITY_CONFLICT' THEN RAISE EXCEPTION 'replay identity not checked'; END IF;
 r := public.register_career_invocation(op,inv,'m1');
 r := public.finish_career_operation(op,'completed');
 IF r->>'error'<>'PENDING_COST' THEN RAISE EXCEPTION 'early release'; END IF;
 r := public.settle_career_invocation(inv,'test-log-'||inv::text,'0.030000000000',10,5,'succeeded',100,'resolved');
 IF (r->>'credits_used')::numeric <> 36 THEN RAISE EXCEPTION 'formula wrong: %',r; END IF;
 r := public.settle_career_invocation(inv,'test-log-'||inv::text,'0.030000000000',10,5,'succeeded',100,'resolved');
 IF r->>'duplicate'<>'true' THEN RAISE EXCEPTION 'debit not idempotent'; END IF;
 r := public.settle_career_invocation(inv,'test-log-'||inv::text,'0.040000000000',10,5,'succeeded',100,'resolved');
 IF r->>'error'<>'EVIDENCE_CONFLICT' THEN RAISE EXCEPTION 'changed cost accepted'; END IF;
 BEGIN UPDATE public.ai_credit_policies SET markup_percent=21 WHERE id=pol;
 EXCEPTION WHEN raise_exception THEN blocked:=true; END;
 IF NOT blocked THEN RAISE EXCEPTION 'policy changed'; END IF;
 blocked:=false;
 BEGIN UPDATE public.ai_credit_ledger SET credit_delta=0 WHERE account_id=a;
 EXCEPTION WHEN raise_exception THEN blocked:=true; END;
 IF NOT blocked THEN RAISE EXCEPTION 'ledger edited'; END IF;
 r := public.finish_career_operation(op,'completed');
 IF r->>'ok'<>'true' THEN RAISE EXCEPTION 'finish failed: %',r; END IF;
 IF EXISTS(SELECT 1 FROM public.user_ai_credit_accounts WHERE id=a AND active_operation_id IS NOT NULL) THEN RAISE EXCEPTION 'guard retained'; END IF;
 SELECT count(*) INTO n FROM public.ai_credit_sync_outbox b JOIN public.user_ai_credit_accounts c ON c.id=b.account_id WHERE c.id=a AND b.revision=c.revision;
 IF n<1 THEN RAISE EXCEPTION 'final revision not queued'; END IF;
 r := public.begin_career_operation(u,'test-op2','test-exec2',sess,'careerTalentStrategist.chat','hash2');
 IF r->>'error'<>'EXHAUSTED' THEN RAISE EXCEPTION 'exhaustion not enforced'; END IF;
 RAISE NOTICE 'Credit SQL regression checks passed';
END $$;
