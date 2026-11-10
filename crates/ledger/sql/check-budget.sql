-- Run as a test admin on a dedicated database after foundation/identity/budget
-- migrations and creation of the standard apl_api and apl_worker roles.
BEGIN;
GRANT EXECUTE ON FUNCTION reserve_refund_budget(uuid,uuid,uuid,uuid,text), finalize_refund_budget(uuid,uuid,uuid,text) TO apl_worker;
CREATE TEMP TABLE budget_test_ids AS SELECT
 '10000000-0000-0000-0000-000000000001'::uuid AS t,
 '10000000-0000-0000-0000-000000000002'::uuid AS e,
 '10000000-0000-0000-0000-000000000003'::uuid AS c,
 '10000000-0000-0000-0000-000000000004'::uuid AS w;
GRANT SELECT ON budget_test_ids TO apl_worker;
CREATE FUNCTION pg_temp.action_id(n int) RETURNS uuid LANGUAGE sql AS $$
 SELECT ('20000000-0000-0000-0000-'||lpad(n::text,12,'0'))::uuid
$$;
INSERT INTO tenants SELECT t,true FROM budget_test_ids;
INSERT INTO environments SELECT t,e,true FROM budget_test_ids;
INSERT INTO workloads SELECT t,e,w,true FROM budget_test_ids;
INSERT INTO connections SELECT t,e,c,true FROM budget_test_ids;
INSERT INTO actions (tenant_id,environment_id,id,workload_id,request,status)
SELECT t,e,pg_temp.action_id(n),w,jsonb_build_object('type','refund.create','connection_id',c,'parameters',jsonb_build_object('currency','USD','amount_minor',1500)),'received'
FROM budget_test_ids CROSS JOIN generate_series(1,6) AS n;
SELECT set_config('apl.tenant_id',t::text,true),set_config('apl.environment_id',e::text,true) FROM budget_test_ids;
SET LOCAL ROLE apl_worker;
DO $$ DECLARE ids record; BEGIN
 SELECT * INTO ids FROM budget_test_ids;
 IF reserve_refund_budget(ids.t,ids.e,pg_temp.action_id(1),ids.c,'verified-customer') <> 'not_configured' THEN RAISE EXCEPTION 'missing config did not fail closed'; END IF;
END $$;
RESET ROLE;
INSERT INTO budget_connections SELECT t,e,c,6000,3500 FROM budget_test_ids;
INSERT INTO budget_scope_limits (tenant_id,environment_id,connection_id,scope_kind,scope_ref,daily_limit_minor,exposure_limit_minor)
SELECT t,e,c,'workload',w::text,4500,3500 FROM budget_test_ids
UNION ALL SELECT t,e,c,'customer','verified-customer',2000,3500 FROM budget_test_ids;
SET LOCAL ROLE apl_worker;
DO $$ DECLARE ids record; BEGIN
 SELECT * INTO ids FROM budget_test_ids;
 IF reserve_refund_budget(ids.t,ids.e,pg_temp.action_id(1),ids.c,'verified-customer') <> 'new_hold' THEN RAISE EXCEPTION 'first hold failed'; END IF;
 IF reserve_refund_budget(ids.t,ids.e,pg_temp.action_id(1),ids.c,'verified-customer') <> 'already_held' THEN RAISE EXCEPTION 'reserve is not idempotent'; END IF;
 IF reserve_refund_budget(ids.t,ids.e,pg_temp.action_id(1),ids.c,'different') <> 'conflict' THEN RAISE EXCEPTION 'hold customer identity changed'; END IF;
 IF reserve_refund_budget(ids.t,ids.e,pg_temp.action_id(2),ids.c,'verified-customer') <> 'daily_exceeded' THEN RAISE EXCEPTION 'customer limit bypassed'; END IF;
 IF reserve_refund_budget(ids.t,ids.e,pg_temp.action_id(2),ids.c,NULL) <> 'new_hold' THEN RAISE EXCEPTION 'failed capacity check left a partial hold'; END IF;
 IF reserve_refund_budget(ids.t,ids.e,pg_temp.action_id(3),ids.c,NULL) <> 'exposure_exceeded' THEN RAISE EXCEPTION 'exposure limit bypassed'; END IF;
 IF finalize_refund_budget(ids.t,ids.e,pg_temp.action_id(2),'released') <> 'released' OR
    finalize_refund_budget(ids.t,ids.e,pg_temp.action_id(2),'released') <> 'released' THEN RAISE EXCEPTION 'release is not idempotent'; END IF;
 IF finalize_refund_budget(ids.t,ids.e,pg_temp.action_id(2),'settled') <> 'conflict' THEN RAISE EXCEPTION 'opposite terminal outcome was accepted'; END IF;
 IF reserve_refund_budget(ids.t,ids.e,pg_temp.action_id(3),ids.c,NULL) <> 'new_hold' THEN RAISE EXCEPTION 'release did not free exposure'; END IF;
 IF finalize_refund_budget(ids.t,ids.e,pg_temp.action_id(1),'settled') <> 'settled' OR
    finalize_refund_budget(ids.t,ids.e,pg_temp.action_id(3),'settled') <> 'settled' THEN RAISE EXCEPTION 'settlement failed'; END IF;
 BEGIN
  PERFORM reserve_refund_budget(gen_random_uuid(),ids.e,pg_temp.action_id(5),ids.c,NULL);
  RAISE EXCEPTION 'tenant context mismatch was accepted';
 EXCEPTION WHEN insufficient_privilege THEN NULL;
 END;
 IF has_table_privilege(current_user,'budget_reservations','UPDATE') OR has_function_privilege('apl_api','reserve_refund_budget(uuid,uuid,uuid,uuid,text)','EXECUTE') THEN RAISE EXCEPTION 'unsafe ledger grants'; END IF;
END $$;
RESET ROLE;
-- A previous dispatch's verified historical date is a fixture, not a runtime input.
INSERT INTO budget_reservations
SELECT t,e,pg_temp.action_id(4),c,w,NULL,2500,(clock_timestamp() AT TIME ZONE 'UTC')::date-1,'held' FROM budget_test_ids;
SET LOCAL ROLE apl_worker;
DO $$ DECLARE ids record; BEGIN
 SELECT * INTO ids FROM budget_test_ids;
 IF reserve_refund_budget(ids.t,ids.e,pg_temp.action_id(5),ids.c,NULL) <> 'exposure_exceeded' THEN RAISE EXCEPTION 'prior-day hold disappeared from exposure'; END IF;
 IF finalize_refund_budget(ids.t,ids.e,pg_temp.action_id(4),'settled') <> 'settled' THEN RAISE EXCEPTION 'late settlement failed'; END IF;
 IF reserve_refund_budget(ids.t,ids.e,pg_temp.action_id(5),ids.c,NULL) <> 'new_hold' THEN RAISE EXCEPTION 'late settlement consumed current day capacity'; END IF;
 IF reserve_refund_budget(ids.t,ids.e,pg_temp.action_id(6),ids.c,NULL) <> 'daily_exceeded' THEN RAISE EXCEPTION 'workload daily limit bypassed'; END IF;
END $$;
RESET ROLE;
DO $$ BEGIN
 IF (SELECT count(*) FROM budget_ledger_events WHERE action_id=pg_temp.action_id(2))<>2 THEN RAISE EXCEPTION 'release replay created a duplicate event'; END IF;
 IF (SELECT utc_day FROM budget_reservations WHERE action_id=pg_temp.action_id(4)) <> (clock_timestamp() AT TIME ZONE 'UTC')::date-1 THEN RAISE EXCEPTION 'late settlement moved the dispatch day'; END IF;
END $$;
ROLLBACK;
