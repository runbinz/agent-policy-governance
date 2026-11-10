-- Wake-up inbox only; the worker still reads Stripe before applying outcomes.
CREATE TABLE stripe_webhook_inbox (
 provider_namespace text NOT NULL REFERENCES provider_routes(provider_namespace),
 event_id text NOT NULL CHECK(event_id ~ '^evt_[A-Za-z0-9]{1,120}$'),
 event_type text NOT NULL CHECK(event_type IN ('refund.created','refund.updated','refund.failed','charge.refund.updated')),
 refund_id text NOT NULL CHECK(refund_id ~ '^re_[A-Za-z0-9]{1,120}$'),
 charge_id text NOT NULL CHECK(charge_id ~ '^ch_[A-Za-z0-9]{1,120}$'),
 correlation text CHECK(octet_length(correlation)<=128),
 received_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(provider_namespace,event_id)
);
CREATE FUNCTION ingest_stripe_wake(ns text,event text,kind text,refund text,charge text,key text) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE route public.provider_routes%ROWTYPE;
BEGIN
 SELECT * INTO route FROM public.provider_routes r WHERE r.provider_namespace=ns AND ns LIKE 'stripe-test:%';
 IF NOT FOUND THEN RAISE EXCEPTION 'webhook route unavailable' USING ERRCODE='42501'; END IF;
 INSERT INTO public.stripe_webhook_inbox(provider_namespace,event_id,event_type,refund_id,charge_id,correlation)
 VALUES(ns,event,kind,refund,charge,key) ON CONFLICT DO NOTHING;
 IF NOT FOUND THEN RETURN false; END IF;
 PERFORM set_config('apl.tenant_id',route.tenant_id::text,true),set_config('apl.environment_id',route.environment_id::text,true);
 UPDATE public.external_dispatch_queue q SET available_at_ms=least(q.available_at_ms,
   floor(extract(epoch FROM clock_timestamp())*1000)::bigint)
 FROM public.external_dispatches d
 WHERE (q.tenant_id,q.environment_id,q.action_id)=(d.tenant_id,d.environment_id,d.action_id)
  AND (d.tenant_id,d.environment_id,d.connection_id)=(route.tenant_id,route.environment_id,route.connection_id)
  AND d.provider_namespace=ns AND d.provider_key=key AND d.snapshot#>>'{request,payment_id}'=charge
  AND d.snapshot#>>'{first_send_at}' IS NOT NULL AND NOT q.closed;
 RETURN true;
END $$;
REVOKE ALL ON FUNCTION ingest_stripe_wake(text,text,text,text,text,text) FROM PUBLIC;
