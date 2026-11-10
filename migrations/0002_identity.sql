CREATE TABLE tenants (tenant_id uuid PRIMARY KEY, enabled boolean NOT NULL DEFAULT true);
CREATE TABLE environments (tenant_id uuid NOT NULL REFERENCES tenants, environment_id uuid NOT NULL, enabled boolean NOT NULL DEFAULT true, PRIMARY KEY(tenant_id,environment_id));
CREATE TABLE workloads (tenant_id uuid NOT NULL,environment_id uuid NOT NULL,workload_id uuid NOT NULL,enabled boolean NOT NULL DEFAULT true,PRIMARY KEY(tenant_id,environment_id,workload_id),FOREIGN KEY(tenant_id,environment_id) REFERENCES environments);
CREATE TABLE connections (tenant_id uuid NOT NULL,environment_id uuid NOT NULL,connection_id uuid NOT NULL,enabled boolean NOT NULL DEFAULT true,PRIMARY KEY(tenant_id,environment_id,connection_id),FOREIGN KEY(tenant_id,environment_id) REFERENCES environments);
CREATE TABLE workload_grants (
 tenant_id uuid NOT NULL,environment_id uuid NOT NULL,workload_id uuid NOT NULL,connection_id uuid NOT NULL,
 enabled boolean NOT NULL DEFAULT true,submit_refund boolean NOT NULL DEFAULT false,read_action boolean NOT NULL DEFAULT false,read_events boolean NOT NULL DEFAULT false,
 PRIMARY KEY(tenant_id,environment_id,workload_id,connection_id),
 FOREIGN KEY(tenant_id,environment_id,workload_id) REFERENCES workloads,
 FOREIGN KEY(tenant_id,environment_id,connection_id) REFERENCES connections
);
-- Private global index used only to establish verified identity's tenant context.
CREATE TABLE identity_registry (
 issuer text NOT NULL,subject text NOT NULL,tenant_id uuid NOT NULL,environment_id uuid NOT NULL,workload_id uuid NOT NULL,connection_id uuid NOT NULL,
 PRIMARY KEY(issuer,subject),
 FOREIGN KEY(tenant_id,environment_id,workload_id,connection_id) REFERENCES workload_grants
);
CREATE TABLE identity_audit (sequence bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,changed_at timestamptz NOT NULL DEFAULT now(),actor text NOT NULL,table_name text NOT NULL,operation text NOT NULL,old_record jsonb,new_record jsonb);
CREATE FUNCTION audit_identity_change() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
BEGIN
 INSERT INTO public.identity_audit(actor,table_name,operation,old_record,new_record) VALUES(session_user,TG_TABLE_NAME,TG_OP,to_jsonb(OLD),to_jsonb(NEW));
 RETURN NULL;
END $$;
DO $$ DECLARE t text; BEGIN
 FOREACH t IN ARRAY ARRAY['tenants','environments','workloads','connections','workload_grants'] LOOP
 EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY',t);
 EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY',t);
 IF t='tenants' THEN
 EXECUTE format('CREATE POLICY tenant_scope ON %I USING (tenant_id=nullif(current_setting(''apl.tenant_id'',true),'''')::uuid) WITH CHECK (tenant_id=nullif(current_setting(''apl.tenant_id'',true),'''')::uuid)',t);
 ELSE
 EXECUTE format('CREATE POLICY tenant_scope ON %I USING (tenant_id=nullif(current_setting(''apl.tenant_id'',true),'''')::uuid AND environment_id=nullif(current_setting(''apl.environment_id'',true),'''')::uuid) WITH CHECK (tenant_id=nullif(current_setting(''apl.tenant_id'',true),'''')::uuid AND environment_id=nullif(current_setting(''apl.environment_id'',true),'''')::uuid)',t);
 END IF;
 END LOOP;
 FOREACH t IN ARRAY ARRAY['tenants','environments','workloads','connections','workload_grants','identity_registry'] LOOP
 EXECUTE format('CREATE TRIGGER identity_change AFTER INSERT OR UPDATE OR DELETE ON %I FOR EACH ROW EXECUTE FUNCTION audit_identity_change()',t);
 END LOOP;
END $$;
-- Definer allows row locks without granting runtime UPDATE on identity tables.
-- Locks remain until caller transaction completes, serializing revocation and dispatch.
CREATE FUNCTION authorize_scope(t uuid,e uuid,w uuid,c uuid,permission text) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE allowed boolean;
BEGIN
 IF t IS DISTINCT FROM nullif(current_setting('apl.tenant_id',true),'')::uuid OR e IS DISTINCT FROM nullif(current_setting('apl.environment_id',true),'')::uuid THEN RETURN false; END IF;
 SELECT (tn.enabled AND en.enabled AND wl.enabled AND cn.enabled AND gr.enabled AND CASE permission WHEN 'submit_refund' THEN gr.submit_refund WHEN 'read_action' THEN gr.read_action WHEN 'read_events' THEN gr.read_events ELSE false END)
 INTO allowed FROM public.tenants tn JOIN public.environments en USING(tenant_id)
 JOIN public.workloads wl USING(tenant_id,environment_id)
 JOIN public.workload_grants gr USING(tenant_id,environment_id,workload_id)
 JOIN public.connections cn USING(tenant_id,environment_id,connection_id)
 WHERE tn.tenant_id=t AND en.environment_id=e AND wl.workload_id=w AND cn.connection_id=c
 FOR SHARE OF tn,en,wl,gr,cn;
 RETURN coalesce(allowed,false);
END $$;
REVOKE ALL ON FUNCTION authorize_scope(uuid,uuid,uuid,uuid,text) FROM PUBLIC;
CREATE FUNCTION lookup_identity(i text,s text) RETURNS TABLE(tenant_id uuid,environment_id uuid,workload_id uuid,connection_id uuid)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE identity public.identity_registry%ROWTYPE;
BEGIN
 SELECT * INTO identity FROM public.identity_registry r WHERE r.issuer=i AND r.subject=s;
 IF NOT FOUND THEN RETURN; END IF;
 PERFORM set_config('apl.tenant_id',identity.tenant_id::text,true),set_config('apl.environment_id',identity.environment_id::text,true);
 -- Any enabled identity may authenticate; individual operations check their own permission.
 IF EXISTS(SELECT FROM public.tenants tn JOIN public.environments en USING(tenant_id) JOIN public.workloads wl USING(tenant_id,environment_id) JOIN public.workload_grants gr USING(tenant_id,environment_id,workload_id) JOIN public.connections cn USING(tenant_id,environment_id,connection_id)
 WHERE tn.tenant_id=identity.tenant_id AND en.environment_id=identity.environment_id AND wl.workload_id=identity.workload_id AND cn.connection_id=identity.connection_id AND tn.enabled AND en.enabled AND wl.enabled AND gr.enabled AND cn.enabled) THEN
 RETURN QUERY SELECT identity.tenant_id,identity.environment_id,identity.workload_id,identity.connection_id;
 END IF;
END $$;
REVOKE ALL ON FUNCTION lookup_identity(text,text) FROM PUBLIC;
