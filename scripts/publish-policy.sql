-- Run with psql -v ON_ERROR_STOP=1 and dedicated policy administration credentials.
-- expected_version=0 means this connection must not yet have an active policy.
BEGIN;

INSERT INTO policy_versions (
  tenant_id, environment_id, connection_id, version,
  auto_limit_minor, hard_limit_minor, approval_ttl_seconds
) VALUES (
  :'tenant_id'::uuid, :'environment_id'::uuid, :'connection_id'::uuid, :'version'::bigint,
  :'auto_limit_minor'::bigint, :'hard_limit_minor'::bigint, :'approval_ttl_seconds'::bigint
);

INSERT INTO policy_bindings AS current_binding (tenant_id, environment_id, connection_id, version)
SELECT :'tenant_id'::uuid, :'environment_id'::uuid, :'connection_id'::uuid, :'version'::bigint
WHERE :'expected_version'::bigint = 0 OR EXISTS (
  SELECT FROM policy_bindings
  WHERE (tenant_id, environment_id, connection_id) =
    (:'tenant_id'::uuid, :'environment_id'::uuid, :'connection_id'::uuid)
)
ON CONFLICT (tenant_id, environment_id, connection_id) DO UPDATE
SET version = EXCLUDED.version
WHERE current_binding.version = :'expected_version'::bigint
RETURNING version AS published_version
\gset

-- If the precondition failed, \gset errors and psql exits without committing.
COMMIT;
\echo Published policy version :published_version
