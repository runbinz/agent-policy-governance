-- Local development only; intentionally public fixture credentials.
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
DO $$ BEGIN
 IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname='apl_api_login') THEN
  CREATE ROLE apl_api_login LOGIN PASSWORD 'local_api_only' NOSUPERUSER NOBYPASSRLS;
 END IF;
 IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname='apl_worker_login') THEN
  CREATE ROLE apl_worker_login LOGIN PASSWORD 'local_worker_only' NOSUPERUSER NOBYPASSRLS;
 END IF;
END $$;
GRANT apl_api TO apl_api_login;
GRANT apl_worker TO apl_worker_login;
