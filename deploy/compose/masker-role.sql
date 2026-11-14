-- Development only: the database role of the face masker (ADR 0036), as described in
-- spec/jobs/README.md ("Database role for external workers"). Run by the masker-db-init service after
-- migrate, so external_tasks exists. It is safe to run again: the role is created once and the grants
-- are repeated.
--
-- The password is a public placeholder, like every credential in deploy/compose. In a real deployment
-- create the role yourself with a real secret and give it to the masker as
-- CIPHERFRAME_ML_DATABASE_URL_FILE.

SELECT 'CREATE ROLE cipherframe_masker LOGIN PASSWORD ''dev-placeholder-masker'''
WHERE NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'cipherframe_masker')
\gexec

GRANT CONNECT ON DATABASE cipherframe TO cipherframe_masker;
GRANT USAGE ON SCHEMA public TO cipherframe_masker;
GRANT SELECT ON external_tasks TO cipherframe_masker;
GRANT UPDATE (state, attempts, lease_owner, lease_until, envelope, result, updated_at, completed_at)
    ON external_tasks TO cipherframe_masker;
