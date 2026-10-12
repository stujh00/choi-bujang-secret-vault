-- Step 5: revoke direct Data API table privileges for client roles.
-- Run manually in the Supabase SQL Editor. This does not alter rows, RLS
-- policies, service_role grants, or the server-only Supabase Secret Key.

-- Inspect grants before the change.
SELECT grantee, privilege_type, is_grantable
FROM information_schema.role_table_grants
WHERE table_schema = 'public'
  AND table_name = 'vault_notes'
  AND grantee IN ('PUBLIC', 'anon', 'authenticated')
ORDER BY grantee, privilege_type;

-- Inspect effective client-role privileges before the change.
SELECT role_name,
  has_table_privilege(role_name, 'public.vault_notes', 'SELECT') AS can_select,
  has_table_privilege(role_name, 'public.vault_notes', 'INSERT') AS can_insert,
  has_table_privilege(role_name, 'public.vault_notes', 'UPDATE') AS can_update,
  has_table_privilege(role_name, 'public.vault_notes', 'DELETE') AS can_delete
FROM (VALUES ('anon'), ('authenticated')) AS roles(role_name);

BEGIN;

REVOKE ALL ON TABLE public.vault_notes FROM PUBLIC, anon, authenticated;

COMMIT;

-- Inspect grants after the change.
SELECT grantee, privilege_type, is_grantable
FROM information_schema.role_table_grants
WHERE table_schema = 'public'
  AND table_name = 'vault_notes'
  AND grantee IN ('PUBLIC', 'anon', 'authenticated')
ORDER BY grantee, privilege_type;

-- Inspect effective client-role privileges after the change.
SELECT role_name,
  has_table_privilege(role_name, 'public.vault_notes', 'SELECT') AS can_select,
  has_table_privilege(role_name, 'public.vault_notes', 'INSERT') AS can_insert,
  has_table_privilege(role_name, 'public.vault_notes', 'UPDATE') AS can_update,
  has_table_privilege(role_name, 'public.vault_notes', 'DELETE') AS can_delete
FROM (VALUES ('anon'), ('authenticated')) AS roles(role_name);
