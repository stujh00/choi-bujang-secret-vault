-- Step 4 RLS practice. Run manually in the Supabase SQL Editor.
-- This script changes privileges and policies on public.vault_notes only.

-- Inspect current table grants before applying changes.
SELECT grantee, privilege_type, is_grantable
FROM information_schema.role_table_grants
WHERE table_schema = 'public'
  AND table_name = 'vault_notes'
  AND grantee IN ('PUBLIC', 'anon', 'authenticated')
ORDER BY grantee, privilege_type;

SELECT role_name,
  has_table_privilege(role_name, 'public.vault_notes', 'SELECT') AS can_select,
  has_table_privilege(role_name, 'public.vault_notes', 'INSERT') AS can_insert,
  has_table_privilege(role_name, 'public.vault_notes', 'UPDATE') AS can_update,
  has_table_privilege(role_name, 'public.vault_notes', 'DELETE') AS can_delete
FROM (VALUES ('anon'), ('authenticated')) AS roles(role_name);

-- Review existing policies. Unexpected policies stop the script below so they
-- cannot silently combine with these owner-only policies.
SELECT schemaname, tablename, policyname, permissive, roles, cmd, qual, with_check
FROM pg_policies
WHERE schemaname = 'public'
  AND tablename = 'vault_notes'
ORDER BY policyname;

BEGIN;

DO $policy_guard$
DECLARE
  unexpected_policies text;
BEGIN
  SELECT string_agg(policyname, ', ' ORDER BY policyname)
    INTO unexpected_policies
    FROM pg_policies
    WHERE schemaname = 'public'
      AND tablename = 'vault_notes'
      AND policyname NOT IN (
        'vault_notes_select_owner',
        'vault_notes_insert_owner',
        'vault_notes_update_owner',
        'vault_notes_delete_owner'
      );

  IF unexpected_policies IS NOT NULL THEN
    RAISE EXCEPTION 'Unexpected public.vault_notes policies exist (%); inspect them before applying this script.', unexpected_policies;
  END IF;
END;
$policy_guard$;

ALTER TABLE public.vault_notes ENABLE ROW LEVEL SECURITY;

REVOKE ALL ON TABLE public.vault_notes FROM PUBLIC, anon, authenticated;
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE public.vault_notes TO authenticated;

DROP POLICY IF EXISTS vault_notes_select_owner ON public.vault_notes;
DROP POLICY IF EXISTS vault_notes_insert_owner ON public.vault_notes;
DROP POLICY IF EXISTS vault_notes_update_owner ON public.vault_notes;
DROP POLICY IF EXISTS vault_notes_delete_owner ON public.vault_notes;

CREATE POLICY vault_notes_select_owner
  ON public.vault_notes
  FOR SELECT TO authenticated
  USING (auth.uid() = owner_id);

CREATE POLICY vault_notes_insert_owner
  ON public.vault_notes
  FOR INSERT TO authenticated
  WITH CHECK (auth.uid() = owner_id);

CREATE POLICY vault_notes_update_owner
  ON public.vault_notes
  FOR UPDATE TO authenticated
  USING (auth.uid() = owner_id)
  WITH CHECK (auth.uid() = owner_id);

CREATE POLICY vault_notes_delete_owner
  ON public.vault_notes
  FOR DELETE TO authenticated
  USING (auth.uid() = owner_id);

COMMIT;

-- Verify resulting grants and effective table privileges.
SELECT grantee, privilege_type, is_grantable
FROM information_schema.role_table_grants
WHERE table_schema = 'public'
  AND table_name = 'vault_notes'
  AND grantee IN ('PUBLIC', 'anon', 'authenticated')
ORDER BY grantee, privilege_type;

SELECT role_name,
  has_table_privilege(role_name, 'public.vault_notes', 'SELECT') AS can_select,
  has_table_privilege(role_name, 'public.vault_notes', 'INSERT') AS can_insert,
  has_table_privilege(role_name, 'public.vault_notes', 'UPDATE') AS can_update,
  has_table_privilege(role_name, 'public.vault_notes', 'DELETE') AS can_delete
FROM (VALUES ('anon'), ('authenticated')) AS roles(role_name);

SELECT schemaname, tablename, policyname, permissive, roles, cmd, qual, with_check
FROM pg_policies
WHERE schemaname = 'public'
  AND tablename = 'vault_notes'
ORDER BY policyname;