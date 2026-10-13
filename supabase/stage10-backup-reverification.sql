-- Stage 10 hardening: independent, read-only backup verification before any restore.
-- Always reject missing/tampered/nonbaseline snapshots. No note is modified here.
CREATE OR REPLACE FUNCTION public.verify_test_note_b_backup()
RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = ''
AS $verify$
DECLARE
  backup public.vault_recovery_snapshots%ROWTYPE;
  expected_id CONSTANT uuid := '00000000-0000-4000-8000-000000000005';
  expected_title CONSTANT text := 'B 소유 공개 시험 메모';
  expected_content CONSTANT text := '공개 가능한 가상 시험 자료입니다. 민감 정보는 포함하지 않습니다.';
  hash_now text;
BEGIN
  -- Freshly read the privately held snapshot, never the mutable live note.
  SELECT * INTO backup FROM public.vault_recovery_snapshots
   WHERE id = expected_id;
  IF NOT FOUND OR backup.id IS DISTINCT FROM expected_id
      OR backup.owner_id IS NULL OR backup.verified_at IS NULL
      OR backup.verified_at > now()
      OR backup.title IS DISTINCT FROM expected_title
      OR backup.content IS DISTINCT FROM expected_content THEN
    RAISE EXCEPTION 'backup not verified against pre-incident baseline';
  END IF;
  hash_now := encode(sha256(convert_to(
    jsonb_build_object('id', backup.id, 'owner_id', backup.owner_id,
      'title', backup.title, 'content', backup.content)::text, 'UTF8')), 'hex');
  IF hash_now IS DISTINCT FROM backup.content_sha256 THEN
    RAISE EXCEPTION 'backup digest mismatch';
  END IF;
  RETURN jsonb_build_object('verified', true, 'noteId', backup.id,
    'contentSha256', hash_now, 'ownerVerified', true);
END
$verify$;

REVOKE ALL ON FUNCTION public.verify_test_note_b_backup()
  FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.verify_test_note_b_backup() TO service_role;

-- The write transaction does its *own* fresh validation again so a race
-- between HTTP preflight and restore cannot bypass backup verification.
CREATE OR REPLACE FUNCTION public.restore_test_note_b()
RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = ''
AS $restore$
DECLARE
  proof jsonb;
  backup public.vault_recovery_snapshots%ROWTYPE;
  existing public.vault_notes%ROWTYPE;
  result public.vault_notes%ROWTYPE;
  actual_hash text;
  affected bigint;
  expected_id CONSTANT uuid := '00000000-0000-4000-8000-000000000005';
BEGIN
  proof := public.verify_test_note_b_backup();
  IF proof->>'verified' IS DISTINCT FROM 'true'
      OR proof->>'noteId' IS DISTINCT FROM expected_id::text
      OR proof->>'ownerVerified' IS DISTINCT FROM 'true' THEN
    RAISE EXCEPTION 'independent pre-restore backup verification failed';
  END IF;
  -- Re-read and lock the backup after verifying. Never trust a request body.
  SELECT * INTO backup FROM public.vault_recovery_snapshots
   WHERE id = expected_id FOR SHARE;
  IF NOT FOUND OR backup.owner_id IS NULL
      OR backup.content_sha256 IS DISTINCT FROM proof->>'contentSha256' THEN
    RAISE EXCEPTION 'backup changed since verification';
  END IF;
  actual_hash := encode(sha256(convert_to(
    jsonb_build_object('id', backup.id, 'owner_id', backup.owner_id,
      'title', backup.title, 'content', backup.content)::text, 'UTF8')), 'hex');
  IF actual_hash IS DISTINCT FROM backup.content_sha256 THEN
    RAISE EXCEPTION 'locked backup integrity mismatch';
  END IF;

  SELECT * INTO existing FROM public.vault_notes WHERE id = expected_id FOR UPDATE;
  IF FOUND AND existing.owner_id IS DISTINCT FROM backup.owner_id THEN
    RAISE EXCEPTION 'target ownership mismatch; refuse overwrite';
  END IF;
  INSERT INTO public.vault_notes (id, owner_id, title, content)
   VALUES (backup.id, backup.owner_id, backup.title, backup.content)
  ON CONFLICT (id) DO UPDATE SET
    title = EXCLUDED.title,
    content = EXCLUDED.content
  WHERE public.vault_notes.owner_id = EXCLUDED.owner_id;
  GET DIAGNOSTICS affected = ROW_COUNT;
  IF affected <> 1 THEN RAISE EXCEPTION 'restore must affect exactly one B note'; END IF;

  SELECT * INTO result FROM public.vault_notes WHERE id=expected_id;
  actual_hash := encode(sha256(convert_to(
    jsonb_build_object('id', result.id, 'owner_id', result.owner_id,
      'title', result.title, 'content', result.content)::text, 'UTF8')), 'hex');
  IF actual_hash IS DISTINCT FROM backup.content_sha256
     OR result.owner_id IS DISTINCT FROM backup.owner_id THEN
    RAISE EXCEPTION 'post restore hash or ownership mismatch';
  END IF;
  INSERT INTO public.vault_recovery_audit(note_id, operation, content_sha256)
    VALUES (backup.id, 'restore', actual_hash);
  RETURN jsonb_build_object('restored', true, 'noteId', result.id,
    'contentSha256', actual_hash, 'ownerVerified', true);
END
$restore$;
REVOKE ALL ON FUNCTION public.restore_test_note_b() FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.restore_test_note_b() TO service_role;
