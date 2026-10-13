-- 10단계: 사전 확인된 가상 B 메모 1건만 비공개 DB에 보관.
-- Supabase SQL Editor에서 심판에게 10단계를 제출하기 *전에* 한 번 실행합니다.
-- 이 파일은 원본 제목/내용을 공개 Git 파일에서 읽지만 사본 표는 Supabase 내부에만 생성합니다.
-- 원본이 이미 변조/삭제된 경우 중단하며, 그 상태를 정상 백업으로 간주하지 않습니다.
BEGIN;

CREATE TABLE IF NOT EXISTS public.vault_recovery_snapshots (
  id uuid PRIMARY KEY,
  owner_id uuid NOT NULL,
  title text NOT NULL,
  content text NOT NULL,
  content_sha256 text NOT NULL CHECK (content_sha256 ~ '^[0-9a-f]{64}$'),
  verified_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS public.vault_recovery_audit (
  audit_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  note_id uuid NOT NULL,
  operation text NOT NULL CHECK (operation IN ('restore')),
  content_sha256 text NOT NULL,
  recorded_at timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE public.vault_recovery_snapshots ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.vault_recovery_audit ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON TABLE public.vault_recovery_snapshots, public.vault_recovery_audit
  FROM PUBLIC, anon, authenticated, service_role;
REVOKE ALL ON SEQUENCE public.vault_recovery_audit_audit_id_seq
  FROM PUBLIC, anon, authenticated, service_role;

DO $safe_snapshot$
DECLARE
  saved public.vault_notes%ROWTYPE;
  previous public.vault_recovery_snapshots%ROWTYPE;
  expected_id CONSTANT uuid := '00000000-0000-4000-8000-000000000005';
  expected_title CONSTANT text := 'B 소유 공개 시험 메모';
  expected_content CONSTANT text := '공개 가능한 가상 시험 자료입니다. 민감 정보는 포함하지 않습니다.';
  computed_hash text;
BEGIN
  SELECT * INTO saved FROM public.vault_notes WHERE id = expected_id;
  IF NOT FOUND OR saved.owner_id IS NULL
      OR saved.title IS DISTINCT FROM expected_title
      OR saved.content IS DISTINCT FROM expected_content THEN
    RAISE EXCEPTION 'B source note missing or not identical to verified stage4 baseline; no snapshot is written';
  END IF;
  computed_hash := encode(sha256(convert_to(
    jsonb_build_object('id', saved.id, 'owner_id', saved.owner_id,
      'title', saved.title, 'content', saved.content)::text, 'UTF8')), 'hex');
  SELECT * INTO previous FROM public.vault_recovery_snapshots WHERE id = expected_id;
  IF FOUND THEN
    IF previous.owner_id IS DISTINCT FROM saved.owner_id
        OR previous.title IS DISTINCT FROM saved.title
        OR previous.content IS DISTINCT FROM saved.content
        OR previous.content_sha256 IS DISTINCT FROM computed_hash THEN
      RAISE EXCEPTION 'Existing immutable backup mismatch; refuse overwrite';
    END IF;
  ELSE
    INSERT INTO public.vault_recovery_snapshots
      (id, owner_id, title, content, content_sha256)
    VALUES (saved.id, saved.owner_id, saved.title, saved.content, computed_hash);
  END IF;
END
$safe_snapshot$;

-- Restore is a single database transaction: if a check fails, nothing is committed.
-- The API only invokes this RPC after verifying a short-lived, B-targeted judge JWT.
CREATE OR REPLACE FUNCTION public.restore_test_note_b()
RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = ''
AS $restore$
DECLARE
  backup public.vault_recovery_snapshots%ROWTYPE;
  existing public.vault_notes%ROWTYPE;
  result public.vault_notes%ROWTYPE;
  actual_hash text;
  affected bigint;
  expected_id CONSTANT uuid := '00000000-0000-4000-8000-000000000005';
BEGIN
  SELECT * INTO backup FROM public.vault_recovery_snapshots
    WHERE id = expected_id FOR SHARE;
  IF NOT FOUND OR backup.owner_id IS NULL THEN
    RAISE EXCEPTION 'verified backup not installed';
  END IF;
  actual_hash := encode(sha256(convert_to(
    jsonb_build_object('id', backup.id, 'owner_id', backup.owner_id,
      'title', backup.title, 'content', backup.content)::text, 'UTF8')), 'hex');
  IF actual_hash IS DISTINCT FROM backup.content_sha256 THEN
    RAISE EXCEPTION 'backup integrity mismatch';
  END IF;

  SELECT * INTO existing FROM public.vault_notes WHERE id = expected_id FOR UPDATE;
  IF FOUND AND existing.owner_id IS DISTINCT FROM backup.owner_id THEN
    RAISE EXCEPTION 'restore target ownership mismatch; refuse overwrite';
  END IF;

  INSERT INTO public.vault_notes (id, owner_id, title, content)
    VALUES (backup.id, backup.owner_id, backup.title, backup.content)
  ON CONFLICT (id) DO UPDATE SET
    title = EXCLUDED.title,
    content = EXCLUDED.content
  WHERE public.vault_notes.owner_id = EXCLUDED.owner_id;
  GET DIAGNOSTICS affected = ROW_COUNT;
  IF affected <> 1 THEN
    RAISE EXCEPTION 'restore did not affect exactly one authorized note';
  END IF;

  SELECT * INTO result FROM public.vault_notes WHERE id = expected_id;
  actual_hash := encode(sha256(convert_to(
    jsonb_build_object('id', result.id, 'owner_id', result.owner_id,
      'title', result.title, 'content', result.content)::text, 'UTF8')), 'hex');
  IF actual_hash IS DISTINCT FROM backup.content_sha256
      OR result.owner_id IS DISTINCT FROM backup.owner_id THEN
    RAISE EXCEPTION 'post-restore hash or owner mismatch';
  END IF;
  INSERT INTO public.vault_recovery_audit(note_id, operation, content_sha256)
    VALUES (backup.id, 'restore', actual_hash);
  RETURN jsonb_build_object('restored', true, 'noteId', backup.id,
    'contentSha256', actual_hash, 'ownerVerified', true);
END
$restore$;

REVOKE ALL ON FUNCTION public.restore_test_note_b()
  FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.restore_test_note_b() TO service_role;
COMMIT;

-- Read-only verification (no titles, content, emails, tokens or owner IDs printed):
SELECT count(*) AS verified_backup_count,
  bool_and(content_sha256 = encode(sha256(convert_to(
    jsonb_build_object('id', id, 'owner_id', owner_id,
    'title', title, 'content', content)::text, 'UTF8')), 'hex')) AS hash_valid
FROM public.vault_recovery_snapshots
WHERE id = '00000000-0000-4000-8000-000000000005'::uuid;
