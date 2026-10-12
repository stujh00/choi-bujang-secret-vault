-- Step 4 ownership practice. This is a manual learning script, not a migration.
-- Replace both email placeholders in the Supabase SQL Editor before running.
-- Do not save real account emails back into this repository.

DO $step4$
DECLARE
  a_email text := 'A_EMAIL_PLACEHOLDER';
  b_email text := 'B_EMAIL_PLACEHOLDER';
  a_match_count bigint;
  b_match_count bigint;
  a_owner_id uuid;
  b_owner_id uuid;
  test_note_id constant uuid := '00000000-0000-4000-8000-000000000005';
  test_note_title constant text := 'B 소유 공개 시험 메모';
  test_note_content constant text := '공개 가능한 가상 시험 자료입니다. 민감 정보는 포함하지 않습니다.';
BEGIN
  IF position('@' IN a_email) = 0 OR position('@' IN b_email) = 0 THEN
    RAISE EXCEPTION 'Replace both account email placeholders before running; no notes were changed.';
  END IF;

  SELECT count(*), (array_agg(id))[1]
    INTO a_match_count, a_owner_id
    FROM auth.users
    WHERE lower(email) = lower(a_email);

  SELECT count(*), (array_agg(id))[1]
    INTO b_match_count, b_owner_id
    FROM auth.users
    WHERE lower(email) = lower(b_email);

  IF a_match_count <> 1 OR a_owner_id IS NULL
      OR b_match_count <> 1 OR b_owner_id IS NULL THEN
    RAISE EXCEPTION 'Each account email must match exactly one auth.users row; no notes were changed.';
  END IF;

  IF (SELECT count(*)
      FROM public.vault_notes
      WHERE id IN (
        '00000000-0000-4000-8000-000000000001'::uuid,
        '00000000-0000-4000-8000-000000000002'::uuid,
        '00000000-0000-4000-8000-000000000003'::uuid,
        '00000000-0000-4000-8000-000000000004'::uuid
      )) <> 4 THEN
    RAISE EXCEPTION 'The four seeded virtual notes were not all found; no notes were changed.';
  END IF;

  IF EXISTS (
    SELECT 1
    FROM public.vault_notes
    WHERE id = test_note_id
      AND (owner_id IS DISTINCT FROM b_owner_id
        OR title IS DISTINCT FROM test_note_title
        OR content IS DISTINCT FROM test_note_content)
  ) THEN
    RAISE EXCEPTION 'The reserved test note ID is already used by a different note; no notes were changed.';
  END IF;

  UPDATE public.vault_notes
  SET owner_id = a_owner_id
  WHERE id IN (
    '00000000-0000-4000-8000-000000000001'::uuid,
    '00000000-0000-4000-8000-000000000002'::uuid,
    '00000000-0000-4000-8000-000000000003'::uuid,
    '00000000-0000-4000-8000-000000000004'::uuid
  );

  INSERT INTO public.vault_notes (id, owner_id, title, content)
  VALUES (test_note_id, b_owner_id, test_note_title, test_note_content)
  ON CONFLICT (id) DO NOTHING;
END
$step4$;

SELECT id, title, owner_id
FROM public.vault_notes
WHERE id IN (
  '00000000-0000-4000-8000-000000000001'::uuid,
  '00000000-0000-4000-8000-000000000002'::uuid,
  '00000000-0000-4000-8000-000000000003'::uuid,
  '00000000-0000-4000-8000-000000000004'::uuid,
  '00000000-0000-4000-8000-000000000005'::uuid
)
ORDER BY id;
