create table if not exists public.vault_notes (
  id uuid primary key default gen_random_uuid(),
  owner_id uuid,
  title text not null,
  content text not null,
  created_at timestamptz not null default now()
);

alter table public.vault_notes enable row level security;

revoke all on table public.vault_notes from anon, authenticated;

insert into public.vault_notes (id, title, content)
values
  ('00000000-0000-4000-8000-000000000001', '과제', '실습용 가상 과제 기록'),
  ('00000000-0000-4000-8000-000000000002', '포트폴리오', '실습용 가상 포트폴리오 기록'),
  ('00000000-0000-4000-8000-000000000003', '아침 리추얼', '실습용 가상 리추얼 기록'),
  ('00000000-0000-4000-8000-000000000004', '훈련 행정 자료', '실습용 가상 행정 기록')
on conflict (id) do update
set title = excluded.title,
    content = excluded.content;