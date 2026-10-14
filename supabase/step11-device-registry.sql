-- Metadata only. This table never contains notes, keys or authentication tokens.
create table if not exists public.vault_devices (
  id uuid primary key default gen_random_uuid(),
  owner_id uuid not null references auth.users(id) on delete cascade,
  device_id text not null check (device_id ~ '^[0-9a-f]{16}$'),
  status text not null default 'pending' check (status in ('pending','approved','rejected','revoked')),
  requested_at timestamptz not null default now(),
  approved_at timestamptz,
  expires_at timestamptz,
  reviewed_by text,
  unique(owner_id,device_id),
  check (status <> 'approved' or (approved_at is not null and expires_at > approved_at and reviewed_by is not null))
);
alter table public.vault_devices enable row level security;
revoke all on public.vault_devices from public, anon, authenticated;
grant select,insert,update,delete on public.vault_devices to service_role;
