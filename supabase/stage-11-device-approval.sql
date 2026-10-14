-- Stage 11: server-side device approval records.
-- The browser receives only an HttpOnly cookie; the raw opaque value is never
-- stored in localStorage, returned in JSON, or written to this table.
begin;

create table if not exists public.device_registrations (
  id uuid primary key default gen_random_uuid(),
  owner_id uuid not null references auth.users(id),
  device_token_hash text not null unique check (device_token_hash ~ '^[0-9a-f]{64}$'),
  status text not null default 'pending' check (status in ('pending', 'approved', 'revoked')),
  requested_at timestamptz not null default now(),
  approved_at timestamptz,
  revoked_at timestamptz,
  created_at timestamptz not null default now()
);

create index if not exists device_registrations_owner_status_idx
  on public.device_registrations (owner_id, status);

alter table public.device_registrations enable row level security;
revoke all privileges on table public.device_registrations from public, anon, authenticated;
grant select, insert, update, delete on table public.device_registrations to service_role;

commit;

-- Approval is an operator action, never a browser button action. After the
-- browser sends POST /api/device/approval, approve the requested row in the
-- Supabase SQL editor using the authenticated B owner UUID, for example:
-- update public.device_registrations
-- set status = 'approved', approved_at = now()
-- where owner_id = '<B-user-uuid>' and status = 'pending';
