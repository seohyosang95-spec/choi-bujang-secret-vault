-- Stage 11: private server-side copies used by POST /api/notes/restore.
-- The service_role-backed server function is the only intended reader.
begin;

create extension if not exists pgcrypto;

create table if not exists public.note_restore_copies (
  id uuid primary key,
  owner_id uuid not null references auth.users(id),
  title text not null,
  content text not null,
  content_sha256 text not null check (content_sha256 ~ '^[0-9a-f]{64}$'),
  copied_at timestamptz not null default now()
);

alter table public.note_restore_copies enable row level security;
revoke all privileges on table public.note_restore_copies from public, anon, authenticated;

commit;

-- Prepare exactly one private B-owned copy without exposing its contents in the
-- repository. Replace the owner selector with the test account B in Supabase
-- SQL editor, then verify the resulting row before using the restore route.
--
-- insert into public.note_restore_copies (id, owner_id, title, content, content_sha256)
-- select n.id, n.owner_id, n.title, n.content, encode(digest(n.content, 'sha256'), 'hex')
-- from public.notes n
-- where n.owner_id = '<B-user-uuid>'
-- order by n.created_at asc
-- limit 1
-- on conflict (id) do update set
--   owner_id = excluded.owner_id,
--   title = excluded.title,
--   content = excluded.content,
--   content_sha256 = excluded.content_sha256;
