begin;

create extension if not exists pgcrypto;

do $$
begin
  if exists (
    select 1
    from information_schema.columns
    where table_schema = 'public'
      and table_name = 'notes'
      and column_name = 'id'
      and data_type <> 'uuid'
  ) then
    alter table public.notes
      add column api_id uuid not null default gen_random_uuid();
    alter table public.notes drop constraint if exists notes_pkey;
    alter table public.notes drop column id;
    alter table public.notes rename column api_id to id;
    alter table public.notes add primary key (id);
    drop sequence if exists public.notes_id_seq;
  end if;
end $$;

alter table public.notes
  alter column id set default gen_random_uuid();

alter table public.notes enable row level security;
revoke all privileges on table public.notes from anon, authenticated;

commit;

select column_name, data_type, column_default
from information_schema.columns
where table_schema = 'public'
  and table_name = 'notes'
  and column_name in ('id', 'owner_id')
order by column_name;

select relrowsecurity as rls_enabled
from pg_catalog.pg_class
where oid = 'public.notes'::regclass;
