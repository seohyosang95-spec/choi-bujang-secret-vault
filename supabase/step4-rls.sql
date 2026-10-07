-- =====================================================================
-- 4단계 제작 3: notes 테이블 RLS 정책 및 최소 권한 설정 SQL
-- =====================================================================

-- [1] 적용 전 권한 및 RLS 상태 대조 확인
select grantee, privilege_type
from information_schema.role_table_grants
where table_schema = 'public'
  and table_name = 'notes'
  and grantee in ('anon', 'authenticated')
order by grantee, privilege_type;

select
  r.rolname,
  has_table_privilege(r.rolname, 'public.notes', 'SELECT') as can_select,
  has_table_privilege(r.rolname, 'public.notes', 'INSERT') as can_insert,
  has_table_privilege(r.rolname, 'public.notes', 'UPDATE') as can_update,
  has_table_privilege(r.rolname, 'public.notes', 'DELETE') as can_delete
from pg_roles r
where r.rolname in ('anon', 'authenticated');

-- [2] 권한 회수 및 최소 권한 부여, RLS 정책 적용
begin;

-- RLS 활성화
alter table public.notes enable row level security;

-- 기존 권한 회수 (PUBLIC, anon, authenticated)
revoke all on table public.notes from public, anon, authenticated;

-- authenticated 역할에 SELECT·INSERT·UPDATE·DELETE 부여
grant select, insert, update, delete on table public.notes to authenticated;

-- 기존 정책 중복 방지 정리
drop policy if exists "notes_select_owner_only" on public.notes;
drop policy if exists "notes_insert_owner_only" on public.notes;
drop policy if exists "notes_update_owner_only" on public.notes;
drop policy if exists "notes_delete_owner_only" on public.notes;

-- SELECT 정책: auth.uid() = owner_id인 기존 행만 조회 허용
create policy "notes_select_owner_only" on public.notes
  for select
  to authenticated
  using (auth.uid() = owner_id);

-- INSERT 정책: auth.uid() = owner_id인 새 행만 추가 허용
create policy "notes_insert_owner_only" on public.notes
  for insert
  to authenticated
  with check (auth.uid() = owner_id);

-- UPDATE 정책: 기존 행 USING 및 새 행 WITH CHECK 모두 auth.uid() = owner_id일 때만 수정 허용
create policy "notes_update_owner_only" on public.notes
  for update
  to authenticated
  using (auth.uid() = owner_id)
  with check (auth.uid() = owner_id);

-- DELETE 정책: auth.uid() = owner_id인 기존 행만 삭제 허용
create policy "notes_delete_owner_only" on public.notes
  for delete
  to authenticated
  using (auth.uid() = owner_id);

commit;

-- [3] 적용 후 권한 및 RLS 상태 대조 확인
-- 기대 결과:
-- - anon: 권한 없음 (결과 행 없음, has_table_privilege 모두 false)
-- - authenticated: SELECT, INSERT, UPDATE, DELETE만 존재 (true)
select grantee, privilege_type
from information_schema.role_table_grants
where table_schema = 'public'
  and table_name = 'notes'
  and grantee in ('anon', 'authenticated')
order by grantee, privilege_type;

select
  r.rolname,
  has_table_privilege(r.rolname, 'public.notes', 'SELECT') as can_select,
  has_table_privilege(r.rolname, 'public.notes', 'INSERT') as can_insert,
  has_table_privilege(r.rolname, 'public.notes', 'UPDATE') as can_update,
  has_table_privilege(r.rolname, 'public.notes', 'DELETE') as can_delete
from pg_roles r
where r.rolname in ('anon', 'authenticated');

-- 등록된 RLS 정책 확인
select
  policyname,
  roles,
  cmd,
  qual as using_expression,
  with_check as with_check_expression
from pg_policies
where schemaname = 'public'
  and tablename = 'notes'
order by policyname;
