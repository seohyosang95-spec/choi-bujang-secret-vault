-- =====================================================================
-- 5단계 제작 2: notes 테이블에서 PUBLIC, anon, authenticated 직접 권한 회수 SQL
-- =====================================================================

-- [1] 적용 전 권한 및 역할 권한 대조 확인
-- 기대 결과(적용 전): authenticated 등에 권한이 남아있을 수 있음
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

-- [2] 권한 회수 트랜잭션 실행
begin;

-- RLS 활성화 상태 유지 확인
alter table public.notes enable row level security;

-- PUBLIC, anon, authenticated 역할의 모든 권한 완전 회수
revoke all privileges on table public.notes from public, anon, authenticated;

commit;

-- [3] 적용 후 권한 대조 확인
-- 기대 결과:
-- - role_table_grants: anon, authenticated 역할에 대해 아무 권한도 조회되지 않아야 함 (0 rows)
-- - has_table_privilege: anon, authenticated 모두 can_select, can_insert, can_update, can_delete가 false여야 함
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
