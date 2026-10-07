-- =====================================================================
-- 4단계 제작 1: 가상 메모 소유자(owner_id) 연결 및 시험 메모 준비
-- =====================================================================
-- 사용법:
-- 아래 'user_a@example.com'과 'user_b@example.com' 자리에
-- 실제 Supabase auth.users에 등록된 A와 B의 이메일을 입력한 후 실행하세요.

begin;

do $$
declare
  user_a_id uuid;
  user_b_id uuid;
begin
  -- 1. A 계정의 ID 조회
  select id into user_a_id
  from auth.users
  where email = 'user_a@example.com'; -- <<< 여기에 A의 실제 이메일 입력

  if user_a_id is null then
    raise exception 'A 계정(user_a@example.com)을 auth.users에서 찾을 수 없습니다. 이메일을 확인하세요.';
  end if;

  -- 2. B 계정의 ID 조회
  select id into user_b_id
  from auth.users
  where email = 'user_b@example.com'; -- <<< 여기에 B의 실제 이메일 입력

  if user_b_id is null then
    raise exception 'B 계정(user_b@example.com)을 auth.users에서 찾을 수 없습니다. 이메일을 확인하세요.';
  end if;

  -- 3. 기존 가상 메모 3개에 A의 owner_id 연결
  update public.notes
  set owner_id = user_a_id
  where id in (
    select id
    from public.notes
    order by created_at asc
    limit 3
  );

  -- 4. B 소유의 공개 가능한 시험 메모 한 건 준비
  insert into public.notes (id, owner_id, title, content)
  values (
    gen_random_uuid(),
    user_b_id,
    'B의 시험 메모',
    'B 사용자가 소유한 공개 가능한 시험용 메모입니다.'
  )
  on conflict (title) do update
  set owner_id = excluded.owner_id,
      content = excluded.content;
end $$;

commit;

-- 5. 결과 확인: A의 세 메모와 B의 한 메모에 각각 올바른 소유자 ID가 있는지 확인
select
  n.id,
  n.title,
  n.owner_id,
  u.email as owner_email,
  n.created_at
from public.notes n
left join auth.users u on n.owner_id = u.id
order by n.created_at asc;
