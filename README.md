# BYTE BACK 방어전 4단계 저장점

이 저장소는 메모 CRUD API에 소유자 검증(IDOR 방어)과 데이터베이스 RLS 최소 권한 정책을 적용한 4단계 상태입니다. 검증된 사용자 ID와 DB의 `owner_id`를 비교하여 본인 데이터만 접근하도록 통제합니다.

## 현재 작동하는 기능

- `/`은 로그아웃 상태에서 이메일·비밀번호 로그인 화면을 표시합니다.
- 공식 `@supabase/supabase-js` 흐름의 `signInWithPassword`, `getSession`, `onAuthStateChange`, `signOut`을 사용합니다.
- 브라우저는 SDK가 발급한 access token만 `Authorization: Bearer …` 헤더로 `/api/notes`에 보냅니다.
- 서버는 `src/verify-login.mjs`로 토큰을 검사하고, 검증된 `userId`를 통해 메모 소유권을 엄격히 검증합니다:
  - `GET /api/notes`: 현재 로그인한 사용자의 `owner_id`와 일치하는 메모 목록만 반환합니다.
  - `GET /api/notes/:id`: 대상 메모의 `owner_id`가 본인인지 확인하며, 타인 메모는 `403 {"error":"FORBIDDEN"}`으로 거부합니다.
  - `POST /api/notes`: 클라이언트의 본문 값과 무관하게 확인된 `login.userId`를 `owner_id`로 강제 지정합니다.
  - `PUT /api/notes/:id`: 기존 행의 `owner_id`와 새로 갱신될 행의 소유자가 모두 본인인지 검증하며, 타인 메모는 `403 {"error":"FORBIDDEN"}`으로 거부합니다.
  - `DELETE /api/notes/:id`: 기존 행의 `owner_id`가 본인인지 검증하여 본인 것만 삭제를 허용하며, 타인 메모는 `403 {"error":"FORBIDDEN"}`으로 거부합니다.
- 비로그인 요청은 401 JSON 오류(`{"error":"AUTH_REQUIRED"}`)로 거부합니다.
- `/data.json`은 빈 목록(`{"notes": []}`)을 유지하며 빌드 시 `/aleph.json`이 자동 생성됩니다.

## Supabase SQL 실행 가이드

1. **소유자 분리 및 시험 메모 준비**:
   - `supabase/step4-owners.sql` 파일의 `user_a@example.com`과 `user_b@example.com`에 실제 A와 B의 이메일을 입력한 뒤, Supabase SQL Editor에서 실행합니다.
   - 기존 가상 메모 3개는 A 소유로 연결되고, B 소유의 공개 가능한 시험 메모 1건이 생성됩니다.
2. **RLS 및 최소 권한 설정**:
   - `supabase/step4-rls.sql`을 Supabase SQL Editor에서 실행합니다.
   - `anon` 역할의 권한을 완전 회수하고, `authenticated` 역할에 대해서만 `auth.uid() = owner_id` 조건의 RLS(SELECT, INSERT, UPDATE, DELETE) 정책을 적용합니다.

## 다시 실행하고 직접 확인하기

로컬 시험 실행:
```bash
npm run build -- --local
npm run test:package
npm run test:r5
```

배포 후 확인 항목:
1. A 계정으로 로그인 시 A의 메모 3건이 정상 조회·수정·삭제되는지 확인합니다.
2. B 계정으로 로그인 시 A의 메모가 목록에 보이지 않고, B의 시험 메모만 조회·수정·삭제되는지 확인합니다.
3. B 계정 토큰으로 A의 메모 ID를 직접 조회(`GET /api/notes/:id`), 수정(`PUT`), 삭제(`DELETE`) 시도할 때 모두 `403 FORBIDDEN`으로 거부되는지 확인합니다.
4. 비로그인 요청 시 `401 AUTH_REQUIRED` JSON 오류가 오는지 확인합니다.
