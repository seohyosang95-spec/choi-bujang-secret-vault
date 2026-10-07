# BYTE BACK 방어전 3단계 저장점

이 저장소는 Supabase Auth 이메일·비밀번호 로그인과 인증된 가상 메모 CRUD를 붙인 3단계 상태입니다. 비밀번호와 JWT는 공식 Supabase SDK가 처리하며 코드·로그·응답·Git에 저장하지 않습니다.

## 현재 작동하는 기능

- `/`은 로그아웃 상태에서 이메일·비밀번호 로그인 화면을 표시합니다.
- 공식 `@supabase/supabase-js` 흐름의 `signInWithPassword`, `getSession`, `onAuthStateChange`, `signOut`을 사용합니다.
- 로그인 실패 이유는 로그인 화면에 표시하며, 로그인 뒤에는 로그아웃·메모 추가·수정·삭제 화면으로 바뀝니다.
- 브라우저는 SDK가 발급한 access token만 `Authorization: Bearer …` 헤더로 `/api/notes`에 보냅니다.
- 서버는 수정하지 않은 `src/verify-login.mjs`로 토큰을 검사하고, 검증된 `userId`만 새 메모의 `owner_id`로 저장합니다. 브라우저 본문의 `userId`나 `role`은 읽지 않습니다.
- 비로그인 또는 검증 실패 요청은 자료 없이 `401 {"error":"AUTH_REQUIRED"}`로 거부합니다.
- `/data.json`은 계속 메모 0건이며 `/aleph.json` 생성과 `X-Content-Type-Options: nosniff` 설정도 유지합니다.

## 공개 Supabase 설정

`public/auth-config.js`에는 브라우저에서 써도 되는 Supabase Project URL과 publishable key가 설정되어 있습니다. `aleph.config.json`에는 같은 프로젝트의 `/auth/v1` 발급자, `authenticated` 대상, 공개 JWKS 주소가 기록되어 있습니다.

Vercel의 `SUPABASE_URL`과 서버 전용 `SUPABASE_SECRET_KEY`는 서버 환경변수에만 둡니다. 서버 전용 키는 브라우저 파일·응답·로그에 넣지 않습니다.

`supabase/step3-auth-crud.sql`을 Supabase **SQL Editor → New query → Run**에서 한 번 실행합니다. 기존 숫자 ID를 UUID로 바꾸고 UUID 기본값, `owner_id uuid`, RLS, `anon`·`authenticated` 권한 회수를 유지합니다.

## 자료 API 계약

모든 경로는 정상 토큰이 필요합니다.

- `GET /api/notes`: 메모 배열
- `POST /api/notes`: `{id?, title, body}`를 받고 `{id}` 반환. ID가 없으면 서버가 UUID 생성
- `GET /api/notes/:id`: `{id, title, body}` 또는 404
- `PUT /api/notes/:id`: `{title, body}`로 수정
- `DELETE /api/notes/:id`: 삭제 후 같은 ID의 GET은 404

3단계에서는 로그인 여부만 검사합니다. 단건 GET·PUT·DELETE에 `owner_id` 조건이 아직 없어 B가 A의 메모에 접근할 수 있는 허점은 4단계에서 확인하고 막습니다.

## 다시 실행하고 직접 확인하기

로컬 정적 결과와 자동 시험은 `npm run build -- --local && npm run test:package && npm run test:r5`로 실행합니다. 로컬 시험은 실제 Supabase 로그인이나 Vercel 배포 성공을 증명하지 않습니다.

배포 후 화면에서 다음 순서로 확인합니다.

1. 시크릿 창에서 `/api/notes`를 열어 401 JSON 오류가 오고 메모가 보이지 않는지 확인합니다.
2. A 계정으로 로그인해 화면이 메모 목록·편집 화면으로 바뀌는지 확인합니다.
3. 메모를 추가하고 수정한 뒤 삭제하며, 삭제한 ID의 GET이 404인지 확인합니다.
4. 로그아웃해 로그인 화면으로 돌아오고 자료 화면이 사라지는지 확인합니다.
5. `/aleph.json`이 열리고 첫 문서 응답에 `X-Content-Type-Options: nosniff`가 있는지 확인합니다.
6. 브라우저 Sources와 Network 응답·로그에 `SUPABASE_SECRET_KEY` 값이 없는지 확인합니다.

정상 결과는 A 로그인 뒤 CRUD가 되고 로그아웃 뒤 로그인 화면으로 돌아오는 것입니다. 거부되어야 할 결과는 토큰이 없거나 검증에 실패한 자료 요청이며, HTML이나 빈 화면이 아니라 401 JSON 오류가 와야 합니다.

## 과거 노출과 현재 한계

첫 커밋과 옛 배포에 공개 가상 메모가 남아 있는 한 과거 노출이 해소됐다고 쓰지 않습니다. 3단계는 새 요청에 로그인 검사를 추가하지만, B가 A의 메모 ID를 알면 읽고 수정하거나 삭제할 수 있는 소유자 검증 결함을 의도적으로 남깁니다. 이 결함은 4단계 범위입니다.
