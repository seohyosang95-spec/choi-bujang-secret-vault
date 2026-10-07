# BYTE BACK 방어전 5단계 저장점

이 저장소는 모든 메모 자료 요청을 서버 함수(`/api/notes`) 한곳으로 모으고, 브라우저나 외부에서 Supabase REST API(`originalApiUrl`)로 메모를 직접 조회하지 못하도록 데이터베이스 직접 권한을 회수한 5단계 상태입니다.

## 현재 작동하는 기능

- `/`은 로그아웃 상태에서 이메일·비밀번호 로그인 화면을 표시합니다.
- 공식 `@supabase/supabase-js` 흐름의 `signInWithPassword`, `getSession`, `onAuthStateChange`, `signOut`을 사용합니다.
- 브라우저 코드는 메모 테이블을 직접 호출하지 않고, 오직 서버 함수(`/api/notes`)만 호출합니다.
- 서버 함수(`api/notes.js`)는 `SUPABASE_SECRET_KEY`를 사용하여 로그인·소유자 검증(IDOR 방어)을 수행한 후 DB에 접근합니다:
  - `GET /api/notes`: 로그인한 사용자의 메모 목록만 반환
  - `GET /api/notes/:id`: 대상 메모의 소유자 검증 후 단건 반환 (타인 메모는 `403 FORBIDDEN`)
  - `POST /api/notes`: 검증된 사용자 ID를 `owner_id`로 저장
  - `PUT /api/notes/:id`: 소유자 확인 후 본인 메모만 수정 (타인 메모는 `403 FORBIDDEN`)
  - `DELETE /api/notes/:id`: 소유자 확인 후 본인 메모만 삭제 (타인 메모는 `403 FORBIDDEN`)
- `aleph.config.json`에 원본 자료 API의 HTTPS 주소(`originalApiUrl`)가 등록되어 있습니다.
- `/data.json`은 빈 목록(`{"notes": []}`)을 유지하며 빌드 시 `/aleph.json`이 자동 생성됩니다.

## Supabase SQL 실행 가이드

1. **PUBLIC·anon·authenticated 권한 회수**:
   - `supabase/step5-revoke.sql`을 Supabase SQL Editor에서 실행합니다.
   - `notes` 테이블에 대해 `PUBLIC`, `anon`, `authenticated`의 직접 권한이 모두 회수되어 외부에서 anon/auth 키로 원본 엔드포인트를 직접 조회해도 자료가 노출되지 않습니다.
   - 서버 함수는 `SUPABASE_SECRET_KEY`(service_role)를 통해 정상 작동을 유지합니다.

## 다시 실행하고 직접 확인하기

로컬 시험 실행:
```bash
npm run build -- --local
npm run test:package
npm run test:r5
```

배포 후 확인 항목:
1. 브라우저에서 A 사용자로 로그인하여 메모 읽기, 추가, 수정, 삭제가 정상 작동하는지 확인합니다.
2. B 사용자로 로그인했을 때 A의 메모가 보이지 않고, B의 메모만 다뤄지는지 확인합니다.
3. 원본 자료 주소(`originalApiUrl`)를 공개 키(`anon` 키)로 직접 `curl` 또는 브라우저/Postman에서 호출했을 때 메모 자료가 조회되지 않는지 확인합니다.
