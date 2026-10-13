# BYTE BACK 방어전 6단계 저장점

이 저장소는 등록된 기기(`request.deviceRegistered === true`)만 자료실 접근을 허용하고, 미등록 기기는 이유 코드 `device_not_registered`와 함께 거부하는 6단계 상태입니다.

## 현재 작동하는 기능

- `/`은 로그아웃 상태에서 이메일·비밀번호 로그인 화면을 표시합니다.
- 브라우저에 Supabase 공개 키(`sb_publishable_…` / `anon`)가 전혀 없으며, 서버 함수(`/api/auth`)를 통해 로그인을 안전하게 중계합니다.
- 브라우저 코드는 메모 테이블을 직접 호출하지 않고, 오직 서버 함수(`/api/notes`)만 호출합니다.
- 서버 함수(`api/notes.js`)는 서버 전용 키(service_role)를 사용하여 로그인·소유자 검증(IDOR 방어)을 수행한 후 DB에 접근합니다:
  - `GET /api/notes`: 로그인한 사용자의 메모 목록만 반환
  - `GET /api/notes/:id`: 대상 메모의 소유자 검증 후 단건 반환 (타인 메모는 `403 FORBIDDEN`)
  - `POST /api/notes`: 검증된 사용자 ID를 `owner_id`로 저장
  - `PUT /api/notes/:id`: 소유자 확인 후 본인 메모만 수정 (타인 메모는 `403 FORBIDDEN`)
  - `DELETE /api/notes/:id`: 소유자 확인 후 본인 메모만 삭제 (타인 메모는 `403 FORBIDDEN`)
- 학생 판정기(`src/decider.mjs`)에 6단계 기기 등록 검증 규칙(`device_registered`)이 구현되어 있습니다:
  - 등록된 기기(`deviceRegistered === true`): `decision: 'allow'`, `reasonCode: 'approved'`
  - 미등록 기기 또는 누락된 요청: `decision: 'deny'`, `reasonCode: 'device_not_registered'`
- `aleph.config.json`에 원본 자료 API의 HTTPS 주소(`originalApiUrl`) 및 step 6이 등록되어 있습니다.
- `/data.json`은 빈 목록(`{"notes": []}`)을 유지하며 빌드 시 `/aleph.json`이 자동 생성됩니다.

## 판정기 확인 순서

이번 과정에는 따로 설치할 접속 프로그램이 없으며, 미등록 기기 공격 시도는 심판이 맡습니다. 로컬에서는 아래 가상 요청 순서로 판정기를 직접 확인합니다:

1. 로컬 판정기 가상 요청 시험 실행:
   ```bash
   npm run decider:test
   ```
2. 출력 확인:
   - `통과 · 등록 기기의 정상 요청`: 등록 기기의 요청이 `allow`로 통과하는지 확인합니다.
   - `통과 · 미등록 기기의 가상 요청`: 미등록 기기(`deviceRegistered: false`) 요청이 `deny` 및 `device_not_registered`로 정상 거부되는지 확인합니다.

## 다시 실행하고 직접 확인하기

로컬 시험 실행:
```bash
npm run decider:test
npm run test:package
npm run test:r5
npm run build -- --local
```

배포 후 확인 항목:
1. 등록 기기에서 기존 화면이 열리고 로그인 및 메모 CRUD가 정상 작동하는지 확인합니다.
2. 미등록 기기 접근 차단은 심판이 격리 환경에서 가상 요청으로 판정합니다.
3. 원본 자료 주소(`originalApiUrl`)를 공개 키로 직접 호출했을 때 메모 자료가 조회되지 않는지 확인합니다.
