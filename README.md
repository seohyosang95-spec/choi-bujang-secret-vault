# BYTE BACK 방어전 7단계 저장점

이 저장소는 등록된 기기(`request.deviceRegistered === true`) 중에서도 평소와 다른 시각·처음 보는 네트워크·대량 조회가 결합된 복합 이상 접속에 대해 추가 본인 확인(`step_up_required`)을 요구하고, 미등록 기기는 이유 코드 `device_not_registered`로 차단하는 7단계 상태입니다.

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
- 학생 판정기(`src/decider.mjs`)에 6~7단계 판정 규칙(`device_registered`, `step_up_required`)이 구현되어 있습니다:
  - 미등록 기기(`deviceRegistered !== true`): `decision: 'deny'`, `reasonCode: 'device_not_registered'`
  - 복합 이상 접속(처음 보는 네트워크 + 이상 시각/원격 지역 + 대량 조회 이상 징후): `decision: 'step_up'`, `reasonCode: 'step_up_required'`
  - 재인증 완료 요청(`stepUp.verified === true`, `authAgeSeconds <= 900`): `decision: 'allow'`, `reasonCode: 'approved'`
  - 등록 기기의 정상 요청: `decision: 'allow'`, `reasonCode: 'approved'`
- 제공 엔진 계약 상태:
  - 제공 엔진이 재로그인 시각을 확인하는 계약이 준비된 환경에서만 다시 로그인 전 차단과 새 요청 허용을 실측합니다.
  - 현재 시작 틀 환경에는 해당 계약이 아직 준비되지 않았으므로, 가상 사건 규칙만 시험(`npm run fixture:7`)하고 실제 자료 차단은 미실행으로 남깁니다. (토큰 원문은 기록하지 않습니다.)
- `aleph.config.json`에 원본 자료 API의 HTTPS 주소(`originalApiUrl`) 및 step 7이 등록되어 있습니다.
- `/data.json`은 빈 목록(`{"notes": []}`)을 유지하며 빌드 시 `/aleph.json`이 자동 생성됩니다.

## 판정기 및 가상 사건 확인 순서

1. 가상 요청 판정기 시험 실행:
   ```bash
   npm run decider:test
   ```
   - `등록 기기의 정상 요청`: `allow` 통과
   - `미등록 기기의 가상 요청`: `deny` 및 `device_not_registered` 거부
   - `복합 이상 접속`: `step_up` 및 `step_up_required` 추가 본인 확인 요구
   - `다시 확인한 복합 이상 접속`: `allow` 통과

2. 가상 사건 비교 시험 실행:
   ```bash
   npm run fixture:7
   ```
   - 정상 사건: `allow`
   - 복합 이상 사건: `step_up`

## 다시 실행하고 직접 확인하기

로컬 시험 실행:
```bash
npm run fixture:7
npm run decider:test
npm run test:r5
npm run build -- --local
```

배포 후 확인 항목:
1. 정상 등록 기기에서 기존 로그인 및 메모 CRUD가 정상 작동하는지 확인합니다.
2. 정상 사건(`allow`)과 복합 이상 사건(`step_up`)의 판정이 다르게 작동하는지 확인합니다.
3. 원본 자료 주소(`originalApiUrl`)를 공개 키로 직접 호출했을 때 메모 자료가 조회되지 않는지 확인합니다.
