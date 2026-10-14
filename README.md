# BYTE BACK 방어전 11단계 저장점

이 저장소는 자료마다 갈 수 있는 구역을 분리하고, 검증된 비공개 메모 사본에서 B의 지정 메모 한 건만 복원하며, 서버 승인 기기에서만 자료실을 여는 11단계 상태입니다.

## 현재 작동하는 기능

- `/`은 로그아웃 상태에서 이메일·비밀번호 로그인 화면을 표시합니다.
- 브라우저에 Supabase 공개 키(`sb_publishable_…` / `anon`)가 전혀 없으며, 서버 함수(`/api/auth`)를 통해 로그인을 안전하게 중계합니다.
- 브라우저 코드는 메모 테이블을 직접 호출하지 않고, 오직 서버 함수(`/api/notes`)만 호출합니다.
- 서버가 구별할 수 있는 자원 ID 헤더(`X-Resource-ID`)를 통해 내 메모(`notes`)와 강사 공지(`announcements`) 구역을 분리합니다.
- 서버 함수(`api/notes.js`)는 서버 전용 키(service_role)를 사용하여 검증된 사용자와 저장된 소유자·강사 권한을 대조합니다:
  - 요청 본문이나 헤더의 미검증 `role`을 신뢰하지 않고 검증된 토큰의 권한만 사용
  - 메뉴를 우회한 직접 API 요청에서도 다른 구역 및 알 수 없는 자원 접근 시 `403 FORBIDDEN`
  - 강사 공지 수정·생성·삭제는 검증된 강사만 허용 (`403 FORBIDDEN`)
  - 타인 메모 조회·수정·삭제 요청 거부 (`403 FORBIDDEN`)
  - 본인 메모 조회·생성·수정·삭제 정상 수행
- 학생 판정기(`src/decider.mjs`)에 6~8단계 판정 규칙(`device_registered`, `step_up_required`, `zone_isolation`)이 구현되어 있습니다:
  - 미등록 기기(`deviceRegistered !== true`): `decision: 'deny'`, `reasonCode: 'device_not_registered'`
  - 복합 이상 접속: `decision: 'step_up'`, `reasonCode: 'step_up_required'`
  - 8단계 구역 분리 규칙 (`zone_isolation`):
    - A의 자기 메모 읽기·수정: `decision: 'allow'`, `reasonCode: 'approved'`
    - B의 A 메모 접근 시도: `decision: 'deny'`, `reasonCode: 'forbidden_resource'`
    - 일반 학생의 강사 공지 수정: `decision: 'deny'`, `reasonCode: 'forbidden_resource'`
    - 일반 학생의 강사 공지 읽기: `decision: 'allow'`, `reasonCode: 'approved'`
    - `:id` 깊이의 기능 경로(`/notes/export` 등): `decision: 'deny'`, `reasonCode: 'unknown_route'`
    - 알 수 없는 경로 및 쿼리 우회 경로: `decision: 'deny'`, `reasonCode: 'unknown_route'`
- `aleph.config.json`에 원본 자료 API의 HTTPS 주소(`originalApiUrl`) 및 step 11이 등록되어 있습니다.
- 탐지기(`src/detect.mjs`)는 같은 확인된 `identity.sub`의 GET 사건이 10분 안에 120건을 초과할 때만 한 대상에 대해 `propose_revocation`과 `burst_read`를 제안합니다. 정상 사건은 `observe`로 남기며 실제 회수나 기기 권한 변경은 수행하지 않습니다.
- `/data.json`은 빈 목록(`{"notes": []}`)을 유지하며 빌드 시 `/aleph.json`이 자동 생성됩니다.
- 정책 복원 미리보기(`npm run policy:preview`)는 별도 신뢰 SHA-256으로 검증된 안전 정책 사본과 현재 시험 정책의 변경 경로·종류만 읽기 전용으로 보여 줍니다. 사본 누락·검증 실패·시험 정책 누락 시 중단하며 운영 정책을 수정하지 않습니다.
- 시험 정책 복원(`npm run policy:restore`)은 먼저 `planSha256`, 복원 버전, 변경 범위를 보여 줍니다. `--confirm <planSha256>`를 다시 전달하면 복원 직전에 안전 사본·별도 신뢰 다이제스트·현재 시험 정책을 디스크에서 다시 읽고 모두 재검증합니다. 사본이 없거나 검증에 실패하거나 처음 표시한 버전·해시·변경 범위와 달라지면 쓰기 전에 중단합니다. 확인된 경우에만 시험 정책의 `policy` 구역을 복원하고, `serviceRules`·`auditHistory` 등 나머지 최상위 항목은 그대로 보존합니다. 운영 정책에 쓰는 경로·API는 없습니다.
- 비공개 메모 사본 복원 서비스는 `POST /api/notes/restore`입니다. 인증된 시험 계정 B가 `{ "id": "<메모 UUID>", "ownerId": "<B 사용자 UUID>", "contentSha256": "<64자리 SHA-256>" }`만 보내면 서버가 비공개 `note_restore_copies` 사본의 ID·소유자·내용 해시를 모두 대조한 뒤 지정한 한 건만 `notes`에 복원 저장합니다. 다른 메모와 감사 기록은 조회·수정하지 않습니다. 사본 테이블 준비 SQL은 `supabase/stage-11-restore.sql`에 있습니다.
- 설치형 웹앱 설정은 `/manifest.webmanifest`이며 앱 이름·아이콘·오프라인 안내만 제공합니다. 설치 표시만으로 기기 승인을 끝내지 않습니다.
- `GET/POST /api/device/approval`은 로그인한 학생의 승인 상태를 서버 등록부에서 읽습니다. 첫 요청은 `pending` 등록만 만들고, 승인 버튼은 권한을 부여하지 않습니다. 서버는 브라우저 식별자를 발급하거나 저장하지 않고 요청 특성의 일방향 지문만 등록부에 저장합니다. 승인 상태와 보호 자료만 JSON으로 반환합니다.
- 11단계 자료 API는 서버 등록부의 `approved` 상태가 확인된 학생 기기에서만 기존 메모·공지 구역을 엽니다. 승인 전에는 화면과 서버 API 모두 보호 자료를 반환하지 않습니다. 등록부 준비 SQL은 `supabase/stage-11-device-approval.sql`이며, 실제 승인은 브라우저가 아닌 운영자가 서버에서 수행합니다.
- 로그인 세션은 페이지 메모리에서만 유지하며 브라우저 저장소에 세션·기기 식별자·승인 값을 쓰지 않습니다. 새로고침 후에는 다시 로그인하고 서버 승인 상태를 확인합니다.

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

3. 8단계 구역 분리 직접 점검:
   - A 자기 메모 읽기·수정: `allow`
   - B의 A 메모 읽기·수정: `deny` (`forbidden_resource`)
   - 학생 공지 수정: `deny` (`forbidden_resource`)
   - 학생 공지 읽기: `allow`
   - 기능 경로(`/notes/export`): `deny` (`unknown_route`)

4. 9단계 탐지 비교 시험:
   ```bash
   npm run detect:test
   ```
   - 정상 조회 30건·120건: `observe`
   - 같은 기기의 121건 이상 조회: `propose_revocation`, `burst_read`, 대상 1개
   - 다른 사용자 합산·10분 밖 조회: `observe`

## 다시 실행하고 직접 확인하기

로컬 시험 실행:
```bash
npm run fixture:7
npm run decider:test
npm run detect:test
npm run policy:preview -- <safe-snapshot.json> <trusted-sha256.txt> <test-policy.json>
npm run policy:restore -- <safe-snapshot.json> <trusted-sha256.txt> <test-policy.json>
# 위 출력의 planSha256과 변경 범위를 확인한 뒤에만 다음 명령을 실행합니다.
npm run policy:restore -- <safe-snapshot.json> <trusted-sha256.txt> <test-policy.json> --confirm <planSha256>
npm run test:r5
npm run test:package
npm run build -- --local
```

11단계 기기 승인 확인:
```bash
# 로그인 후 화면의 "기기 승인 요청"을 누르면 서버 등록부에 pending이 생깁니다.
# 승인 전: 보호 자료 없음. 운영자가 Supabase에서 status='approved'로 바꾼 뒤:
# 화면의 "상태 새로 확인"을 눌러야 기존 자료실이 열립니다.
```

`supabase/stage-11-device-approval.sql`을 먼저 적용한 뒤 승인 대기 행을 운영자가 확인합니다. 승인 버튼 자체는 `approved`로 바꾸지 않으며, 브라우저 저장소와 화면에는 기기 식별자를 저장·표시하지 않습니다. 오프라인에서는 승인 상태와 보호 자료를 표시하지 않습니다.

메모 사본 복원 직접 확인(시험 계정 B만 사용):
```bash
curl -X POST https://<배포주소>/api/notes/restore \
  -H "Authorization: Bearer <B의-인증-토큰>" \
  -H "Content-Type: application/json" \
  -d '{"id":"<메모 UUID>","ownerId":"<B 사용자 UUID>","contentSha256":"<64자리 SHA-256>"}'
```
성공 응답에는 복원한 한 건의 `id`, `ownerId`, `contentSha256`만 포함됩니다. A 소유 메모나 다른 소유자의 요청은 `403`, 사본의 세 값이 맞지 않으면 `409`로 거부됩니다.

## 복구 후 1~9단계 재시험 순서

아래 순서는 비공개 B 메모 사본 복구 직후, 같은 배포 주소에서 정상 요청과 금지 요청을 다시 확인하는 순서입니다. 이 README를 갱신하는 동안에는 실제 배포·A/B 계정·원본 API를 대상으로 한 종합 재시험을 실행하지 않았으므로, 아래 모든 상태는 `미실행`입니다. `npm run decider:test`와 `npm run detect:test`의 가상 출력은 이 종합 재시험 결과로 바꾸어 적지 않습니다.

먼저 `supabase/stage-11-restore.sql`을 Supabase SQL Editor에서 실행하고 B 소유의 비공개 사본 한 건을 준비합니다. 복원 응답의 `id`, `ownerId`, `contentSha256`가 사본의 세 값과 같은지 확인한 뒤 아래 순서를 시작합니다. 복원된 B 메모를 삭제하는 요청은 재시험에 포함하지 않습니다.

1. **1단계 공개 자료 확인** — 정상: 배포 주소의 화면과 공개 확인 경로가 열림. 금지: `/data.json` 또는 공개 화면에 비공개 B 메모의 본문·토큰·소유자 정보가 나타나지 않음. 상태: `미실행`.
2. **2단계 원본 자료 보호** — 정상: 앱의 서버 경유 자료 요청만 다음 단계로 사용. 금지: `originalApiUrl`을 브라우저나 공개 키로 직접 호출해 비공개 메모가 조회되지 않음. 상태: `미실행`.
3. **3단계 로그인·자료 API** — 정상: B 로그인 후 `GET /api/my/notes`가 성공하고 복구한 B 메모가 보임. 금지: 로그아웃 상태의 `GET /api/my/notes`가 `401 AUTH_REQUIRED`로 거부됨. 상태: `미실행`.
4. **4단계 소유자 분리** — 정상: B가 자기 메모를 `GET /api/notes/:id`로 조회함. 금지: A가 B의 복구 메모를 같은 경로로 조회·수정·삭제하려 하면 `403 FORBIDDEN`이고, 다른 메모·감사 기록은 변하지 않음. 상태: `미실행`.
5. **5단계 직접 원본 접근 차단** — 정상: 앱 API가 검증된 로그인 세션으로만 자료를 반환함. 금지: Supabase REST 원본 경로를 인증 없이 직접 호출하거나 브라우저에서 직접 읽으려 하면 비공개 자료가 반환되지 않음. 상태: `미실행`.
6. **6단계 기기 등록 판정** — 정상: 등록된 가상 기기의 정상 요청은 `allow`·`approved`. 금지: `deviceRegistered !== true` 요청은 `deny`·`device_not_registered`. 상태: `미실행`.
7. **7단계 복합 이상 판정** — 정상: 평소 네트워크의 정상 조회는 허용. 금지: 처음 보는 네트워크와 갑작스러운 다량 조회가 함께일 때 본인 확인 전에는 `step_up`·`step_up_required`; 지역 하나만 바꾼 요청은 단독 차단하지 않음. 상태: `미실행`.
8. **8단계 구역 분리** — 정상: A의 자기 메모 요청과 공지 읽기는 허용. 금지: B의 A 메모 요청, 학생의 공지 쓰기, `/notes/export` 같은 기능 경로와 쿼리 우회는 각각 `forbidden_resource` 또는 `unknown_route`로 거부. 상태: `미실행`.
9. **9단계 조회 폭주 탐지** — 정상: 같은 기기의 120건 이하, 서로 다른 사용자 합산, 10분 밖으로 분산된 조회는 `observe`. 금지·탐지: 같은 확인된 기기의 10분 내 121건 이상 GET만 `propose_revocation`·`burst_read`와 대상 한 건을 제안하며 실제 권한을 임의 변경하지 않음. 상태: `미실행`.

10. **10단계 정책·메모 복구** — 정상: 검증된 사본의 지정 자료만 복원되고 다른 자료·감사 기록은 보존됨. 금지: 검증 실패 사본이나 다른 소유자의 복원 요청은 쓰기 전에 중단·거부됨. 상태: `미실행`.
11. **11단계 기기 승인** — 정상: 서버 등록부에서 승인된 기기만 기존 자료실을 열고 메모 CRUD가 유지됨. 금지: 승인 전·회수된 기기는 보호 자료 없이 `DEVICE_NOT_APPROVED`로 거부됨. 설치 표시만으로 승인되었다고 간주하지 않음. 상태: `미실행`.

재시험을 실제로 마친 뒤에는 각 줄의 `미실행`만 실제 관찰값(`통과` 또는 `실패`, HTTP 상태와 핵심 reason code 포함)으로 바꾸고, 실행하지 않은 줄은 계속 `미실행`으로 둡니다.

배포 후 확인 항목:
1. 정상 등록 기기에서 기존 로그인 및 메모 CRUD가 정상 작동하는지 확인합니다.
2. 메뉴를 우회하여 다른 구역이나 타인 메모에 직접 API 요청 시 403으로 차단되는지 확인합니다.
3. 원본 자료 주소(`originalApiUrl`)를 공개 키로 직접 호출했을 때 메모 자료가 조회되지 않는지 확인합니다.
