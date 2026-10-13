# BYTE BACK 방어전 8단계 저장점

이 저장소는 자료마다 갈 수 있는 구역을 분리(마이크로세그멘테이션)하여, 내 자료실 메모와 강사 공지 자원을 구분하고 자기 메모 읽기·수정 허용, 타인 메모 접근 및 일반 학생의 공지 수정 차단, 기능 경로 및 우회 직접 요청 거부를 적용한 8단계 상태입니다.

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
    - 일반 학생의 강사 공지 수정: `decision: 'deny'`, `reasonCode: 'announcement_read_only'`
    - 일반 학생의 강사 공지 읽기: `decision: 'allow'`, `reasonCode: 'approved'`
    - `:id` 깊이의 기능 경로(`/notes/export` 등): `decision: 'deny'`, `reasonCode: 'unknown_route'`
    - 알 수 없는 경로 및 쿼리 우회 경로: `decision: 'deny'`, `reasonCode: 'unknown_route'`
- `aleph.config.json`에 원본 자료 API의 HTTPS 주소(`originalApiUrl`) 및 step 8이 등록되어 있습니다.
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

3. 8단계 구역 분리 직접 점검:
   - A 자기 메모 읽기·수정: `allow`
   - B의 A 메모 읽기·수정: `deny` (`forbidden_resource`)
   - 학생 공지 수정: `deny` (`announcement_read_only`)
   - 학생 공지 읽기: `allow`
   - 기능 경로(`/notes/export`): `deny` (`unknown_route`)

## 다시 실행하고 직접 확인하기

로컬 시험 실행:
```bash
npm run fixture:7
npm run decider:test
npm run test:r5
npm run test:package
npm run build -- --local
```

배포 후 확인 항목:
1. 정상 등록 기기에서 기존 로그인 및 메모 CRUD가 정상 작동하는지 확인합니다.
2. 메뉴를 우회하여 다른 구역이나 타인 메모에 직접 API 요청 시 403으로 차단되는지 확인합니다.
3. 원본 자료 주소(`originalApiUrl`)를 공개 키로 직접 호출했을 때 메모 자료가 조회되지 않는지 확인합니다.
