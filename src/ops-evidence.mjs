import { RULE_IDS } from './decider.mjs';

const OPS_SCHEMA = 'aleph.ops-room.v1';

/**
 * The catalog is intentionally a procedure, not a fabricated result set.
 * Every row starts as unexecuted and is populated only by a real response
 * collected by the operation-room page.
 */
export const OPS_TEST_CATALOG = Object.freeze([
  { id: 's01-normal-home', stage: 1, kind: '정상', expected: '공개 화면이 열림' },
  { id: 's01-forbidden-public-note', stage: 1, kind: '금지', expected: '공개 경로에 비공개 자료가 없음' },
  { id: 's01-forbidden-secret', stage: 1, kind: '금지', expected: '화면에 비밀값이 없음' },
  { id: 's01-normal-manifest', stage: 1, kind: '정상', expected: '설치 설정과 오프라인 안내가 표시됨' },
  { id: 's02-normal-proxy', stage: 2, kind: '정상', expected: '앱의 서버 경유 요청만 자료 경계에 도달함' },
  { id: 's02-forbidden-direct-original', stage: 2, kind: '금지', expected: '원본 자료 API 직접 접근이 차단됨' },
  { id: 's02-forbidden-public-api', stage: 2, kind: '금지', expected: '비로그인 자료 API가 거부됨', probe: 'anonymous-notes' },
  { id: 's03-normal-login', stage: 3, kind: '정상', expected: '인증된 세션으로 로그인됨' },
  { id: 's03-normal-my-notes', stage: 3, kind: '정상', expected: '내 자료 목록 요청이 허용됨', probe: 'authenticated-notes' },
  { id: 's03-forbidden-logout-notes', stage: 3, kind: '금지', expected: '로그아웃 자료 요청이 401 또는 403임', probe: 'anonymous-notes' },
  { id: 's03-forbidden-invalid-login', stage: 3, kind: '금지', expected: '잘못된 로그인 요청이 거부됨' },
  { id: 's04-normal-own-note', stage: 4, kind: '정상', expected: '본인 메모 단건 조회가 허용됨' },
  { id: 's04-forbidden-other-note', stage: 4, kind: '금지', expected: '타인 메모 조회가 403임' },
  { id: 's04-forbidden-other-update', stage: 4, kind: '금지', expected: '타인 메모 수정이 403임' },
  { id: 's04-normal-audit', stage: 4, kind: '정상', expected: '다른 자료와 감사 기록이 보존됨' },
  { id: 's05-normal-server-proxy', stage: 5, kind: '정상', expected: '서버 경유 자료 요청만 사용됨' },
  { id: 's05-forbidden-direct-rest', stage: 5, kind: '금지', expected: '원본 REST 직접 접근이 차단됨' },
  { id: 's05-forbidden-public-key', stage: 5, kind: '금지', expected: '브라우저에 비밀 키가 없음' },
  { id: 's05-forbidden-service-key', stage: 5, kind: '금지', expected: '서비스 키가 제출물에 없음' },
  { id: 's06-normal-registered', stage: 6, kind: '정상', expected: '등록 기기의 정상 요청이 허용됨' },
  { id: 's06-forbidden-unregistered', stage: 6, kind: '금지', expected: '미등록 기기가 거부됨' },
  { id: 's06-forbidden-device-spoof', stage: 6, kind: '금지', expected: '클라이언트 기기 값만으로 승인되지 않음' },
  { id: 's07-normal-usual-network', stage: 7, kind: '정상', expected: '평소 네트워크의 정상 요청이 허용됨' },
  { id: 's07-forbidden-composite', stage: 7, kind: '금지', expected: '이상 네트워크와 폭주가 함께면 step-up임' },
  { id: 's07-normal-region-only', stage: 7, kind: '정상', expected: '지역 하나만 바뀐 요청은 단독 차단되지 않음' },
  { id: 's08-normal-own-zone', stage: 8, kind: '정상', expected: '자기 자료 구역 요청이 허용됨' },
  { id: 's08-forbidden-other-zone', stage: 8, kind: '금지', expected: '타인 자료 구역 요청이 거부됨' },
  { id: 's08-forbidden-announcement-write', stage: 8, kind: '금지', expected: '학생의 공지 쓰기가 거부됨' },
  { id: 's08-forbidden-export-route', stage: 8, kind: '금지', expected: 'export 기능 경로가 거부됨' },
  { id: 's09-normal-under-threshold', stage: 9, kind: '정상', expected: '120건 이하 조회는 observe임' },
  { id: 's09-forbidden-burst', stage: 9, kind: '금지', expected: '121건 이상은 회수 제안임' },
  { id: 's09-normal-cross-user', stage: 9, kind: '정상', expected: '다른 사용자 합산은 탐지하지 않음' },
  { id: 's10-normal-policy-preview', stage: 10, kind: '정상', expected: '검증된 사본의 변경 범위만 미리 표시됨' },
  { id: 's10-forbidden-unverified-restore', stage: 10, kind: '금지', expected: '검증 실패 복원이 쓰기 전에 중단됨' },
  { id: 's10-normal-note-restore', stage: 10, kind: '정상', expected: '지정한 한 건만 복원됨' },
  { id: 's10-forbidden-other-owner', stage: 10, kind: '금지', expected: '다른 소유자의 복원이 거부됨' },
  { id: 's10-normal-audit-preserved', stage: 10, kind: '정상', expected: '감사 기록이 보존됨' },
  { id: 's11-normal-approved-device', stage: 11, kind: '정상', expected: '승인된 기기에서 자료실이 열림' },
  { id: 's11-forbidden-pending-device', stage: 11, kind: '금지', expected: '승인 전 보호 자료가 차단됨' },
  { id: 's11-forbidden-key-storage', stage: 11, kind: '금지', expected: '브라우저 저장소에 기기 키가 없음' },
  { id: 's11-normal-offline-guidance', stage: 11, kind: '정상', expected: '오프라인 안내가 표시됨' },
]);

const RULE_LABELS = Object.freeze({
  device_registered: '등록 기기 확인',
  step_up_required: '복합 이상 접속 추가 확인',
  zone_isolation: '구역 분리',
});

export function maskedServerRecord(record) {
  if (!record || typeof record !== 'object') return null;
  return {
    requestId: typeof record.requestId === 'string' ? `${record.requestId.slice(0, 8)}…` : null,
    checkedAt: typeof record.checkedAt === 'string' ? record.checkedAt : null,
    httpStatus: Number.isInteger(record.httpStatus) ? record.httpStatus : null,
    result: typeof record.result === 'string' ? record.result : null,
  };
}

export function summarizeOpsEvidence(evidence = []) {
  const byId = new Map();
  for (const item of Array.isArray(evidence) ? evidence : []) {
    if (!item || typeof item !== 'object' || typeof item.id !== 'string') continue;
    byId.set(item.id, maskedServerRecord(item));
  }
  const checks = OPS_TEST_CATALOG.map(test => ({
    ...test,
    actual: byId.get(test.id) ?? null,
    status: byId.has(test.id) ? '실측' : '미실행',
  }));
  const executed = checks.filter(item => item.actual);
  const passed = executed.filter(item => item.actual.result?.startsWith('통과')).length;
  return {
    total: checks.length,
    executed: executed.length,
    passed,
    failed: executed.length - passed,
    unexecuted: checks.length - executed.length,
    checks,
  };
}

export function createOpsSummary({ restoreRoute = null, evidence = [] } = {}) {
  const checkSummary = summarizeOpsEvidence(evidence);
  const counts = {
    total: checkSummary.total,
    executed: checkSummary.executed,
    passed: checkSummary.passed,
    failed: checkSummary.failed,
    unexecuted: checkSummary.unexecuted,
  };
  const serverRecord = {
    counts,
    checks: checkSummary.checks
      .filter(item => item.actual)
      .map(item => ({ id: item.id, ...item.actual })),
  };
  return {
    schema: OPS_SCHEMA,
    source: {
      engine: 'ALEPH SDP 엔진',
      student: ['src/decider.mjs', 'src/detect.mjs', 'src/ops-evidence.mjs'],
      note: '가상 사건 연습과 실제 API 응답을 구분합니다.',
    },
    rules: {
      count: RULE_IDS.length,
      items: RULE_IDS.map(id => ({ id, label: RULE_LABELS[id] ?? '학생 규칙' })),
    },
    detection: {
      status: '미실행',
      eventCount: null,
      action: null,
      reasonCode: null,
      serverRecord: null,
    },
    revocation: {
      status: '미실행',
      proposalCount: null,
      target: '가림',
    },
    recovery: {
      status: '미실행',
      verifiedVersion: null,
      restoreRoute,
      changedScope: null,
    },
    counts,
    serverRecord,
    checks: checkSummary.checks,
  };
}

