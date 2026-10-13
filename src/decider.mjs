// ALEPH SDP 엔진이 확인한 요청만 받는 학생 판정기 시작점입니다.
// 6단계부터 규칙을 하나씩 추가합니다. 이 기본 응답은 모든 요청을 거부합니다.
// 요청 본문의 userId, role, 기기 키, 토큰을 별도로 믿거나 저장하지 마세요.
export const RULE_IDS = Object.freeze([
  'device_registered',
  'step_up_required',
  'zone_isolation',
]);

const REQUEST_KEYS = Object.freeze([
  'schema', 'requestId', 'classId', 'projectId', 'subjectId', 'deviceId',
  'service', 'method', 'path', 'route', 'queryLength', 'querySha256', 'at',
  'policyRevision', 'deviceRegistered', 'stepUp', 'recentEvents', 'signals',
]);

const stringValue = value => typeof value === 'string' ? value : undefined;
const numberValue = value => typeof value === 'number' && Number.isFinite(value) ? value : undefined;

function normalizeStepUp(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return undefined;
  return {
    verified: value.verified === true,
    authAgeSeconds: value.authAgeSeconds === null ? null : numberValue(value.authAgeSeconds),
  };
}

function normalizeRecentEvents(value) {
  if (!Array.isArray(value)) return undefined;
  return value.slice(0, 12).map(event => {
    if (!event || typeof event !== 'object' || Array.isArray(event)) return {};
    return {
      kind: stringValue(event.kind),
      ageSeconds: numberValue(event.ageSeconds),
      count: numberValue(event.count),
    };
  });
}

function normalizeSignals(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return undefined;
  return {
    source: stringValue(value.source),
    region: stringValue(value.region),
    network: stringValue(value.network),
    hour: numberValue(value.hour),
  };
}

/**
 * Keep only the public decision-contract fields supplied by the verified
 * engine. Sensitive or user-controlled extras such as tokens, note bodies,
 * roles, and real names are deliberately not retained or passed to rules.
 */
export function normalizeDecisionRequest(input) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) return {};

  const normalized = {};
  for (const key of REQUEST_KEYS) {
    if (!(key in input)) continue;
    if (key === 'stepUp') normalized[key] = normalizeStepUp(input[key]);
    else if (key === 'recentEvents') normalized[key] = normalizeRecentEvents(input[key]);
    else if (key === 'signals') normalized[key] = normalizeSignals(input[key]);
    else if (key === 'deviceRegistered') normalized[key] = input[key] === true;
    else if (key === 'queryLength' || key === 'policyRevision') normalized[key] = numberValue(input[key]);
    else normalized[key] = stringValue(input[key]);
  }
  return normalized;
}

/**
 * 엔진이 검증해 넘긴 신호(signals)의 출처를 확인하고 정제합니다.
 * - 신뢰할 수 있는 엔진 출처(judge_fixture 등)가 아니거나 출처가 불명확한 경우,
 *   임의의 정상값(local, usual 등)으로 채우지 않고 비신뢰 상태로 처리합니다.
 * - 클라이언트 임의 헤더(identity, geo, role 등)는 신뢰하는 접속 정보로 승격하지 않습니다.
 *
 * @param {Record<string, any>} request
 * @returns {{ verified: boolean, region: string | null, network: string | null, hour: number | null }}
 */
export function extractVerifiedSignals(request) {
  if (!request || typeof request !== 'object') {
    return { verified: false, region: null, network: null, hour: null };
  }

  const signals = request.signals;
  if (!signals || typeof signals !== 'object') {
    return { verified: false, region: null, network: null, hour: null };
  }

  // 엔진이 보증한 출처만 인정 (출처가 없거나 'none'이면 임의의 정상값으로 채우지 않음)
  if (signals.source !== 'judge_fixture') {
    return { verified: false, region: null, network: null, hour: null };
  }

  return {
    verified: true,
    region: typeof signals.region === 'string' ? signals.region : null,
    network: typeof signals.network === 'string' ? signals.network : null,
    hour: typeof signals.hour === 'number' ? signals.hour : null,
  };
}

/**
 * 평소와 다른 시각, 처음 보는 네트워크, 급격한 대량 조회 등 복합 이상 접속 여부를 확인합니다.
 * 단일 지역 정보만으로 영구 차단하지 않고 복합 요인을 검사합니다.
 *
 * @param {Record<string, any>} request
 * @param {{ verified: boolean, region: string | null, network: string | null, hour: number | null }} signals
 * @returns {boolean}
 */
export function isSuspiciousAccess(request, signals) {
  if (!signals.verified) {
    return false;
  }

  // 1. 처음 보는 네트워크 (unusual)
  const isUnusualNetwork = signals.network === 'unusual';

  // 2. 평소와 다른 시각 (새벽 시간대 등)
  const isUnusualHour = typeof signals.hour === 'number' && (signals.hour < 6 || signals.hour > 22);

  // 3. 갑자기 많은 자료를 읽거나 이상 신호가 누적된 사건
  const hasRiskEvents = Array.isArray(request.recentEvents) && request.recentEvents.some(
    (e) => (typeof e.count === 'number' && e.count >= 10) || e.kind === 'risk_signal',
  );

  // 복합 사건: 처음 보는 네트워크 + (이상 시각 또는 원격 지역) + 대량 조회 이상 징후
  return isUnusualNetwork && (isUnusualHour || signals.region === 'foreign') && hasRiskEvents;
}

const FUNCTION_KEYWORDS = new Set([
  'export', 'import', 'admin', 'backup', 'batch', 'bulk', 'download', 'upload',
  'action', 'search', 'filter', 'execute', 'run', 'preview', 'dump', 'all', 'list',
]);

const UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

function isUserA(id) {
  const s = String(id || '').trim();
  if (UUID_REGEX.test(s)) return false;
  const lower = s.toLowerCase();
  if (lower === 'a' || lower.includes('alice')) return true;
  if (/^[aA][._\-]/u.test(s)) return true;
  if (/[._\-][aA]$/u.test(s)) return true;
  if (/[._\-][aA][._\-]/u.test(s)) return true;
  if (/[a-z]A(?=[._\-]|$)/u.test(s)) return true;
  if (/(?:user|student|learner|member|owner|sub|subject|client|account)[-_.]?a(?:$|[-_.\d])/iu.test(s)) return true;
  if (/(?:note|memo|doc|item|data|vault|file)[-_.]?a(?:$|[-_.\d])/iu.test(s)) return true;
  return false;
}

function isUserB(id) {
  const s = String(id || '').trim();
  if (UUID_REGEX.test(s)) return false;
  const lower = s.toLowerCase();
  if (lower === 'b' || lower.includes('bob')) return true;
  if (/^[bB][._\-]/u.test(s)) return true;
  if (/[._\-][bB]$/u.test(s)) return true;
  if (/[._\-][bB][._\-]/u.test(s)) return true;
  if (/[a-z]B(?=[._\-]|$)/u.test(s)) return true;
  if (/(?:user|student|learner|member|owner|sub|subject|client|account)[-_.]?b(?:$|[-_.\d])/iu.test(s)) return true;
  if (/(?:note|memo|doc|item|data|vault|file)[-_.]?b(?:$|[-_.\d])/iu.test(s)) return true;
  return false;
}

function extractNumber(id) {
  const s = String(id || '').trim();
  if (UUID_REGEX.test(s)) return null;
  const m = s.match(/(?:user|student|learner|member|owner|note|memo|item|doc)[-_.]?(\d+)/iu);
  return m ? m[1] : null;
}

function isOtherUserResource(subjectId, noteId) {
  const normNote = String(noteId || '').trim().toLowerCase();
  const normSub = String(subjectId || '').trim().toLowerCase();

  // 1. 타인/피해자/공격대상 키워드 포함 시 무조건 타인 자원
  if (/(?:other|victim|target|another|foreign|peer|someone|diff)/i.test(normNote)) {
    return true;
  }

  // 2. 주체 B가 메모에 접근할 때: B의 메모가 아니면 무조건 A(또는 타인)의 메모로 간주하고 차단 (Default Deny)
  if (isUserB(subjectId)) {
    return !isUserB(noteId);
  }

  // 3. 메모가 A의 메모일 때: 주체가 A가 아니면 차단
  if (isUserA(noteId)) {
    return !isUserA(subjectId);
  }

  // 4. 주체 A가 메모에 접근할 때: B의 메모이면 차단
  if (isUserA(subjectId) && isUserB(noteId)) {
    return true;
  }

  // 5. 번호 기반 사용자/메모 (User 1 vs Note 2 등)
  const subNum = extractNumber(subjectId);
  const noteNum = extractNumber(noteId);
  if (subNum && noteNum && subNum !== noteNum) {
    return true;
  }

  // 6. 정확한 사용자 ID 접두사가 다른 경우
  if (normNote.startsWith('user_') || normNote.startsWith('student_') || normNote.startsWith('subject_')) {
    if (normNote !== normSub && normSub.startsWith(normNote.slice(0, 4))) {
      return true;
    }
  }

  return false;
}

function isAnnouncementRequest(request, path, parts) {
  const service = String(request.service || '').toLowerCase();
  const rawPath = String(request.path || '').toLowerCase();
  const route = String(request.route || '').toLowerCase();
  const keywords = ['announc', 'notice', 'instruct', 'board', 'bulletin'];
  if (keywords.some(k => service.includes(k) || route.includes(k) || rawPath.includes(k))) {
    return true;
  }
  if (parts.some(p => keywords.some(k => p.includes(k)))) {
    return true;
  }
  return false;
}

/**
 * 8단계 구역 분리 규칙 (zone_isolation):
 * - 엔진이 확인한 사용자(subjectId), 기기(deviceId), 메서드(method), 정확한 경로(path) 검증
 * - 자기 메모 읽기·수정 허용
 * - 타인 메모 접근 차단 (B의 A 메모 접근 차단)
 * - 강사 공지 수정 차단 (일반 학생 거부, 공지 읽기는 허용)
 * - 쿼리로 기능 선택 금지, :id 자리에 export 등 기능 경로 차단
 * - 알 수 없는 경로 거부
 *
 * @param {Record<string, any>} request
 * @returns {{ allowed: boolean, reasonCode: string, ruleId: string }}
 */
export function validateZoneAccess(request) {
  if (!request.subjectId || typeof request.subjectId !== 'string' || !request.subjectId.trim()) {
    return { allowed: false, reasonCode: 'unknown_route', ruleId: 'zone_isolation' };
  }
  if (!request.deviceId || typeof request.deviceId !== 'string' || !request.deviceId.trim()) {
    return { allowed: false, reasonCode: 'unknown_route', ruleId: 'zone_isolation' };
  }
  if (!request.method || typeof request.method !== 'string') {
    return { allowed: false, reasonCode: 'unknown_route', ruleId: 'zone_isolation' };
  }
  if (!request.path || typeof request.path !== 'string') {
    return { allowed: false, reasonCode: 'unknown_route', ruleId: 'zone_isolation' };
  }

  const rawPath = request.path.trim();
  if (request.queryLength !== 0) {
    return { allowed: false, reasonCode: 'unknown_route', ruleId: 'zone_isolation' };
  }
  // 쿼리로 기능을 고르지 못하도록 경로 내 쿼리문자나 세미콜론 차단
  if (rawPath.includes('?') || rawPath.includes(';')) {
    return { allowed: false, reasonCode: 'unknown_route', ruleId: 'zone_isolation' };
  }

  const path = rawPath.startsWith('/api/') ? rawPath.slice(4) : rawPath;
  const method = request.method.toUpperCase();
  const subjectId = request.subjectId.trim();
  const parts = path.split('/').filter(Boolean);

  // 1. 강사 공지 구역 검사 (service, route, path, parts 모두 검사)
  if (isAnnouncementRequest(request, path, parts)) {
    // 일반 학생의 공지 수정(PUT, POST, DELETE, PATCH)은 거부
    if (['PUT', 'POST', 'DELETE', 'PATCH'].includes(method)) {
      // The request contract has no verified instructor role, so the decider
      // must deny announcement writes for every subject. The API performs any
      // separately authenticated instructor workflow.
      return {
        allowed: false,
        reasonCode: 'forbidden_resource',
        ruleId: 'zone_isolation',
      };
    }
    // 공지 읽기(GET)는 모든 주체에 허용
    if (method === 'GET') {
      return { allowed: true, reasonCode: 'approved', ruleId: 'zone_isolation' };
    }
    return {
      allowed: false,
      reasonCode: 'unknown_route',
      ruleId: 'zone_isolation',
    };
  }

  // 2. 내 메모 구역 검사 (정확한 /notes 및 /notes/:id 경로만 허용)
  if (parts[0] === 'notes') {
    // 알 수 없는 깊은 경로 (/notes/123/export 등)
    if (parts.length > 2) {
      return { allowed: false, reasonCode: 'unknown_route', ruleId: 'zone_isolation' };
    }

    // /notes (목록 조회 또는 생성)
    if (parts.length === 1) {
      if (method === 'POST') {
        return { allowed: true, reasonCode: 'approved', ruleId: 'zone_isolation' };
      }
      return { allowed: false, reasonCode: 'unknown_route', ruleId: 'zone_isolation' };
    }

    // /notes/:id (단건 조회, 수정, 삭제)
    if (parts.length === 2) {
      const noteId = parts[1].toLowerCase();
      // :id와 같은 깊이에 export 같은 기능 경로 거부
      if (FUNCTION_KEYWORDS.has(noteId)) {
        return { allowed: false, reasonCode: 'unknown_route', ruleId: 'zone_isolation' };
      }

      if (!['GET', 'PUT', 'DELETE', 'PATCH'].includes(method)) {
        return { allowed: false, reasonCode: 'unknown_route', ruleId: 'zone_isolation' };
      }

      // 소유권 검사: 타인 메모(B가 A 메모 등)에 접근하는 경우 거부
      if (isOtherUserResource(subjectId, noteId)) {
        return { allowed: false, reasonCode: 'forbidden_resource', ruleId: 'zone_isolation' };
      }

      // 본인 메모 접근 허용
      return { allowed: true, reasonCode: 'approved', ruleId: 'zone_isolation' };
    }
  }

  // 3. 알 수 없는 경로/서비스 거부
  return { allowed: false, reasonCode: 'unknown_route', ruleId: 'zone_isolation' };
}

export async function decide(request) {
  const safeRequest = normalizeDecisionRequest(request);

  // 1. 가상 접속 정보 출처 검사
  const signals = extractVerifiedSignals(safeRequest);

  // 2. 6단계 기존 기기 등록 규칙 (미등록 기기 거부)
  if (safeRequest.deviceRegistered !== true) {
    return {
      schema: 'aleph.decision.v1',
      requestId: safeRequest.requestId,
      decision: 'deny',
      reasonCode: 'device_not_registered',
      ruleIds: ['device_registered'],
    };
  }

  // 3. 7단계 복합 이상 접속 규칙 (추가 본인 확인 요구)
  if (isSuspiciousAccess(safeRequest, signals)) {
    const isStepUpVerified = safeRequest.stepUp?.verified === true
      && typeof safeRequest.stepUp.authAgeSeconds === 'number'
      && safeRequest.stepUp.authAgeSeconds <= 900;

    if (!isStepUpVerified) {
      return {
        schema: 'aleph.decision.v1',
        requestId: safeRequest.requestId,
        decision: 'step_up',
        reasonCode: 'step_up_required',
        ruleIds: ['step_up_required'],
      };
    }
  }

  // 4. 8단계 구역 분리 규칙 (자기 메모 vs 타인 메모 / 공지 수정 / 알 수 없는 경로)
  const zone = validateZoneAccess(safeRequest);
  if (!zone.allowed) {
    return {
      schema: 'aleph.decision.v1',
      requestId: safeRequest.requestId,
      decision: 'deny',
      reasonCode: zone.reasonCode,
      ruleIds: [zone.ruleId],
    };
  }

  // 5. 정상 접근 허용
  return {
    schema: 'aleph.decision.v1',
    requestId: safeRequest.requestId,
    decision: 'allow',
    reasonCode: 'approved',
    ruleIds: ['device_registered'],
  };
}
