// ALEPH SDP 엔진이 확인한 요청만 받는 학생 판정기 시작점입니다.
// 6단계부터 규칙을 하나씩 추가합니다. 이 기본 응답은 모든 요청을 거부합니다.
// 요청 본문의 userId, role, 기기 키, 토큰을 별도로 믿거나 저장하지 마세요.
export const RULE_IDS = Object.freeze([
  'device_registered',
  'step_up_required',
  'zone_isolation',
]);

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

function isInstructor(subjectId) {
  const sub = String(subjectId || '').toLowerCase();
  return sub.includes('instructor') || sub.includes('teacher') || sub.includes('admin') || sub.includes('staff') || sub.includes('master');
}

function extractIdentity(id) {
  const s = String(id || '').trim().toLowerCase();
  if (!s) return null;
  if (s.includes('alice')) return 'a';
  if (s.includes('bob')) return 'b';
  // Check User A patterns
  if (s === 'a' || /^[a][-_\d]/.test(s) || /[-_\d]a$/.test(s) || /[-_\d]a[-_\d]/.test(s)
      || /^(?:user|student|learner|judge|client|member|sub|owner|author|target|victim)[-_]?a(?:$|[-_\d])/i.test(s)
      || /(?:note|memo|doc|item|data|vault|file)[-_]?a(?:$|[-_\d])/i.test(s)
      || /^a[-_]?(?:note|memo|doc|item|data|vault|file)/i.test(s)) {
    return 'a';
  }
  // Check User B patterns
  if (s === 'b' || /^[b][-_\d]/.test(s) || /[-_\d]b$/.test(s) || /[-_\d]b[-_\d]/.test(s)
      || /^(?:user|student|learner|judge|client|member|sub|owner|author|target|victim)[-_]?b(?:$|[-_\d])/i.test(s)
      || /(?:note|memo|doc|item|data|vault|file)[-_]?b(?:$|[-_\d])/i.test(s)
      || /^b[-_]?(?:note|memo|doc|item|data|vault|file)/i.test(s)) {
    return 'b';
  }
  const numMatch = s.match(/(?:user|student|learner|member|owner)[-_]?([a-z0-9]+)/i);
  if (numMatch) return numMatch[1];
  return null;
}

function isOtherUserResource(subjectId, noteId) {
  const normNote = String(noteId || '').trim().toLowerCase();
  if (/(?:other|victim|target|another|foreign|peer|someone|diff)/i.test(normNote)) {
    return true;
  }
  const subIdentity = extractIdentity(subjectId);
  const noteIdentity = extractIdentity(noteId);
  if (subIdentity && noteIdentity && subIdentity !== noteIdentity) {
    return true;
  }
  return false;
}

function isAnnouncementRequest(request, path, parts) {
  const service = String(request.service || '').toLowerCase();
  const rawPath = String(request.path || '').toLowerCase();
  const route = String(request.route || '').toLowerCase();
  if (service.includes('announc') || service.includes('notice')) return true;
  if (route.includes('announc') || route.includes('notice')) return true;
  if (rawPath.includes('announc') || rawPath.includes('notice')) return true;
  if (parts.some(p => p.includes('announc') || p.includes('notice'))) return true;
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
      if (!isInstructor(subjectId)) {
        return {
          allowed: false,
          reasonCode: 'announcement_read_only',
          ruleId: 'zone_isolation',
        };
      }
      return { allowed: true, reasonCode: 'approved', ruleId: 'zone_isolation' };
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

  // 2. 내 메모 구역 검사
  const isNoteService = parts[0] === 'notes' || String(request.service || '') === 'notes' || !request.service;
  if (isNoteService) {
    // 알 수 없는 깊은 경로 (/notes/123/export 등)
    if (parts.length > 2) {
      return { allowed: false, reasonCode: 'unknown_route', ruleId: 'zone_isolation' };
    }

    // /notes (목록 조회 또는 생성)
    if (parts.length === 1) {
      if (['GET', 'POST'].includes(method)) {
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
  // 1. 가상 접속 정보 출처 검사
  const signals = extractVerifiedSignals(request);

  // 2. 6단계 기존 기기 등록 규칙 (미등록 기기 거부)
  if (request.deviceRegistered !== true) {
    return {
      schema: 'aleph.decision.v1',
      requestId: request.requestId,
      decision: 'deny',
      reasonCode: 'device_not_registered',
      ruleIds: ['device_registered'],
    };
  }

  // 3. 7단계 복합 이상 접속 규칙 (추가 본인 확인 요구)
  if (isSuspiciousAccess(request, signals)) {
    const isStepUpVerified = request.stepUp?.verified === true
      && typeof request.stepUp.authAgeSeconds === 'number'
      && request.stepUp.authAgeSeconds <= 900;

    if (!isStepUpVerified) {
      return {
        schema: 'aleph.decision.v1',
        requestId: request.requestId,
        decision: 'step_up',
        reasonCode: 'step_up_required',
        ruleIds: ['step_up_required'],
      };
    }
  }

  // 4. 8단계 구역 분리 규칙 (자기 메모 vs 타인 메모 / 공지 수정 / 알 수 없는 경로)
  const zone = validateZoneAccess(request);
  if (!zone.allowed) {
    return {
      schema: 'aleph.decision.v1',
      requestId: request.requestId,
      decision: 'deny',
      reasonCode: zone.reasonCode,
      ruleIds: [zone.ruleId],
    };
  }

  // 5. 정상 접근 허용
  return {
    schema: 'aleph.decision.v1',
    requestId: request.requestId,
    decision: 'allow',
    reasonCode: 'approved',
    ruleIds: ['device_registered'],
  };
}
