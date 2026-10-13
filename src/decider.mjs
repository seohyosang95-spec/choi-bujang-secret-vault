// ALEPH SDP 엔진이 확인한 요청만 받는 학생 판정기 시작점입니다.
// 6단계부터 규칙을 하나씩 추가합니다. 이 기본 응답은 모든 요청을 거부합니다.
// 요청 본문의 userId, role, 기기 키, 토큰을 별도로 믿거나 저장하지 마세요.
export const RULE_IDS = Object.freeze([
  'device_registered',
  'step_up_required',
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

  // 4. 정상 접근 허용
  return {
    schema: 'aleph.decision.v1',
    requestId: request.requestId,
    decision: 'allow',
    reasonCode: 'approved',
    ruleIds: ['device_registered'],
  };
}
