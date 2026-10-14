const PATTERNS = Object.freeze([
  {
    name: '서명 없는 새 서비스 등록',
    condition: 'T1543 경보에서 새 서비스 등록·서비스 실행 파일 변경과 서명 없음이 함께 보이는 경우',
    basis: 'MITRE ATT&CK T1543(시스템 프로세스 생성·변경)에 근거해 서명 없는 서비스 등록을 확인합니다.',
  },
  {
    name: '낯선 예약 작업 등록',
    condition: 'T1053 경보에서 처음 보는 예약 작업·임의 작업 이름·수업 시간 밖 실행 또는 임시 실행 파일 신호가 보이는 경우',
    basis: 'MITRE ATT&CK T1053(예약 작업)에 근거해 낯선 예약 작업 등록을 확인합니다.',
  },
  {
    name: '시작 폴더 변경',
    condition: 'T1543 경보에서 시작 폴더·시작 프로그램에 평소 목록에 없는 실행 항목이 추가되거나 변경된 경우',
    basis: 'MITRE ATT&CK T1543(시스템 프로세스 생성·변경)에 근거해 시작 폴더 변경을 확인합니다.',
  },
]);

const text = (value) => typeof value === 'string' ? value : '';

/**
 * Wazuh persistence 경보를 패턴과 대조합니다.
 * 외부 모듈, 파일 I/O, 네트워크 없이 입력만 계산합니다.
 * @param {Record<string, any>} alert
 * @returns {{ action: 'block' | 'alert' | 'record', confidence: number, reason: string }}
 */
export function decide(alert) {
  if (!alert || typeof alert !== 'object') {
    return { action: 'record', confidence: 0, reason: '유효한 경보 데이터가 아닙니다' };
  }

  const data = alert.data && typeof alert.data === 'object' ? alert.data : {};
  const description = text(alert.rule?.description);
  const path = text(data.path);
  const level = typeof alert.rule?.level === 'number'
    ? alert.rule.level
    : Number(alert.rule?.level || 0);
  const mitre = Array.isArray(alert.rule?.mitre) ? alert.rule.mitre.map(String) : [];
  const hasT1543 = mitre.some((item) => item.toUpperCase().startsWith('T1543'));
  const hasT1053 = mitre.some((item) => item.toUpperCase().startsWith('T1053'));
  const context = `${description} ${path}`;

  const unsignedService = hasT1543 && /서명\s*없는.*서비스|서비스.*서명(?:이\s*)?없|서비스\s*등록.*연속|평소\s*목록에\s*없는.*서비스|서비스가\s*다시\s*켜도\s*남도록/i.test(context);
  const unfamiliarTask = hasT1053 && /처음\s*보는\s*예약\s*작업|예약\s*작업.*임의|수업\s*시간\s*밖|예약\s*작업.*임시\s*폴더|같은\s*임시\s*파일/i.test(context);
  const startupChange = hasT1543 && /시작\s*(?:폴더|프로그램|항목).*?(?:추가|변경)|시작\s*폴더\s*변경/i.test(context);
  const matchedPattern = unsignedService ? PATTERNS[0]
    : (unfamiliarTask ? PATTERNS[1] : (startupChange ? PATTERNS[2] : null));
  const hasPersistenceSignal = Boolean(matchedPattern);
  const hasPersistenceTechnique = hasT1543 || hasT1053;

  if (matchedPattern && hasPersistenceTechnique && level >= 10) {
    return {
      action: 'block',
      confidence: Math.min(0.98, 0.9 + Math.max(0, level - 10) * 0.02),
      reason: matchedPattern.name,
    };
  }

  if (hasPersistenceTechnique && level >= 5 && (hasPersistenceSignal || description.length > 0)) {
    return {
      action: 'alert',
      confidence: Math.min(0.8, 0.55 + Math.max(0, level - 5) * 0.05),
      reason: matchedPattern ? matchedPattern.name
        : (hasT1053 ? PATTERNS[1].name : PATTERNS[0].name),
    };
  }

  return {
    action: 'record',
    confidence: 0.1,
    reason: `정상 이벤트 · ${PATTERNS[0].name}·${PATTERNS[1].name}·${PATTERNS[2].name} 미부합`,
  };
}

export { PATTERNS };
export default decide;
