const PATTERNS = Object.freeze([
  {
    name: '관리자 그룹 추가',
    condition: 'T1078 경보에서 administrators·관리자 그룹에 계정이 새로 추가되거나 다시 들어간 경우',
    basis: 'MITRE ATT&CK T1078(정상 계정 도용)에 근거해 정상 계정에 관리자 권한을 부여하는 신호를 확인합니다.',
  },
  {
    name: '처음 보는 관리자 명령',
    condition: 'T1068 경보에서 처음 보는 주소·낯선 세션·새로 상승한 권한과 함께 관리자 명령이 실행된 경우',
    basis: 'MITRE ATT&CK T1068(권한 상승 악용)에 근거해 낯선 경로의 관리자 권한 실행을 확인합니다.',
  },
  {
    name: '업무 시간 밖 권한 사용',
    condition: 'T1068 또는 T1078 경보에서 업무 시간 밖에 관리자 그룹 추가나 권한 명령이 발생한 경우',
    basis: 'MITRE ATT&CK T1068·T1078에 근거해 업무 시간 밖 권한 사용을 확인합니다.',
  },
]);

const text = (value) => typeof value === 'string' ? value : '';

/**
 * Wazuh 권한 경보를 순수 계산만으로 판단합니다.
 * 외부 모듈, 파일 I/O, 네트워크를 사용하지 않습니다.
 */
export function decide(alert) {
  if (!alert || typeof alert !== 'object') {
    return { action: 'record', confidence: 0, reason: '유효한 경보 데이터가 아닙니다' };
  }

  const data = alert.data && typeof alert.data === 'object' ? alert.data : {};
  const description = text(alert.rule?.description);
  const group = text(data.group);
  const level = typeof alert.rule?.level === 'number'
    ? alert.rule.level
    : Number(alert.rule?.level || 0);
  const mitre = Array.isArray(alert.rule?.mitre) ? alert.rule.mitre.map(String) : [];
  const hasT1068 = mitre.some((item) => item.toUpperCase().startsWith('T1068'));
  const hasT1078 = mitre.some((item) => item.toUpperCase().startsWith('T1078'));
  const hasPrivilegeTechnique = hasT1068 || hasT1078;
  const context = `${description} ${group}`;

  const administratorGroup = /administrators?|관리자\s*그룹|관리자로/i.test(context)
    && !/관리자\s*그룹은\s*아닙니다|관리자\s*그룹이\s*아닙니다/i.test(description)
    && /(?:추가|들어가|재(?:차|다시)?|다시|그룹에서.*관리자)/i.test(description);
  const unfamiliarAdminCommand = /(?:처음\s*보는|처음\s*본|낯선|방금\s*관리자가\s*된|다른\s*계정의\s*권한|요청\s*주소는\s*처음).*(?:관리자\s*명령|관리자\s*권한)|(?:관리자\s*명령|관리자\s*권한).*(?:처음\s*보는|처음\s*본|낯선|다른\s*계정|방금\s*관리자가|요청\s*주소는\s*처음)/i.test(context);
  const outsideHours = /수업\s*시간\s*밖|업무\s*(?:시간|때)\s*밖|업무처럼\s*보이지\s*않는|야간|비정상\s*시간/i.test(context);
  const outsideHoursPrivilege = outsideHours && /관리자|권한|명령/i.test(context);

  const matchedPattern = administratorGroup ? PATTERNS[0]
    : (unfamiliarAdminCommand ? PATTERNS[1]
      : (outsideHoursPrivilege ? PATTERNS[2] : null));
  const hasStrongSignal = Boolean(matchedPattern);

  if (hasStrongSignal && hasPrivilegeTechnique && level >= 10) {
    return {
      action: 'block',
      confidence: Math.min(0.98, 0.9 + Math.max(0, level - 10) * 0.02),
      reason: matchedPattern.name,
    };
  }

  if (hasPrivilegeTechnique && level >= 5) {
    const fallback = hasT1078 ? PATTERNS[0] : PATTERNS[1];
    return {
      action: 'alert',
      confidence: Math.min(0.8, 0.55 + Math.max(0, level - 5) * 0.05),
      reason: (matchedPattern || fallback).name,
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
