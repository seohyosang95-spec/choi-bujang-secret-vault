const PATTERNS = Object.freeze([
  {
    name: 'CVE-2021-44228 원격 조회 구문',
    condition: '요청 머리글 또는 요청 인자에 ${jndi:ldap|rmi|dns:...} 형태의 원격 조회 구문이 있어 CVE-2021-44228 형태 요청 신호가 확인되는 경우',
    basis: 'CVE-2021-44228 형태 요청에서 머리글·인자 안의 원격 조회 구문(jndi 형태)을 확인합니다.',
  },
  {
    name: 'MITRE ATT&CK T1190 공개 서비스 악용',
    condition: 'Wazuh rule.mitre에 T1190이 있고 규칙 수준이 5 이상인 알려진 취약점·공개 서비스 요청인 경우',
    basis: 'MITRE ATT&CK T1190(Exploit Public-Facing Application)에 근거해 공개 서비스 악용 신호를 분류합니다.',
  },
  {
    name: '알려진 취약점 점검 도구 흔적',
    condition: '경보 설명 또는 요청 경로에 취약점 점검·점검 도구·class-check 같은 알려진 점검 도구 흔적이 있는 경우',
    basis: 'CVE-2021-44228 형태를 찾는 알려진 취약점 점검 도구의 흔적을 보조 신호로 사용합니다.',
  },
]);

const text = (value) => typeof value === 'string' ? value : '';

/**
 * Wazuh 경보를 알려진 CVE 패턴과 대조합니다.
 * 외부 상태 없이 입력만 계산합니다.
 * @param {Record<string, any>} alert
 * @returns {{ action: 'block' | 'alert' | 'record', confidence: number, reason: string }}
 */
export function decide(alert) {
  if (!alert || typeof alert !== 'object') {
    return { action: 'record', confidence: 0, reason: '유효한 경보 데이터가 아닙니다' };
  }

  const data = alert.data && typeof alert.data === 'object' ? alert.data : {};
  const description = text(alert.rule?.description);
  const requestText = [data.useragent, data.url, data.query, data.args, data.request]
    .map(text)
    .filter(Boolean)
    .join(' ');
  const level = typeof alert.rule?.level === 'number'
    ? alert.rule.level
    : Number(alert.rule?.level || 0);
  const mitre = Array.isArray(alert.rule?.mitre) ? alert.rule.mitre.map(String) : [];
  const hasT1190 = mitre.some((item) => item.toUpperCase().startsWith('T1190'));
  const hasRemoteLookup = /\$\{[^{}\r\n]*jndi\s*:\s*(?:ldap|rmi|dns)\s*:/i.test(requestText);
  const hasCveSignal = /CVE-2021-44228/i.test(description)
    || /CVE-2021-44228/i.test(requestText)
    || hasRemoteLookup;
  const hasScannerTrace = /취약점\s*점검|점검\s*도구|class-check|vulnerability\s*scan|scanner/i.test(`${description} ${requestText}`);

  if (hasRemoteLookup && hasCveSignal && hasT1190 && level >= 10) {
    return {
      action: 'block',
      confidence: Math.min(0.98, 0.9 + Math.max(0, level - 10) * 0.02),
      reason: PATTERNS[0].name,
    };
  }

  if (hasT1190 && level >= 5 && (hasCveSignal || hasScannerTrace || description.length > 0)) {
    return {
      action: 'alert',
      confidence: Math.min(0.8, 0.55 + Math.max(0, level - 5) * 0.05),
      reason: hasScannerTrace && !hasRemoteLookup ? PATTERNS[2].name : PATTERNS[1].name,
    };
  }

  if (hasRemoteLookup) {
    return { action: 'alert', confidence: 0.75, reason: PATTERNS[0].name };
  }

  return {
    action: 'record',
    confidence: 0.1,
    reason: `정상 이벤트 · ${PATTERNS[1].name} 미부합`,
  };
}

export { PATTERNS };
export default decide;
