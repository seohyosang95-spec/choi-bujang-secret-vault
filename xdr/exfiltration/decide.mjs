const PATTERNS = Object.freeze([
  {
    name: '처음 보는 목적지 대용량 전송',
    condition: 'T1041 또는 T1048 경보에서 처음 보는 목적지로 대용량·다량 파일이 전송되거나 짧은 시간 반복 전송이 발생한 경우',
    basis: 'MITRE ATT&CK T1041(명령 통로로 유출)·T1048(다른 프로토콜로 유출)에 근거해 낯선 목적지로 자료가 대량 반출되는 신호를 확인합니다.',
  },
  {
    name: '업무 시간 밖 압축 파일 반출',
    condition: 'T1041 또는 T1048 경보에서 업무 시간 밖에 압축 파일이 외부 목적지로 전송·반출된 경우',
    basis: 'MITRE ATT&CK T1048(다른 프로토콜로 유출)에 근거해 업무 시간 밖 압축 자료 반출을 확인합니다.',
  },
]);

const text = (value) => typeof value === 'string' ? value : '';
const number = (value) => {
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : 0;
};

/**
 * Wazuh 유출 경보를 외부 의존성 없이 순수 계산으로 판단합니다.
 */
export function decide(alert) {
  if (!alert || typeof alert !== 'object') {
    return { action: 'record', confidence: 0, reason: '유효한 경보 데이터가 아닙니다' };
  }

  const data = alert.data && typeof alert.data === 'object' ? alert.data : {};
  const description = text(alert.rule?.description);
  const level = number(alert.rule?.level);
  const bytes = number(data.bytes);
  const files = number(data.files);
  const count = number(data.count);
  const mitre = Array.isArray(alert.rule?.mitre) ? alert.rule.mitre.map(String) : [];
  const hasT1041 = mitre.some((item) => item.toUpperCase().startsWith('T1041'));
  const hasT1048 = mitre.some((item) => item.toUpperCase().startsWith('T1048'));
  const hasExfiltrationTechnique = hasT1041 || hasT1048;
  const context = `${description} ${text(data.dstip)}`;

  const unfamiliarDestination = /처음\s*보는\s*(?:목적지|주소)|낯선\s*(?:목적지|주소)|평소에\s*쓰지\s*않던\s*포트|두\s*곳/i.test(context);
  const repeatedOrLarge = bytes >= 50_000_000 || files >= 50 || count >= 8
    || /대용량|큰\s*파일|자료실\s*전체|전체가|연속\s*전송|반복\s*전송|자료\s*\d+건/i.test(description);
  const outsideHours = /업무\s*시간\s*밖|수업\s*시간\s*밖|업무처럼\s*보이지\s*않는|야간/i.test(description);
  const compressedOutbound = /압축\s*파일/i.test(description)
    && /(?:나갔|전송|반출|올라갔|외부)/i.test(description);

  const unfamiliarLargeTransfer = hasExfiltrationTechnique
    && (unfamiliarDestination && repeatedOrLarge
      || (repeatedOrLarge && /(?:외부\s*주소|같은\s*목적지|평소\s*목적지)/i.test(description))
      || (hasT1041 && /자료실\s*전체|전체가.*복사|명령\s*통로.*(?:큰|대용량)/i.test(description)));
  const afterHoursArchive = hasExfiltrationTechnique && outsideHours && compressedOutbound;
  const matchedPattern = afterHoursArchive ? PATTERNS[1]
    : (unfamiliarLargeTransfer ? PATTERNS[0] : null);

  if (matchedPattern && level >= 10) {
    return {
      action: 'block',
      confidence: Math.min(0.98, 0.9 + Math.max(0, level - 10) * 0.02),
      reason: matchedPattern.name,
    };
  }

  if (hasExfiltrationTechnique && level >= 5) {
    return {
      action: 'alert',
      confidence: Math.min(0.8, 0.55 + Math.max(0, level - 5) * 0.05),
      reason: (matchedPattern || (hasT1048 ? PATTERNS[1] : PATTERNS[0])).name,
    };
  }

  return {
    action: 'record',
    confidence: 0.1,
    reason: `정상 이벤트 · ${PATTERNS[0].name}·${PATTERNS[1].name} 미부합`,
  };
}

export { PATTERNS };
export default decide;
