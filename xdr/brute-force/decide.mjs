const PATTERNS = [
  {
    name: '짧은 시간 동일 주소 로그인 실패 연속 (단일 주소 집중 대입)',
    condition: '동일한 출발 IP에서 1~3분 이내에 30건 이상의 로그인 실패가 집중 발생하고 성공 이력이 없는 경우',
    basis: 'MITRE ATT&CK T1110.001(Password Guessing) - 특정 시스템 또는 계정의 암호를 알아내기 위해 단시간에 무차별 대입을 연속 시도하는 형태입니다.',
  },
  {
    name: '다수 계정 대상 동일 비밀번호 연속 대입 (패스워드 스프레잉)',
    condition: '동일한 출발 IP에서 다수의 서로 다른 계정(8개 이상)을 대상으로 동일하거나 유사한 비밀번호 시도 실패가 이어지는 경우',
    basis: 'MITRE ATT&CK T1110.003(Password Spraying) - 계정 잠금 정책을 회피하기 위해 하나의 비밀번호를 여러 계정에 순차 대입하는 형태입니다.',
  },
  {
    name: '계정 이름 순회 무차별 대입',
    condition: '동일한 출발 IP에서 짧은 시간 동안 계정 이름을 지속적으로 바꾸어가며 로그인 실패를 누적시키는 경우',
    basis: 'MITRE ATT&CK T1110.001(Password Guessing) - 유효한 계정을 식별하거나 무작위 계정을 탈취하기 위해 사용자명을 순회하며 대입하는 형태입니다.',
  },
  {
    name: '자동화 도구 기반 일정 간격 무차별 대입',
    condition: '동일한 출발 IP에서 다수 계정에 대해 일정한 시간 간격으로 기계적인 로그인 실패를 반복 발생시키는 경우',
    basis: 'MITRE ATT&CK T1110(Brute Force) - 자동화 스크립트나 공격 도구를 이용해 일정한 주기로 탐지 임계치를 우회하려는 형태입니다.',
  },
  {
    name: '단일 표적 계정 지속 실패 누적',
    condition: '동일한 출발 IP에서 특정 계정 하나만을 표적으로 삼아 성공 없이 50건 이상의 로그인 실패가 지속 이어지는 경우',
    basis: 'MITRE ATT&CK T1110.001(Password Guessing) - 특정 표적 계정의 암호를 알아내기 위해 사전 공격 및 무차별 대입을 집중 시도하는 형태입니다.',
  },
  {
    name: '변형 비밀번호 반복 대입 (사전 대입)',
    condition: '동일한 출발 IP에서 비밀번호를 한 글자씩 변경하거나 규칙적으로 변형하며 40건 이상의 로그인 실패가 누적되는 경우',
    basis: 'MITRE ATT&CK T1110.001(Password Guessing) - 흔히 사용되는 단어나 패턴에 변형 규칙을 적용해 유효 암호를 추측하려는 형태입니다.',
  },
];

/**
 * Wazuh 경보 하나를 받아 패턴과 맞춰 판정합니다.
 * 외부 라이브러리나 import 없이 순수 계산만으로 동작합니다.
 *
 * @param {Record<string, any>} alert - Wazuh 경보 객체
 * @returns {Promise<{ action: 'block' | 'alert' | 'record', confidence: number, reason: string }>}
 */
export async function decide(alert) {
  if (!alert || typeof alert !== 'object') {
    return {
      action: 'record',
      confidence: 0,
      reason: '유효한 경보 데이터가 아닙니다',
    };
  }

  const level = typeof alert.rule?.level === 'number'
    ? alert.rule.level
    : Number(alert.rule?.level || 0);
  const description = typeof alert.rule?.description === 'string'
    ? alert.rule.description
    : '';
  const data = alert.data && typeof alert.data === 'object' ? alert.data : {};
  const mitre = Array.isArray(alert.rule?.mitre) ? alert.rule.mitre : [];
  const count = Number(data.count || 0);

  // 1. 세부 패턴 매칭
  let matchedPattern = null;

  if (data.accounts || description.includes('여러 계정') || description.includes('서로 다른 계정')) {
    matchedPattern = PATTERNS[1]; // 다수 계정 대상 동일 비밀번호 연속 대입 (패스워드 스프레잉)
  } else if (description.includes('계정 이름') || description.includes('이름을 바꿔')) {
    matchedPattern = PATTERNS[2]; // 계정 이름 순회 무차별 대입
  } else if (description.includes('같은 간격') || description.includes('일정한 간격')) {
    matchedPattern = PATTERNS[3]; // 자동화 도구 기반 일정 간격 무차별 대입
  } else if (description.includes('한 글자씩') || description.includes('바꿔 넣는')) {
    matchedPattern = PATTERNS[5]; // 변형 비밀번호 반복 대입 (사전 대입)
  } else if (count >= 50 || description.includes('한 계정에 2분') || description.includes('같은 계정에서 로그인 실패')) {
    matchedPattern = PATTERNS[4]; // 단일 표적 계정 지속 실패 누적
  } else if (count >= 30 || description.includes('2분 안에') || description.includes('1분 안에') || description.includes('90건')) {
    matchedPattern = PATTERNS[0]; // 짧은 시간 동일 주소 로그인 실패 연속 (단일 주소 집중 대입)
  }

  // 2. 확신도(confidence) 계산
  // 0.85 이상: 명확한 공격 (block)
  // 0.5 이상 0.85 미만: 애매한 시도 (alert)
  // 0.5 미만: 정상 이벤트 (record)
  let confidence = 0;
  let reason = '';

  const isMitreT1110 = mitre.includes('T1110');

  if (level >= 10 && isMitreT1110) {
    // 명확한 무차별 대입 공격
    confidence = Math.min(0.95, 0.85 + (level - 10) * 0.05);
    reason = matchedPattern ? matchedPattern.name : PATTERNS[0].name;
  } else if (level >= 5 && isMitreT1110) {
    // 애매한 시도 (일부 실패가 있으나 횟수가 적거나 후속 성공, 변경 화면 등)
    confidence = Math.min(0.8, 0.55 + (level - 5) * 0.05);
    if (!matchedPattern) {
      if (data.accounts || description.includes('두 계정')) {
        matchedPattern = PATTERNS[1];
      } else {
        matchedPattern = PATTERNS[0];
      }
    }
    reason = matchedPattern.name;
  } else {
    // 정상 이벤트 (성공 로그, 세션 유지 등)
    confidence = 0.1;
    reason = '정상 이벤트 (무차별 대입 패턴 미부합)';
  }

  // 3. 행동 결정
  let action = 'record';
  if (confidence >= 0.85) {
    action = 'block';
  } else if (confidence >= 0.5) {
    action = 'alert';
  } else {
    action = 'record';
  }

  return { action, confidence, reason };
}
