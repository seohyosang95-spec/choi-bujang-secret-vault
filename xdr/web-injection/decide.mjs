const PATTERNS = [
  {
    name: '요청 인자 내 SQL 구문 삽입 반복',
    condition: '동일한 출발 IP에서 URL 파라미터나 요청 인자에 SQL 조작 구문(따옴표 결합, SELECT, UNION 등) 또는 데이터베이스 질의 연결 표기가 10회 이상 반복되는 경우',
    basis: 'MITRE ATT&CK T1190(Exploit Public-Facing Application) - 웹 입력값 검증 미흡을 악용해 조작된 SQL 질의를 주입하고 데이터베이스 정보를 무단 탈취·조작하려는 형태입니다.',
  },
  {
    name: '요청 인자 내 스크립트 태그 삽입 반복',
    condition: '동일한 출발 IP에서 검색어나 요청 인자에 <script> 태그, 스크립트 삽입 표식 등이 8회 이상 반복되어 전달되는 경우',
    basis: 'MITRE ATT&CK T1190(Exploit Public-Facing Application) - 웹 애플리케이션의 출력 필터링 취약점을 악용해 클라이언트 측에서 실행될 악성 자바스크립트 코드를 주입하려는 형태입니다.',
  },
  {
    name: '경로 거슬러 올라가기(../) 및 경로 이탈 반복',
    condition: '동일한 출발 IP에서 파일 경로나 요청 파라미터에 상위 디렉터리 이동 표기(../) 또는 경로 이탈 구문이 8회 이상 반복되는 경우',
    basis: 'MITRE ATT&CK T1190(Exploit Public-Facing Application) - 웹 서버의 경로 제약 검증을 우회하여 공개 디렉터리 외부의 시스템 파일 및 중요 자원에 무단 접근하려는 형태입니다.',
  },
  {
    name: '스크립트 및 SQL 표식 혼합 교차 주입',
    condition: '동일한 출발 IP에서 스크립트 삽입 표식과 SQL 구문 표기가 번갈아 반복되며 10회 이상의 연속 요청이 발생하는 경우',
    basis: 'MITRE ATT&CK T1190(Exploit Public-Facing Application) - 취약점 스캐너 또는 공격 스크립트를 통해 다수의 웹 주입 취약점 벡터를 동시에 탐색하고 악용하려는 형태입니다.',
  },
  {
    name: '요청 인자 내 시스템 명령 구분자 반복 주입',
    condition: '동일한 출발 IP에서 요청 파라미터에 셸 명령 구분자(; , | , && 등) 표기가 10회 이상 연속 포함되어 전달되는 경우',
    basis: 'MITRE ATT&CK T1190(Exploit Public-Facing Application) - 백엔드 명령 실행 인터페이스에 셸 메타문자를 주입하여 시스템 권한으로 임의 명령을 실행하려는 형태입니다.',
  },
];

/**
 * Wazuh 경보 하나를 받아 웹 인젝션 패턴과 맞춰 판정합니다.
 * 외부 라이브러리, import, 파일 I/O 없이 순수 계산만으로 동작합니다.
 *
 * @param {Record<string, any>} alert - Wazuh 경보 객체
 * @returns {{ action: 'block' | 'alert' | 'record', confidence: number, reason: string }}
 */
export function decide(alert) {
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
  const url = typeof data.url === 'string' ? data.url : '';

  // 1. 세부 패턴 매칭
  let matchedPattern = null;

  if (description.includes('번갈아') || (description.includes('스크립트') && description.includes('SQL'))) {
    matchedPattern = PATTERNS[3]; // 스크립트 및 SQL 표식 혼합 교차 주입
  } else if (description.includes('명령 구분자') || description.includes('구분 문자')) {
    matchedPattern = PATTERNS[4]; // 시스템 명령 구분자 반복 주입
  } else if (description.includes('경로') || description.includes('거슬러') || description.includes('이탈') || url.includes('path=') || url.includes('..')) {
    matchedPattern = PATTERNS[2]; // 경로 거슬러 올라가기(../) 및 경로 이탈 반복
  } else if (description.includes('스크립트') || url.includes('script')) {
    matchedPattern = PATTERNS[1]; // 요청 인자 내 스크립트 태그 삽입 반복
  } else if (description.includes('SQL') || description.includes('데이터베이스') || description.includes('따옴표') || description.includes('select') || url.includes('sql')) {
    matchedPattern = PATTERNS[0]; // 요청 인자 내 SQL 구문 삽입 반복
  } else if (description.includes('주입') || description.includes('검색')) {
    matchedPattern = PATTERNS[0];
  }

  // 2. 확신도(confidence) 계산
  // 0.85 이상: 명확한 공격 (block)
  // 0.5 이상 0.85 미만: 애매한 시도 (alert)
  // 0.5 미만: 정상 이벤트 (record)
  let confidence = 0;
  let reason = '';

  const isMitreT1190 = mitre.some(m => String(m).toUpperCase().startsWith('T1190'))
    || /SQL|스크립트|주입|경로|명령 구분자|T1190/i.test(description);

  if (level >= 10 && isMitreT1190) {
    // 명확한 공격 (block): level 10~12
    confidence = Math.min(0.95, 0.85 + (level - 10) * 0.05);
    reason = matchedPattern ? matchedPattern.name : PATTERNS[0].name;
  } else if (level >= 5 && isMitreT1190) {
    // 애매한 시도 (alert): level 5~8 (단발성 특수문자, 키워드 우연 일치 등)
    confidence = Math.min(0.8, 0.55 + (level - 5) * 0.05);
    reason = matchedPattern ? matchedPattern.name : PATTERNS[0].name;
  } else {
    // 정상 이벤트 (record): level 2~3, mitre 없음
    confidence = 0.1;
    reason = '정상 이벤트 (웹 인젝션 패턴 미부합)';
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

export default decide;
