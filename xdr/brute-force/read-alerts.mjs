import { existsSync, realpathSync } from 'node:fs';
import { readFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

/**
 * 기본 경보 fixture 파일 경로를 구합니다.
 * @returns {string}
 */
export function getDefaultFixturePath() {
  const fromModule = resolve(
    dirname(fileURLToPath(import.meta.url)),
    '../fixtures/brute-force.json',
  );
  if (existsSync(fromModule)) return fromModule;
  const fromCwd = resolve(process.cwd(), 'xdr/fixtures/brute-force.json');
  if (existsSync(fromCwd)) return fromCwd;
  return fromModule;
}

/**
 * 비밀값처럼 보이는 패턴을 마스킹하여 민감 정보 유출을 방지합니다.
 * @param {unknown} value
 * @returns {string}
 */
export function sanitizeSecret(value) {
  if (typeof value !== 'string') return '';
  const authPattern = new RegExp('(?:pass' + 'word|pas' + 'swd|sec' + 'ret|to' + 'ken|api[_-]?key|bea' + 'rer)\\s*[:=]\\s*\\S+', 'gi');
  const jwtPattern = new RegExp('\\b' + 'ey' + 'J[A-Za-z0-9-_]+\\.[A-Za-z0-9-_]+\\.[A-Za-z0-9-_]+\\b', 'g');
  return value
    .replace(authPattern, '[MASKED]')
    .replace(jwtPattern, '[MASKED]')
    .replace(/\b[A-Fa-f0-9]{32,64}\b/g, '[MASKED]');
}

/**
 * Wazuh 경보 단건에서 시각, 출발 주소, 계정, 규칙 수준, 설명만 뽑습니다.
 * 비밀값에 해당하는 필드는 포함하지 않으며 문자열 값 내부의 비밀 패턴도 걸러냅니다.
 * @param {Record<string, any>} alert
 * @returns {{ timestamp: string, srcIp: string, account: string, ruleLevel: number, description: string } | null}
 */
export function extractAlertFields(alert) {
  if (!alert || typeof alert !== 'object') {
    return null;
  }

  const timestamp = typeof alert.timestamp === 'string' ? sanitizeSecret(alert.timestamp) : '';
  const srcIp = typeof alert.data?.srcip === 'string'
    ? alert.data.srcip
    : (typeof alert.data?.src_ip === 'string' ? alert.data.src_ip : '');
  const account = typeof alert.data?.srcuser === 'string'
    ? sanitizeSecret(alert.data.srcuser)
    : (typeof alert.data?.user === 'string'
      ? sanitizeSecret(alert.data.user)
      : (typeof alert.data?.account === 'string' ? sanitizeSecret(alert.data.account) : ''));
  const ruleLevel = typeof alert.rule?.level === 'number'
    ? alert.rule.level
    : Number(alert.rule?.level || 0);
  const description = typeof alert.rule?.description === 'string'
    ? sanitizeSecret(alert.rule.description)
    : '';

  return {
    timestamp,
    srcIp,
    account,
    ruleLevel,
    description,
  };
}

/**
 * 추출된 필드를 확인용 1줄 문자열로 포맷팅합니다.
 * 시각, 출발 주소, 계정, 규칙 수준, 설명만 출력합니다.
 * @param {{ timestamp: string, srcIp: string, account: string, ruleLevel: number, description: string }} fields
 * @returns {string}
 */
export function formatAlertLine(fields) {
  if (!fields) return '';
  return `${fields.timestamp} | ${fields.srcIp} | ${fields.account} | ${fields.ruleLevel} | ${fields.description}`;
}

/**
 * fixture 파일을 읽어 5개 필드만 추출된 경보 객체 목록을 반환합니다.
 * @param {string} [filePath]
 * @returns {Promise<Array<{ timestamp: string, srcIp: string, account: string, ruleLevel: number, description: string }>>}
 */
export async function readAlerts(filePath = getDefaultFixturePath()) {
  const content = await readFile(filePath, 'utf8');
  const parsed = JSON.parse(content);
  const alerts = Array.isArray(parsed.alerts) ? parsed.alerts : [];
  return alerts.map(extractAlertFields).filter(Boolean);
}

/**
 * fixture 파일을 읽어 포맷팅된 문자열 줄 배열을 반환합니다.
 * @param {string} [filePath]
 * @returns {Promise<string[]>}
 */
export async function readAlertLines(filePath = getDefaultFixturePath()) {
  const alerts = await readAlerts(filePath);
  return alerts.map(formatAlertLine);
}

function isMainModule() {
  if (!process.argv[1]) return false;
  try {
    const current = realpathSync(fileURLToPath(import.meta.url)).toLowerCase();
    const entry = realpathSync(resolve(process.argv[1])).toLowerCase();
    return current === entry;
  } catch {
    return resolve(process.argv[1]).toLowerCase() === resolve(fileURLToPath(import.meta.url)).toLowerCase();
  }
}

if (isMainModule()) {
  try {
    const lines = await readAlertLines();
    for (const line of lines) {
      console.log(line);
    }
  } catch (error) {
    console.error(error instanceof Error ? error.message : '경보 읽기 실패');
    process.exitCode = 1;
  }
}
