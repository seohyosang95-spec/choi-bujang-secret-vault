import { existsSync, realpathSync } from 'node:fs';
import { readFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

export function getDefaultFixturePath() {
  const fromModule = resolve(
    dirname(fileURLToPath(import.meta.url)),
    '../fixtures/known-cve.json',
  );
  if (existsSync(fromModule)) return fromModule;
  const fromCwd = resolve(process.cwd(), 'xdr/fixtures/known-cve.json');
  if (existsSync(fromCwd)) return fromCwd;
  return fromModule;
}

/**
 * 확인용 출력에서 비밀값처럼 보이는 문자열을 가립니다.
 * 원본 경보 객체는 변경하지 않습니다.
 * @param {unknown} value
 * @returns {string}
 */
export function sanitizeSecret(value) {
  if (typeof value !== 'string') return '';
  const authPattern = new RegExp('(?:pass' + 'word|pas' + 'swd|sec' + 'ret|to' + 'ken|api[_-]?key|bea' + 'rer)\s*[:=]\s*\S+', 'gi');
  const jwtPattern = new RegExp('\\b' + 'ey' + 'J[A-Za-z0-9-_]+\\.[A-Za-z0-9-_]+\\.[A-Za-z0-9-_]+\\b', 'g');
  return value
    .replace(authPattern, '[MASKED]')
    .replace(jwtPattern, '[MASKED]')
    .replace(/\b[A-Fa-f0-9]{32,64}\b/g, '[MASKED]');
}

/**
 * Wazuh 경보에서 시각·출발 주소·계정·규칙 수준·설명만 추출합니다.
 * @param {Record<string, any>} alert
 * @returns {{ timestamp: string, srcIp: string, account: string, ruleLevel: number, description: string } | null}
 */
export function extractAlertFields(alert) {
  if (!alert || typeof alert !== 'object') return null;

  const timestamp = typeof alert.timestamp === 'string' ? sanitizeSecret(alert.timestamp) : '';
  const srcIp = typeof alert.data?.srcip === 'string'
    ? sanitizeSecret(alert.data.srcip)
    : (typeof alert.data?.src_ip === 'string' ? sanitizeSecret(alert.data.src_ip) : '');
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

  return { timestamp, srcIp, account, ruleLevel, description };
}

export function formatAlertLine(fields) {
  if (!fields) return '';
  return `${fields.timestamp} | ${fields.srcIp} | ${fields.account} | ${fields.ruleLevel} | ${fields.description}`;
}

export async function readAlerts(filePath = getDefaultFixturePath()) {
  const parsed = JSON.parse(await readFile(filePath, 'utf8'));
  const alerts = Array.isArray(parsed.alerts) ? parsed.alerts : [];
  return alerts.map(extractAlertFields).filter(Boolean);
}

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
    for (const line of await readAlertLines()) console.log(line);
  } catch (error) {
    console.error(error instanceof Error ? error.message : '경보 읽기 실패');
    process.exitCode = 1;
  }
}
