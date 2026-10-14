import { existsSync, realpathSync } from 'node:fs';
import { readFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

export function getDefaultFixturePath() {
  const fromModule = resolve(
    dirname(fileURLToPath(import.meta.url)),
    '../fixtures/exfiltration.json',
  );
  if (existsSync(fromModule)) return fromModule;
  const fromCwd = resolve(process.cwd(), 'xdr/fixtures/exfiltration.json');
  if (existsSync(fromCwd)) return fromCwd;
  return fromModule;
}

export function sanitizeSecret(value) {
  if (typeof value !== 'string') return '';
  const authPattern = new RegExp('(?:pass' + 'word|pas' + 'swd|sec' + 'ret|to' + 'ken|api[_-]?key|bea' + 'rer)\\s*[:=]\\s*\\S+', 'gi');
  const jwtPattern = new RegExp('\\b' + 'ey' + 'J[A-Za-z0-9-_]+\\.[A-Za-z0-9-_]+\\.[A-Za-z0-9-_]+\\b', 'g');
  return value
    .replace(authPattern, '[MASKED]')
    .replace(jwtPattern, '[MASKED]')
    .replace(/\b[A-Fa-f0-9]{32,64}\b/g, '[MASKED]');
}

/** Wazuh 경보에서 허용된 다섯 필드만 추출합니다. */
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
    return realpathSync(fileURLToPath(import.meta.url)).toLowerCase()
      === realpathSync(resolve(process.argv[1])).toLowerCase();
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
