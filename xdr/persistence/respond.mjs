import { appendFile, readFile } from 'node:fs/promises';
import { existsSync, realpathSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { decide } from './decide.mjs';

const moduleDir = dirname(fileURLToPath(import.meta.url));
const DEFAULT_TTL_MS = 60 * 60 * 1000;

export const ztnaDenyRules = new Map();

export function getAlertsLogPath() {
  return resolve(moduleDir, '../alerts.log');
}

export function getDefaultFixturePath() {
  const fromModule = resolve(moduleDir, '../fixtures/persistence.json');
  if (existsSync(fromModule)) return fromModule;
  const fromCwd = resolve(process.cwd(), 'xdr/fixtures/persistence.json');
  if (existsSync(fromCwd)) return fromCwd;
  return fromModule;
}

function safeLogValue(value) {
  if (typeof value !== 'string' || !value) return '-';
  return value
    .replace(/(?:pass(?:word|wd)|secret|token|api[_-]?key|bearer)\s*[:=]\s*\S+/gi, '[MASKED]')
    .replace(/\b[A-Fa-f0-9]{32,64}\b/g, '[MASKED]')
    .replace(/[\r\n]/g, ' ');
}

export async function logAlert(alert, decision, logPath = getAlertsLogPath()) {
  const timestamp = safeLogValue(alert?.timestamp) || new Date().toISOString();
  const alertId = safeLogValue(alert?.id);
  const srcIp = safeLogValue(alert?.data?.srcip);
  const account = safeLogValue(alert?.data?.srcuser || alert?.data?.user);
  const reason = safeLogValue(decision?.reason || '지속성 의심 경보');
  await appendFile(logPath, `[${timestamp}] ALERT alertId=${alertId} srcip=${srcIp} user=${account} reason="${reason}"\n`, 'utf8');
}

export async function respondToAlert(alert, options = {}) {
  const { ttlMs = DEFAULT_TTL_MS, logPath = getAlertsLogPath() } = options;
  const decision = decide(alert);

  if (decision.action === 'block') {
    const targetIp = typeof alert?.data?.srcip === 'string' ? alert.data.srcip : '';
    if (!targetIp) return { action: 'block', decision, error: '출발 주소가 없어 규칙을 생성하지 못했습니다.' };

    const parsedTime = alert.timestamp ? new Date(alert.timestamp).getTime() : NaN;
    const now = Date.now();
    const createdAt = Number.isFinite(parsedTime) ? new Date(parsedTime).toISOString() : new Date(now).toISOString();
    const expiresAt = new Date(Math.max(Number.isFinite(parsedTime) ? parsedTime : 0, now) + ttlMs).toISOString();
    const ruleId = `deny_xdr_${safeLogValue(alert.id)}`;
    const denyRule = {
      ruleId,
      alertId: safeLogValue(alert.id),
      targetIp,
      decision: 'deny',
      reasonCode: 'xdr_persistence_blocked',
      reason: decision.reason,
      createdAt,
      expiresAt,
    };
    ztnaDenyRules.set(ruleId, denyRule);
    return { action: 'block', decision, denyRule };
  }

  if (decision.action === 'alert') {
    await logAlert(alert, decision, logPath);
    return { action: 'alert', decision, logged: true };
  }

  return { action: 'record', decision };
}

export function checkZtnaAccess(requestOrAlert, currentTime) {
  const now = currentTime ? new Date(currentTime).getTime() : Date.now();
  const clientIp = requestOrAlert?.srcip || requestOrAlert?.data?.srcip || requestOrAlert?.ip;
  for (const rule of ztnaDenyRules.values()) {
    if (new Date(rule.expiresAt).getTime() <= now) continue;
    if (clientIp && rule.targetIp === clientIp) {
      return { allowed: false, decision: 'deny', matchedRule: rule, reasonCode: rule.reasonCode };
    }
  }
  return { allowed: true, decision: 'allow', matchedRule: null, reasonCode: 'approved' };
}

export async function processAlerts(alerts, options = {}) {
  const results = [];
  for (const alert of alerts) results.push(await respondToAlert(alert, options));
  return results;
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
    const { alerts } = JSON.parse(await readFile(getDefaultFixturePath(), 'utf8'));
    const results = await processAlerts(alerts);
    const counts = results.reduce((out, item) => {
      out[item.action] += 1;
      return out;
    }, { block: 0, alert: 0, record: 0 });
    console.log(`[대응 완료] 차단 후보: ${counts.block}건, 알림 기록: ${counts.alert}건, 기록(정상): ${counts.record}건`);
  } catch (error) {
    console.error(error instanceof Error ? error.message : '대응 처리 실패');
    process.exitCode = 1;
  }
}
