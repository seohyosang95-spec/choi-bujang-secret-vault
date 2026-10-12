import { appendFile, readFile } from 'node:fs/promises';
import { existsSync, realpathSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { decide } from './decide.mjs';

const __dirname = dirname(fileURLToPath(import.meta.url));

export function getAlertsLogPath() {
  const fromModule = resolve(__dirname, '../alerts.log');
  return fromModule;
}

export function getDefaultFixturePath() {
  const fromModule = resolve(__dirname, '../fixtures/web-injection.json');
  if (existsSync(fromModule)) return fromModule;
  const fromCwd = resolve(process.cwd(), 'xdr/fixtures/web-injection.json');
  if (existsSync(fromCwd)) return fromCwd;
  return fromModule;
}

// 기본 차단 규칙 유효 시간: 1시간
const DEFAULT_TTL_MS = 60 * 60 * 1000;

/**
 * ZTNA 판정기의 거부 규칙 저장소 (동적 규칙 연결 맵)
 * 판정기의 기존 규칙을 변경하지 않고 거부 규칙을 등록하여 관리합니다.
 */
export const ztnaDenyRules = new Map();

/**
 * 알림(alert) 발생 시 xdr/alerts.log 에 한 줄씩 로그를 추가합니다.
 * @param {Record<string, any>} alert
 * @param {Record<string, any>} decision
 * @param {string} [logPath]
 */
export async function logAlert(alert, decision, logPath = getAlertsLogPath()) {
  const timestamp = alert.timestamp || new Date().toISOString();
  const alertId = alert.id || '(id 없음)';
  const srcIp = alert.data?.srcip || '-';
  const user = alert.data?.srcuser || '-';
  const reason = decision?.reason || alert.rule?.description || '의심스러운 웹 주입 시도';
  const line = `[${timestamp}] ALERT alertId=${alertId} srcip=${srcIp} user=${user} reason="${reason}"\n`;
  await appendFile(logPath, line, 'utf8');
}

/**
 * Wazuh 경보 하나를 받아 decide를 수행하고,
 * - 차단 후보(block): ZTNA 판정기 거부 규칙으로 등록 (만료 시각, 근거 경보 번호 포함)
 * - 알림 후보(alert): xdr/alerts.log 에 한 줄씩 기록
 * - 정상(record): 차단 규칙 없이 통과
 *
 * 정상 사용자를 막지 않도록 사용자 계정이 아닌 공격 출발 주소(srcip)만 거부 규칙으로 등록합니다.
 *
 * @param {Record<string, any>} alert
 * @param {object} [options]
 * @param {number} [options.ttlMs=DEFAULT_TTL_MS]
 * @param {string} [options.logPath]
 * @returns {Promise<{ action: string, decision: object, denyRule?: object, logged?: boolean }>}
 */
export async function respondToAlert(alert, options = {}) {
  const { ttlMs = DEFAULT_TTL_MS, logPath = getAlertsLogPath() } = options;
  const decision = await decide(alert);

  if (decision.action === 'block') {
    // 차단 후보: 정상 사용자를 막지 않기 위해 계정이 아닌 공격 출발 주소(srcip)만 차단
    const targetIp = alert.data?.srcip;
    if (!targetIp) {
      return { action: 'block', decision, error: '출발 주소가 없어 규칙을 생성하지 못했습니다.' };
    }

    const baseTime = Math.max(
      alert.timestamp ? new Date(alert.timestamp).getTime() : 0,
      Date.now(),
    );
    const expiresAt = new Date(baseTime + ttlMs).toISOString();
    const ruleId = `deny_xdr_${alert.id}`;

    const denyRule = {
      ruleId,
      alertId: alert.id,
      targetIp,
      decision: 'deny',
      reasonCode: 'xdr_web_injection_blocked',
      reason: decision.reason,
      createdAt: alert.timestamp || new Date().toISOString(),
      expiresAt,
    };

    ztnaDenyRules.set(ruleId, denyRule);
    return { action: 'block', decision, denyRule };
  }

  if (decision.action === 'alert') {
    // 알림 후보: alerts.log 에 한 줄 누적
    await logAlert(alert, decision, logPath);
    return { action: 'alert', decision, logged: true };
  }

  // 정상 이벤트(record): 차단 없음
  return { action: 'record', decision };
}

/**
 * ZTNA 판정기 접속 검사 함수:
 * 등록된 거부 규칙을 바탕으로 요청 또는 경보가 차단되는지 판정합니다.
 * 판정기의 기존 규칙은 손대지 않고 동적으로 등록된 거부 규칙만 검사합니다.
 *
 * @param {{ srcip?: string, ip?: string, [key: string]: any }} requestOrAlert
 * @param {Date | number | string} [currentTime]
 * @returns {{ allowed: boolean, decision: 'allow' | 'deny', matchedRule: object | null, reasonCode: string }}
 */
export function checkZtnaAccess(requestOrAlert, currentTime) {
  const now = currentTime ? new Date(currentTime).getTime() : Date.now();
  const clientIp = requestOrAlert.srcip || requestOrAlert.data?.srcip || requestOrAlert.ip;

  for (const rule of ztnaDenyRules.values()) {
    const expireTime = new Date(rule.expiresAt).getTime();
    if (expireTime <= now) {
      continue; // 만료된 규칙은 건너뜀
    }

    if (clientIp && rule.targetIp === clientIp) {
      return {
        allowed: false,
        decision: 'deny',
        matchedRule: rule,
        reasonCode: rule.reasonCode,
      };
    }
  }

  return {
    allowed: true,
    decision: 'allow',
    matchedRule: null,
    reasonCode: 'approved',
  };
}

/**
 * 여러 경보를 순차적으로 처리합니다.
 * @param {Array<Record<string, any>>} alerts
 * @param {object} [options]
 * @returns {Promise<Array<object>>}
 */
export async function processAlerts(alerts, options = {}) {
  const results = [];
  for (const alert of alerts) {
    const result = await respondToAlert(alert, options);
    results.push(result);
  }
  return results;
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
    const fixturePath = getDefaultFixturePath();
    const content = await readFile(fixturePath, 'utf8');
    const { alerts } = JSON.parse(content);

    console.log(`[대응 모듈] ${alerts.length}건의 경보를 처리합니다...`);
    const results = await processAlerts(alerts);

    const blockCount = results.filter((r) => r.action === 'block').length;
    const alertCount = results.filter((r) => r.action === 'alert').length;
    const recordCount = results.filter((r) => r.action === 'record').length;

    console.log(`[대응 완료] 차단 후보: ${blockCount}건, 알림 기록: ${alertCount}건, 기록(정상): ${recordCount}건`);
    console.log(`[ZTNA 판정기] 등록된 거부 규칙 수: ${ztnaDenyRules.size}건`);

    // 시험 경보를 다시 흘렸을 때 명확한 공격만 막히고 정상 요청은 통과하는지 검증
    console.log('\n[재시험 검증] 시험 경보를 ZTNA 판정기에 다시 흘려 접속을 검증합니다:');
    let attackBlocked = 0;
    let normalPassed = 0;
    let suspiciousPassed = 0;

    const attackIds = ['wi-01', 'wi-02', 'wi-03', 'wi-04', 'wi-05', 'wi-06', 'wi-07', 'wi-08'];
    const normalIds = ['wi-18', 'wi-19', 'wi-20', 'wi-21', 'wi-22', 'wi-23', 'wi-24', 'wi-25', 'wi-26'];

    for (const a of alerts) {
      const access = checkZtnaAccess(a);
      const isAttack = attackIds.includes(a.id);
      const isNormal = normalIds.includes(a.id);

      if (isAttack) {
        if (!access.allowed && access.decision === 'deny') {
          attackBlocked += 1;
        } else {
          console.error(`  [오류] 명확한 공격(${a.id})이 차단되지 않았습니다!`);
        }
      } else if (isNormal) {
        if (access.allowed && access.decision === 'allow') {
          normalPassed += 1;
        } else {
          console.error(`  [오류] 정상 요청(${a.id})이 차단되었습니다!`);
        }
      } else {
        if (access.allowed) {
          suspiciousPassed += 1;
        }
      }
    }

    console.log(`- 명확한 공격 차단: ${attackBlocked}/${attackIds.length}건 차단 완료`);
    console.log(`- 정상 요청 통과: ${normalPassed}/${normalIds.length}건 통과 완료`);
    console.log(`- 애매한 시도(알림): ${suspiciousPassed}/9건 통과 (알림 로그 누적)`);

    if (attackBlocked === attackIds.length && normalPassed === normalIds.length) {
      console.log('\n[검증 성공] 명확한 공격만 막히고 정상 요청은 모두 통과했습니다.');
    } else {
      console.error('\n[검증 실패] 차단/통과 조건이 맞지 않습니다.');
      process.exitCode = 1;
    }
  } catch (error) {
    console.error(error instanceof Error ? error.message : '대응 처리 실패');
    process.exitCode = 1;
  }
}
