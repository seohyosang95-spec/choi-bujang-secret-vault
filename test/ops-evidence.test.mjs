import assert from 'node:assert/strict';
import { test } from 'node:test';
import {
  OPS_TEST_CATALOG,
  createOpsSummary,
  summarizeOpsEvidence,
} from '../src/ops-evidence.mjs';

test('작전실은 1~11단계 41종을 미실행으로 시작한다', () => {
  const summary = createOpsSummary({ restoreRoute: 'POST /api/notes/restore' });
  assert.equal(OPS_TEST_CATALOG.length, 41);
  assert.equal(summary.counts.total, 41);
  assert.equal(summary.counts.executed, 0);
  assert.equal(summary.counts.unexecuted, 41);
  assert.ok(summary.checks.every(item => item.status === '미실행' && item.actual === null));
  assert.ok(summary.checks.every(item => item.stage >= 1 && item.stage <= 11));
  assert.ok(summary.checks.every(item => !Object.hasOwn(item, 'body') && !Object.hasOwn(item, 'token')));
});

test('실측 기록은 결과·요청 ID·확인 시각만 가려서 집계한다', () => {
  const summary = summarizeOpsEvidence([{
    id: 's02-forbidden-public-api',
    requestId: 'ops-1234567890-private',
    checkedAt: '2026-10-14T00:00:00.000Z',
    httpStatus: 401,
    result: '통과 · HTTP 401 · AUTH_REQUIRED',
    body: '메모 본문은 집계하지 않음',
  }]);
  const measured = summary.checks.find(item => item.id === 's02-forbidden-public-api');
  assert.equal(summary.executed, 1);
  assert.equal(summary.passed, 1);
  assert.equal(summary.unexecuted, 40);
  assert.equal(measured.status, '실측');
  assert.equal(measured.actual.requestId, 'ops-1234…');
  assert.equal(measured.actual.httpStatus, 401);
  assert.equal(measured.actual.result, '통과 · HTTP 401 · AUTH_REQUIRED');
  assert.equal('body' in measured.actual, false);
});
