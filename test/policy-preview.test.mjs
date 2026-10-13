import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  createPolicyRestorePlan,
  policySha256,
  previewPolicyChanges,
  restoreTestPolicy,
  verifySafePolicySnapshot,
} from '../src/policy-preview.mjs';

const safePolicy = Object.freeze({
  zones: { notes: 'owner_only', announcements: 'read_only' },
  limits: { burstRead: 120 },
});
const safeSnapshot = Object.freeze({
  schema: 'aleph.safe-policy-snapshot.v1',
  version: 'safe-before-incident-2026-10-13',
  verifiedAt: '2026-10-13T00:00:00.000Z',
  policySha256: policySha256(safePolicy),
  policy: safePolicy,
});

test('검증된 사본의 복원 버전과 변경 범위만 미리 보여 준다', () => {
  const currentPolicy = {
    zones: { notes: 'owner_only', announcements: 'read_write' },
    limits: { burstRead: 120 },
    trial: { enabled: true },
  };
  const preview = previewPolicyChanges({
    safeSnapshot,
    trustedDigest: safeSnapshot.policySha256,
    currentPolicy,
    currentVersion: 'test-current-1',
  });

  assert.equal(preview.restoreVersion, 'safe-before-incident-2026-10-13');
  assert.deepEqual(preview.changeScope, { added: 1, removed: 0, changed: 1, total: 2 });
  assert.deepEqual(preview.changes, [
    { path: '/trial', kind: 'added' },
    { path: '/zones/announcements', kind: 'changed' },
  ]);
  assert.equal(Object.hasOwn(preview, 'safeSnapshot'), false);
  assert.equal(Object.hasOwn(preview, 'currentPolicy'), false);
});

test('안전 사본이 없으면 중단한다', () => {
  assert.throws(
    () => previewPolicyChanges({ trustedDigest: safeSnapshot.policySha256, currentPolicy: safePolicy }),
    error => error.code === 'safe_policy_snapshot_missing',
  );
});

test('신뢰 다이제스트가 다르면 중단하고 정책을 바꾸지 않는다', () => {
  const currentPolicy = { ...safePolicy };
  assert.throws(
    () => verifySafePolicySnapshot(safeSnapshot, '0'.repeat(64)),
    error => error.code === 'safe_policy_snapshot_verification_failed',
  );
  assert.deepEqual(currentPolicy, safePolicy);
});

test('복원 계획은 변경 범위를 먼저 보여 주고 서비스 규칙과 감사 이력을 보존한다', () => {
  const currentTestPolicy = {
    policy: {
      zones: { notes: 'owner_only', announcements: 'read_write' },
      limits: { burstRead: 120 },
      trial: { enabled: true },
    },
    serviceRules: { billing: 'unchanged' },
    auditHistory: [{ event: 'policy-test', at: '2026-10-13T01:00:00.000Z' }],
  };
  const plan = createPolicyRestorePlan({
    safeSnapshot,
    trustedDigest: safeSnapshot.policySha256,
    currentTestPolicy,
    currentVersion: 'test-current-2',
  });

  assert.equal(plan.restoreVersion, 'safe-before-incident-2026-10-13');
  assert.deepEqual(plan.changeScope, { added: 1, removed: 0, changed: 1, total: 2 });
  assert.deepEqual(plan.changes, [
    { path: '/policy/trial', kind: 'added' },
    { path: '/policy/zones/announcements', kind: 'changed' },
  ]);
  assert.deepEqual(plan.preservedTopLevel, ['auditHistory', 'serviceRules']);
  assert.equal(plan.confirmationRequired, true);
  assert.equal(Object.hasOwn(plan, 'policy'), false);

  const restored = restoreTestPolicy({
    safeSnapshot,
    trustedDigest: safeSnapshot.policySha256,
    currentTestPolicy,
    currentVersion: 'test-current-2',
    plan,
    confirmation: true,
  });
  assert.deepEqual(restored.policy, safePolicy);
  assert.deepEqual(restored.serviceRules, currentTestPolicy.serviceRules);
  assert.deepEqual(restored.auditHistory, currentTestPolicy.auditHistory);
  assert.deepEqual(currentTestPolicy.policy.trial, { enabled: true });
});

test('복원은 확인 없이 적용되지 않고 오래된 계획도 거부한다', () => {
  const currentTestPolicy = { policy: { ...safePolicy }, serviceRules: { search: 'keep' } };
  const plan = createPolicyRestorePlan({
    safeSnapshot,
    trustedDigest: safeSnapshot.policySha256,
    currentTestPolicy,
  });

  assert.throws(
    () => restoreTestPolicy({
      safeSnapshot,
      trustedDigest: safeSnapshot.policySha256,
      currentTestPolicy,
      plan,
    }),
    error => error.code === 'restore_confirmation_required',
  );
  assert.throws(
    () => restoreTestPolicy({
      safeSnapshot,
      trustedDigest: safeSnapshot.policySha256,
      currentTestPolicy: { ...currentTestPolicy, policy: { ...safePolicy, extra: true } },
      plan,
      confirmation: true,
    }),
    error => error.code === 'restore_plan_stale',
  );
});
