import { createHash } from 'node:crypto';

const SNAPSHOT_SCHEMA = 'aleph.safe-policy-snapshot.v1';
const PREVIEW_SCHEMA = 'aleph.policy-preview.v1';
const RESTORE_PLAN_SCHEMA = 'aleph.policy-restore-plan.v1';
const SHA256 = /^[a-f0-9]{64}$/u;

export class PolicyPreviewError extends Error {
  constructor(code) {
    super(code);
    this.name = 'PolicyPreviewError';
    this.code = code;
  }
}

function fail(code) {
  throw new PolicyPreviewError(code);
}

function isRecord(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function canonicalize(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalize).join(',')}]`;
  if (isRecord(value)) {
    return `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${canonicalize(value[key])}`).join(',')}}`;
  }
  return JSON.stringify(value);
}

export function policySha256(policy) {
  return createHash('sha256').update(canonicalize(policy), 'utf8').digest('hex');
}

function validDate(value) {
  return typeof value === 'string' && Number.isFinite(Date.parse(value));
}

/**
 * Verify a safe snapshot against a separately stored trusted digest.
 * The trusted digest must not come from the current/test policy file.
 */
export function verifySafePolicySnapshot(snapshot, trustedDigest) {
  if (!snapshot) fail('safe_policy_snapshot_missing');
  if (!isRecord(snapshot)) fail('safe_policy_snapshot_invalid');
  if (snapshot.schema !== SNAPSHOT_SCHEMA
      || typeof snapshot.version !== 'string' || !snapshot.version.trim()
      || !validDate(snapshot.verifiedAt) || !isRecord(snapshot.policy)) {
    fail('safe_policy_snapshot_invalid');
  }

  const expected = typeof trustedDigest === 'string' ? trustedDigest.trim().toLowerCase() : '';
  const declared = typeof snapshot.policySha256 === 'string'
    ? snapshot.policySha256.trim().toLowerCase() : '';
  const actual = policySha256(snapshot.policy);
  if (!SHA256.test(expected) || !SHA256.test(declared)
      || expected !== declared || actual !== expected) {
    fail('safe_policy_snapshot_verification_failed');
  }

  return {
    version: snapshot.version,
    policySha256: actual,
    policy: snapshot.policy,
  };
}

function pointerPart(value) {
  return String(value).replaceAll('~', '~0').replaceAll('/', '~1');
}

function compareValues(baseline, current, path, changes) {
  if (Object.is(baseline, current)) return;

  if (isRecord(baseline) && isRecord(current)) {
    const keys = [...new Set([...Object.keys(baseline), ...Object.keys(current)])].sort();
    for (const key of keys) {
      const childPath = `${path}/${pointerPart(key)}`;
      if (!Object.hasOwn(baseline, key)) changes.push({ path: childPath, kind: 'added' });
      else if (!Object.hasOwn(current, key)) changes.push({ path: childPath, kind: 'removed' });
      else compareValues(baseline[key], current[key], childPath, changes);
    }
    return;
  }

  if (Array.isArray(baseline) && Array.isArray(current)) {
    const length = Math.max(baseline.length, current.length);
    for (let index = 0; index < length; index += 1) {
      const childPath = `${path}/${index}`;
      if (index >= baseline.length) changes.push({ path: childPath, kind: 'added' });
      else if (index >= current.length) changes.push({ path: childPath, kind: 'removed' });
      else compareValues(baseline[index], current[index], childPath, changes);
    }
    return;
  }

  changes.push({ path: path || '/', kind: 'changed' });
}

/**
 * Produce a read-only restore preview. This function deliberately has no
 * policy-write or restore operation.
 */
export function previewPolicyChanges({ safeSnapshot, trustedDigest, currentPolicy, currentVersion = null } = {}) {
  const verified = verifySafePolicySnapshot(safeSnapshot, trustedDigest);
  if (!isRecord(currentPolicy)) fail('test_policy_missing');

  const changes = [];
  compareValues(verified.policy, currentPolicy, '', changes);
  const added = changes.filter(change => change.kind === 'added').length;
  const removed = changes.filter(change => change.kind === 'removed').length;
  const changed = changes.filter(change => change.kind === 'changed').length;

  return {
    schema: PREVIEW_SCHEMA,
    restoreVersion: verified.version,
    safePolicySha256: verified.policySha256,
    currentVersion: typeof currentVersion === 'string' ? currentVersion : null,
    changeScope: { added, removed, changed, total: changes.length },
    changes,
  };
}

function restorePlanDigest(plan) {
  return policySha256({
    schema: plan.schema,
    restoreVersion: plan.restoreVersion,
    safePolicySha256: plan.safePolicySha256,
    currentVersion: plan.currentVersion,
    currentPolicySha256: plan.currentPolicySha256,
    changeScope: plan.changeScope,
    changes: plan.changes,
    preservedTopLevel: plan.preservedTopLevel,
    confirmationRequired: plan.confirmationRequired,
  });
}

function prefixedChanges(changes) {
  return changes.map(change => ({
    path: change.path === '/' ? '/policy' : `/policy${change.path}`,
    kind: change.kind,
  }));
}

/**
 * Build a read-only restore plan for a test-policy envelope.
 *
 * The envelope keeps mutable test rules under `policy`. Every other top-level
 * field is deliberately preserved, including serviceRules and auditHistory.
 * The returned plan contains paths and counts, never policy values.
 */
export function createPolicyRestorePlan({
  safeSnapshot,
  trustedDigest,
  currentTestPolicy,
  currentVersion = null,
} = {}) {
  if (!isRecord(currentTestPolicy) || !isRecord(currentTestPolicy.policy)) {
    fail('test_policy_missing');
  }

  const preview = previewPolicyChanges({
    safeSnapshot,
    trustedDigest,
    currentPolicy: currentTestPolicy.policy,
    currentVersion,
  });
  const plan = {
    schema: RESTORE_PLAN_SCHEMA,
    restoreVersion: preview.restoreVersion,
    safePolicySha256: preview.safePolicySha256,
    currentVersion: preview.currentVersion,
    currentPolicySha256: policySha256(currentTestPolicy.policy),
    changeScope: preview.changeScope,
    changes: prefixedChanges(preview.changes),
    preservedTopLevel: Object.keys(currentTestPolicy)
      .filter(key => key !== 'policy')
      .sort(),
    confirmationRequired: true,
  };

  return { ...plan, planSha256: restorePlanDigest(plan) };
}

/**
 * Apply a previously displayed plan to a test-policy value in memory.
 *
 * This is intentionally a pure transformation: it returns a new envelope,
 * preserves every non-policy field, and has no production-policy writer.
 */
export function restoreTestPolicy({
  safeSnapshot,
  trustedDigest,
  currentTestPolicy,
  currentVersion = null,
  plan,
  confirmation = false,
} = {}) {
  const expectedPlan = createPolicyRestorePlan({
    safeSnapshot,
    trustedDigest,
    currentTestPolicy,
    currentVersion,
  });

  if (!isRecord(plan) || plan.planSha256 !== expectedPlan.planSha256) {
    fail('restore_plan_stale');
  }
  if (confirmation !== true) fail('restore_confirmation_required');

  const verified = verifySafePolicySnapshot(safeSnapshot, trustedDigest);
  if (verified.version !== expectedPlan.restoreVersion
      || verified.policySha256 !== expectedPlan.safePolicySha256) {
    fail('restore_plan_stale');
  }
  const restored = structuredClone(currentTestPolicy);
  restored.policy = structuredClone(verified.policy);
  return restored;
}
