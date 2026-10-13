import { readFile, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import {
  createPolicyRestorePlan,
  restoreTestPolicy,
} from '../src/policy-preview.mjs';

async function readJson(path) {
  return JSON.parse(await readFile(resolve(path), 'utf8'));
}

async function readRestoreInputs(snapshotPath, digestPath, currentPath) {
  // Read all three inputs from disk as one restore attempt. The confirmed
  // attempt calls this again immediately before writing the test policy.
  const [safeSnapshot, trustedDigest, currentTestPolicy] = await Promise.all([
    readJson(snapshotPath),
    readFile(resolve(digestPath), 'utf8').then(value => value.trim()),
    readJson(currentPath),
  ]);
  return { safeSnapshot, trustedDigest, currentTestPolicy };
}

const [snapshotPath, digestPath, currentPath, ...options] = process.argv.slice(2);
const confirmIndex = options.indexOf('--confirm');
const confirmation = confirmIndex >= 0 ? options[confirmIndex + 1] : undefined;
const validOptions = confirmIndex < 0
  ? options.length === 0
  : confirmIndex === 0 && options.length === 2 && Boolean(confirmation);

if (!snapshotPath || !digestPath || !currentPath
    || !validOptions) {
  process.stderr.write('사용법: npm run policy:restore -- <safe-snapshot.json> <trusted-sha256.txt> <test-policy.json> [--confirm <plan-sha256>]\n');
  process.exit(1);
}

try {
  const initialInputs = await readRestoreInputs(snapshotPath, digestPath, currentPath);
  const plan = createPolicyRestorePlan(initialInputs);

  if (confirmIndex < 0) {
    process.stdout.write(`${JSON.stringify(plan, null, 2)}\n`);
    process.stdout.write('복원 대기: 위 변경 범위를 확인한 뒤 planSha256을 --confirm 값으로 다시 전달하세요.\n');
    process.exit(0);
  }

  if (confirmation !== plan.planSha256) {
    process.stderr.write('정책 복원 중단: restore_plan_mismatch\n');
    process.exit(1);
  }

  // Never restore from the object that produced the preview. Re-read and
  // re-verify the safe snapshot, trusted digest, and current test policy.
  // Any change (including a changed snapshot version or policy contents)
  // invalidates the displayed confirmation before a write can happen.
  const rereadInputs = await readRestoreInputs(snapshotPath, digestPath, currentPath);
  const rereadPlan = createPolicyRestorePlan(rereadInputs);
  if (rereadPlan.planSha256 !== plan.planSha256) {
    process.stderr.write('정책 복원 중단: restore_plan_stale\n');
    process.exit(1);
  }

  const restored = restoreTestPolicy({
    ...rereadInputs,
    plan: rereadPlan,
    confirmation: true,
  });
  await writeFile(resolve(currentPath), `${JSON.stringify(restored, null, 2)}\n`, 'utf8');
  process.stdout.write(`시험 정책 복원 완료: ${plan.restoreVersion}\n`);
} catch (error) {
  process.stderr.write(`정책 복원 중단: ${error.code ?? 'policy_restore_failed'}\n`);
  process.exitCode = 1;
}
