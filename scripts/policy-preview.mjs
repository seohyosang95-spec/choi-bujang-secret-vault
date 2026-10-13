import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { previewPolicyChanges } from '../src/policy-preview.mjs';

async function readJson(path) {
  return JSON.parse(await readFile(resolve(path), 'utf8'));
}

const [snapshotPath, digestPath, currentPath] = process.argv.slice(2);
if (!snapshotPath || !digestPath || !currentPath) {
  process.stderr.write('사용법: npm run policy:preview -- <safe-snapshot.json> <trusted-sha256.txt> <test-policy.json>\n');
  process.exit(1);
}

try {
  const safeSnapshot = await readJson(snapshotPath);
  const trustedDigest = (await readFile(resolve(digestPath), 'utf8')).trim();
  const currentPolicy = await readJson(currentPath);
  const preview = previewPolicyChanges({ safeSnapshot, trustedDigest, currentPolicy });
  process.stdout.write(`${JSON.stringify(preview, null, 2)}\n`);
} catch (error) {
  process.stderr.write(`정책 미리보기 중단: ${error.code ?? 'policy_preview_failed'}\n`);
  process.exitCode = 1;
}
