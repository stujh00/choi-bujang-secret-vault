import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { POLICY_BASELINE, previewVerifiedPolicy } from '../src/stage10-policy-preview.mjs';

const root = resolve(import.meta.dirname, '..');
try {
  const snapshotSource = execFileSync('git', [
    '-C', root, 'show', `${POLICY_BASELINE.commit}:${POLICY_BASELINE.path}`,
  ], { encoding: 'utf8', timeout: 10000, maxBuffer: 256 * 1024 });
  const currentSource = readFileSync(resolve(root, POLICY_BASELINE.path), 'utf8');
  const preview = previewVerifiedPolicy({ snapshotSource, currentSource });
  process.stdout.write(JSON.stringify(preview, null, 2) + '\n');
  process.stderr.write('주의: 이 결과는 GitHub 저장소 정책 코드 비교이며 외부 심판의 시험 정책 복원을 증명하지 않습니다.\n');
} catch (error) {
  process.stderr.write(`POLICY_PREVIEW_ABORTED: ${error.message}\n`);
  process.exitCode = 1;
}
