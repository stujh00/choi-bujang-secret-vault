import { createHash } from 'node:crypto';
import { POLICY_BASELINE, previewVerifiedPolicy, gitBlobSha1 } from './stage10-policy-preview.mjs';

// An adapter for a *test* policy only. No production policy or audit API is called.
export function planTestPolicyRestore({ backupSource, testPolicySource, baseline = POLICY_BASELINE } = {}) {
  const preview = previewVerifiedPolicy({
    snapshotSource: backupSource,
    currentSource: testPolicySource,
    baseline,
  });
  const approvalCode = createHash('sha256').update(JSON.stringify({
    scope: 'isolated_test_policy_only',
    baselineCommit: preview.baselineCommit,
    baselineSha: preview.baselineBlobSha1,
    currentSha: preview.currentBlobSha1,
    changedHunks: preview.changedHunks,
  })).digest('hex');
  return Object.freeze({
    ...preview,
    scope: 'isolated_test_policy_only',
    approvalCode,
    writes: preview.changedHunks > 0 ? [baseline.path] : [],
    willModifyExternalJudgePolicy: false,
    willModifyProductionPolicy: false,
    willModifyAuditHistory: false,
  });
}

export async function applyTestPolicyRestore({
  backupSource, baseline = POLICY_BASELINE, plan, approvalCode,
  readTestPolicy, writeTestPolicy,
} = {}) {
  if (!plan || typeof readTestPolicy !== 'function' || typeof writeTestPolicy !== 'function') {
    throw new Error('POLICY_RESTORE_ADAPTER_MISSING');
  }
  if (typeof approvalCode !== 'string' || approvalCode !== plan.approvalCode) {
    throw new Error('POLICY_RESTORE_NOT_APPROVED');
  }
  const current = await readTestPolicy();
  const fresh = planTestPolicyRestore({ backupSource, testPolicySource: current, baseline });
  if (fresh.approvalCode !== plan.approvalCode
      || fresh.baselineBlobSha1 !== plan.baselineBlobSha1
      || fresh.currentBlobSha1 !== plan.currentBlobSha1) {
    throw new Error('POLICY_RESTORE_PLAN_STALE');
  }
  if (fresh.changedHunks === 0) {
    return Object.freeze({ status: 'already_safe', changed: false, policySha1: fresh.baselineBlobSha1 });
  }
  await writeTestPolicy(backupSource);
  const after = await readTestPolicy();
  if (gitBlobSha1(after) !== fresh.baselineBlobSha1) {
    throw new Error('POLICY_RESTORE_POSTCHECK_FAILED');
  }
  return Object.freeze({ status: 'test_policy_restored', changed: true, policySha1: fresh.baselineBlobSha1 });
}
