import assert from 'node:assert/strict';
import { test } from 'node:test';
import { gitBlobSha1, previewVerifiedPolicy } from '../src/stage10-policy-preview.mjs';

const verified = 'allow: own note\ndeny: foreign note\n';
const baseline = { commit: 'test-baseline', blobSha1: gitBlobSha1(verified) };
const run = (snapshotSource, currentSource = verified) =>
  previewVerifiedPolicy({ snapshotSource, currentSource, baseline });

test('verified unchanged source returns zero changes without modifying inputs', () => {
  const result = run(verified);
  assert.equal(result.changedHunks, 0);
  assert.equal(result.changedLines, 0);
  assert.equal(result.mode, 'read_only_preview');
  assert.equal(result.externalTestPolicyVerified, false);
});
test('shows only the changed policy lines and baseline commit', () => {
  const result = run(verified, 'allow: own note\nallow: foreign note\n');
  assert.equal(result.baselineCommit, 'test-baseline');
  assert.equal(result.changedHunks, 1);
  assert.deepEqual(result.changes[0].removed, ['deny: foreign note']);
  assert.deepEqual(result.changes[0].added, ['allow: foreign note']);
});
test('rejects missing or invalid source snapshots', () => {
  assert.throws(() => run(undefined), /POLICY_BACKUP_MISSING/);
  assert.throws(() => run('tampered'), /POLICY_BACKUP_UNVERIFIED/);
});
test('rejects missing current policy and forged snapshot checksum', () => {
  assert.throws(() => run(verified, ''), /CURRENT_TEST_POLICY_MISSING/);
  assert.throws(() => previewVerifiedPolicy({
    snapshotSource: verified, currentSource: verified,
    baseline: { commit: 'test', blobSha1: '0'.repeat(40) },
  }), /POLICY_BACKUP_UNVERIFIED/);
});
