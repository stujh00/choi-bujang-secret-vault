import { createHash } from 'node:crypto';

// Stage 9 was committed before stage 10 recovery work began.
// This protects only the repository policy source, NOT an external SDP test policy.
export const POLICY_BASELINE = Object.freeze({
  commit: '05fbd654883542268ee2727af8534d01ed3753bb',
  path: 'src/decider.mjs',
  blobSha1: '3ffce49819c09b56cc783604fee788e5f776f68a',
});

export function gitBlobSha1(content) {
  if (typeof content !== 'string') throw new TypeError('INVALID_POLICY_SOURCE');
  const bytes = Buffer.from(content, 'utf8');
  return createHash('sha1').update(`blob ${bytes.length}\0`).update(bytes).digest('hex');
}

function changesBetween(before, after) {
  const oldLines = before.split('\n');
  const newLines = after.split('\n');
  const n = oldLines.length;
  const m = newLines.length;
  if (n * m > 1000000) throw new Error('POLICY_DIFF_TOO_LARGE');
  const lengths = Array.from({ length: n + 1 }, () => new Uint32Array(m + 1));
  for (let i = n - 1; i >= 0; i--) {
    for (let j = m - 1; j >= 0; j--) {
      lengths[i][j] = oldLines[i] === newLines[j]
        ? lengths[i + 1][j + 1] + 1
        : Math.max(lengths[i + 1][j], lengths[i][j + 1]);
    }
  }
  const hunks = [];
  let i = 0, j = 0, pending = null;
  const finish = () => {
    if (pending) { hunks.push(pending); pending = null; }
  };
  while (i < n || j < m) {
    if (i < n && j < m && oldLines[i] === newLines[j]) {
      finish(); i++; j++;
      continue;
    }
    pending ??= { previousLine: i + 1, currentLine: j + 1, removed: [], added: [] };
    if (i < n && (j === m || lengths[i + 1][j] >= lengths[i][j + 1])) {
      pending.removed.push(oldLines[i++]);
    } else {
      pending.added.push(newLines[j++]);
    }
  }
  finish();
  return hunks;
}

// Read-only preview. Reject missing/tampered snapshots before any comparison.
// Never mutate policy files, other services or audit history.
export function previewVerifiedPolicy({ snapshotSource, currentSource, baseline = POLICY_BASELINE } = {}) {
  if (typeof snapshotSource !== 'string' || !snapshotSource.length) {
    throw new Error('POLICY_BACKUP_MISSING');
  }
  if (!baseline || !/^[a-f0-9]{40}$/.test(baseline.blobSha1 ?? '')
      || gitBlobSha1(snapshotSource) !== baseline.blobSha1) {
    throw new Error('POLICY_BACKUP_UNVERIFIED');
  }
  if (typeof currentSource !== 'string' || !currentSource.length) {
    throw new Error('CURRENT_TEST_POLICY_MISSING');
  }
  const changes = changesBetween(snapshotSource, currentSource);
  return Object.freeze({
    mode: 'read_only_preview',
    scope: 'repository_policy_source_only',
    externalTestPolicyVerified: false,
    baselineCommit: baseline.commit,
    baselineBlobSha1: baseline.blobSha1,
    currentBlobSha1: gitBlobSha1(currentSource),
    changedHunks: changes.length,
    changedLines: changes.reduce((sum, h) => sum + h.removed.length + h.added.length, 0),
    changes,
  });
}
