import assert from 'node:assert/strict';
import { test } from 'node:test';
import { gitBlobSha1 } from '../src/stage10-policy-preview.mjs';
import { planTestPolicyRestore, applyTestPolicyRestore } from '../src/stage10-policy-restore.mjs';

const backup = 'allow: own note\ndeny: foreign note\n';
const changed = 'allow: own note\nallow: foreign note\n';
const baseline = { path: 'src/decider.mjs', commit: 'test-old-commit', blobSha1: gitBlobSha1(backup) };
const args = (policy) => ({ backupSource: backup, testPolicySource: policy, baseline });

test('preview lists exact changes and original version, does not change policy', () => {
  const p = planTestPolicyRestore(args(changed));
  assert.equal(p.baselineCommit,'test-old-commit');
  assert.deepEqual(p.writes,['src/decider.mjs']);
  assert.equal(p.changes[0].removed[0],'deny: foreign note');
  assert.equal(p.willModifyExternalJudgePolicy,false);
});
test('explicit approval restores only isolated test policy; unrelated rules and audit preserved', async () => {
  const store = { testPolicy: changed, otherService: 'unchanged', audit: ['before'] };
  const plan = planTestPolicyRestore(args(store.testPolicy));
  const result = await applyTestPolicyRestore({ backupSource: backup, baseline, plan, approvalCode: plan.approvalCode,
    readTestPolicy: async () => store.testPolicy, writeTestPolicy: async v => { store.testPolicy = v; } });
  assert.equal(result.status,'test_policy_restored');
  assert.equal(store.testPolicy,backup);
  assert.equal(store.otherService,'unchanged');
  assert.deepEqual(store.audit,['before']);
});
test('missing approval and stale test policy cannot mutate anything', async () => {
  const store = { value: changed, writes: 0 };
  const plan = planTestPolicyRestore(args(store.value));
  const common = { backupSource:backup, baseline, plan,
    readTestPolicy: async()=>store.value, writeTestPolicy:async v=>{ store.value=v;store.writes++; }};
  await assert.rejects(applyTestPolicyRestore({ ...common, approvalCode:'wrong' }), /POLICY_RESTORE_NOT_APPROVED/);
  store.value += 'injected rule\n';
  await assert.rejects(applyTestPolicyRestore({ ...common, approvalCode:plan.approvalCode }), /POLICY_RESTORE_PLAN_STALE/);
  assert.equal(store.writes,0);
});
test('missing, tampered or unverified backups fail closed', () => {
  assert.throws(()=>planTestPolicyRestore({testPolicySource:changed,baseline}), /POLICY_BACKUP_MISSING/);
  assert.throws(()=>planTestPolicyRestore({ backupSource:'forged',testPolicySource:changed,baseline }), /POLICY_BACKUP_UNVERIFIED/);
});
test('already-safe policy does not invoke writes', async () => {
  const plan = planTestPolicyRestore(args(backup));
  let writes = 0;
  const result = await applyTestPolicyRestore({ backupSource:backup, baseline, plan, approvalCode:plan.approvalCode,
    readTestPolicy:async()=>backup, writeTestPolicy:async()=>{writes++;} });
  assert.equal(result.status,'already_safe'); assert.equal(writes,0);
});
test('post-restore verification detects unsuccessful write', async () => {
  const plan = planTestPolicyRestore(args(changed));
  await assert.rejects(applyTestPolicyRestore({ backupSource:backup, baseline, plan, approvalCode:plan.approvalCode,
    readTestPolicy:async()=>changed, writeTestPolicy:async()=>{} }),/POLICY_RESTORE_POSTCHECK_FAILED/);
});
