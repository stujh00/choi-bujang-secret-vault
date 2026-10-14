import {readFileSync,writeFileSync,mkdirSync,renameSync} from 'node:fs';
import {fileURLToPath} from 'node:url';
import {resolve} from 'node:path';
import {sha256,equalDigest} from '../src/restore-backup.mjs';

const root=fileURLToPath(new URL('../',import.meta.url));
export function verifiedSnapshot(projectRoot=root) {
  const raw=readFileSync(resolve(projectRoot,'backups/step10/safe-policy.json'),'utf8').replace(/\r\n/g,'\n');
  const digest=readFileSync(resolve(projectRoot,'backups/step10/safe-policy.sha256'),'utf8').trim().split(/\s+/)[0];
  if(!equalDigest(sha256(raw),digest)) throw new Error('safe policy snapshot digest mismatch');
  const snapshot=JSON.parse(raw);
  if(snapshot.schema!=='vault.safe-policy.v1'||!/^[-a-zA-Z0-9._]{1,80}$/.test(snapshot.version??'')
      ||snapshot.sourcePath!=='src/decider.mjs'||typeof snapshot.source!=='string'
      ||!snapshot.source.includes('export async function decide('))
    throw new Error('invalid safe policy snapshot');
  return snapshot;
}
export function restorePlan(projectRoot=root) {
  const snapshot=verifiedSnapshot(projectRoot);
  const current=readFileSync(resolve(projectRoot,snapshot.sourcePath),'utf8');
  const before=current.split('\n'),after=snapshot.source.split('\n');
  const differences=[];
  for(let i=0;i<Math.max(before.length,after.length);i++)
    if(before[i]!==after[i]) differences.push({line:i+1,current:before[i]??null,safe:after[i]??null});
  return {version:snapshot.version,verified:true,oldPolicySha256:sha256(current),safePolicySha256:sha256(snapshot.source),
    changed:current!==snapshot.source,differences,scope:[snapshot.sourcePath],
    protected:['auditHistory','other service rules','notes','authentication configuration']};
}
export function restoreApply(version,projectRoot=root) {
  // Re-read both backup and current source immediately before applying.
  const plan=restorePlan(projectRoot),snapshot=verifiedSnapshot(projectRoot);
  if(version!==plan.version) throw new Error('explicit --confirm='+plan.version+' required');
  const reviewed=JSON.parse(readFileSync(resolve(projectRoot,'artifacts/policy-restore-plan.json'),'utf8'));
  if(reviewed.version!==plan.version||reviewed.oldPolicySha256!==plan.oldPolicySha256
      ||reviewed.safePolicySha256!==plan.safePolicySha256)
    throw new Error('policy changed since review; run restore:plan again');
  if(plan.changed) {
    const destination=resolve(projectRoot,snapshot.sourcePath),temporary=destination+'.verified-tmp';
    writeFileSync(temporary,snapshot.source,{flag:'wx'});renameSync(temporary,destination);
  }
  const record={version:plan.version,verified:true,applied:true,changed:plan.changed,scope:plan.scope,
    beforeSha256:plan.oldPolicySha256,afterSha256:plan.safePolicySha256,completedAt:new Date().toISOString()};
  writeFileSync(resolve(projectRoot,'artifacts/policy-restore-result.json'),JSON.stringify(record,null,2)+'\n');
  return record;
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url)) {
  try {
    const plan=restorePlan();
    console.log(JSON.stringify(plan,null,2));
    mkdirSync(resolve(root,'artifacts'),{recursive:true});
    if(process.argv.includes('--apply')) {
      const confirm=process.argv.find(arg=>arg.startsWith('--confirm='))?.slice('--confirm='.length);
      console.log(JSON.stringify(restoreApply(confirm),null,2));
    } else writeFileSync(resolve(root,'artifacts/policy-restore-plan.json'),JSON.stringify(plan,null,2)+'\n');
  } catch {console.error('Policy restore stopped: backup verification, reviewed plan, or version confirmation failed.');process.exitCode=1;}
}
