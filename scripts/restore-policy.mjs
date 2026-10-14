import {readFileSync, writeFileSync, mkdirSync, renameSync} from 'node:fs';
import {createHash, timingSafeEqual} from 'node:crypto';
import {resolve} from 'node:path';
import {fileURLToPath} from 'node:url';

const projectRoot=new URL('../',import.meta.url);
const snapshotUrl=new URL('../backups/step10/safe-policy.json',import.meta.url);
const checksumUrl=new URL('../backups/step10/safe-policy.sha256',import.meta.url);
const policyUrl=new URL('../src/decider.mjs',import.meta.url);
function sha(buffer){return createHash('sha256').update(buffer).digest('hex');}
function verifiedSnapshot(){
 const bytes=readFileSync(snapshotUrl);
 const expected=readFileSync(checksumUrl,'utf8').trim().split(/\s+/)[0];
 if(!/^[0-9a-f]{64}$/i.test(expected)||
    !timingSafeEqual(Buffer.from(sha(bytes),'hex'),Buffer.from(expected,'hex')))
   throw new Error('safe policy snapshot digest mismatch');
 const p=JSON.parse(bytes.toString('utf8'));
 if(p.schema!=='vault.safe-policy.v1'||p.version!=='step9-reviewed'
   ||p.sourcePath!=='src/decider.mjs'||typeof p.source!=='string'
   ||!p.source.includes('export async function decide('))
   throw new Error('invalid safe policy snapshot');
 return p;
}
const policy=verifiedSnapshot();
const actual=readFileSync(policyUrl,'utf8');
const plan={
 version:policy.version,
 verified:true,
 oldPolicySha256:sha(Buffer.from(actual)),
 safePolicySha256:sha(Buffer.from(policy.source)),
 changed:actual!==policy.source,
 scope:['src/decider.mjs'],
 protected:['auditHistory','Supabase database','1~9단계 메모','인증키','보너스 XDR'],
};
if(process.argv[1]?.endsWith('restore-policy.mjs')){
 const apply=process.argv.includes('--apply');
 if(!apply) console.log(JSON.stringify(plan,null,2));
 else{
  if(!process.argv.includes('--confirm='+policy.version))
   throw new Error('explicit --confirm='+policy.version+' required');
  // Do not overwrite more than one target file; no deletion of audit logs.
  if(plan.changed){
    const dst=fileURLToPath(policyUrl);
    const temp=dst+'.verified-tmp';
    writeFileSync(temp,policy.source,{flag:'wx'});
    renameSync(temp,dst);
  }
  const folder=fileURLToPath(new URL('../artifacts/',import.meta.url));
  mkdirSync(folder,{recursive:true});
  const record={...plan,applied:true,completedAt:new Date().toISOString()};
  writeFileSync(resolve(folder,'policy-restore-result.json'),JSON.stringify(record,null,2)+'\n');
  console.log(JSON.stringify({version:record.version,applied:true,scope:record.scope,changed:record.changed}));
 }
}
export {verifiedSnapshot};
