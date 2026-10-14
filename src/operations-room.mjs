import { randomUUID, createHash, timingSafeEqual } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { RULE_IDS, decide } from './decider.mjs';
import { detect } from './detect.mjs';
import { fixtureRequests } from '../scripts/fixture-7.mjs';
import { getOperations } from './restore-state.mjs';

// Only allowlisted metadata is returned. No runtime audit identities or note bodies.
export async function operationsReport() {
  const requestId = randomUUID();
  const checkedAt = new Date().toISOString();
  const { normal, suspicious } = fixtureRequests();
  const scenarios = [
    ['registered_read', normal, 'allow'],
    ['unregistered_read', {...normal, deviceRegistered:false}, 'deny'],
    ['suspicious_read', suspicious, 'step_up'],
    ['reauthenticated_read', {...suspicious, stepUp:{verified:true,authAgeSeconds:60}}, 'allow'],
    ['outside_zone', {...normal, route:'GET /notes',path:'/notes'}, 'deny'],
    ['unsigned_write', {...normal, method:'PUT',route:'PUT /notes/:id'}, 'deny'],
  ];
  const results = [];
  for(const [name,input,expected] of scenarios) {
    const id = randomUUID();
    const actual = await decide({...input,requestId:id});
    results.push({name,scope:'server_fixture',status:'measured',expected,
      actual:actual.decision,passed:actual.decision===expected,requestId:id,checkedAt,
      ruleIds:actual.ruleIds.filter(id=>RULE_IDS.includes(id))});
  }
  const event = (index)=>({at:new Date(Date.UTC(2026,9,1)+index*2000).toISOString(),method:'GET',identity:{sub:'learner_fixture'}});
  const detections = [30,121].map(count=>{
    const output=detect(Array.from({length:count},(_,i)=>event(i)));
    return {name:'reads_'+count,scope:'server_fixture',status:'measured',expected:count===30?'observe':'propose_revocation',
      actual:output.action,passed:output.action===(count===30?'observe':'propose_revocation'),requestId:randomUUID(),checkedAt};
  });
  const checks=[...getOperations(),{name:'policy_restore_in_this_runtime',status:'not_run',evidence:[]},{name:'stage1_to9_full_live_regression',status:'not_run',evidence:[]}].map(row=>({name:row.name,status:row.status,evidence:row.evidence.map(e=>({
    status:e.status,passed:e.passed,httpStatus:e.httpStatus,checkedAt:e.time
  }))}));
  let policyBackup={status:'not_run',version:null};
  try {
    const raw=await readFile(new URL('../backups/step10/safe-policy.json',import.meta.url));
    const claimed=(await readFile(new URL('../backups/step10/safe-policy.sha256',import.meta.url),'utf8')).trim().split(/\s/)[0];
    const actual=createHash('sha256').update(raw).digest();
    if(!/^[a-f0-9]{64}$/i.test(claimed)||!timingSafeEqual(actual,Buffer.from(claimed,'hex')))throw new Error('hash');
    const backup=JSON.parse(raw.toString('utf8'));
    policyBackup={status:'measured',verified:true,version:backup.version,contentSha256:actual.toString('hex'),checkedAt};
  }catch{policyBackup={status:'measured',verified:false,version:null,checkedAt};}
  return {schema:'vault.operations.v1',requestId,checkedAt,commit:process.env.VERCEL_GIT_COMMIT_SHA??null,
    policyRules:[...RULE_IDS],checks,
    decision:{status:'measured',scope:'server_fixture',results},
    detection:{status:'measured',scope:'server_fixture',results:detections},
    revocation:{status:'not_run',reason:'Engine enforcement is not observed by this server; a proposal is not a revocation.'},
    restore:{version:policyBackup.version,policyBackup,status:checks.find(x=>x.name==='note_restore')?.status??'not_run',
      policyApply:{status:'not_run',reason:'CLI artifact is not runtime evidence'}},
    regression:[...results,...detections,...Array.from({length:11},(_,i)=>({
      name:'stage_'+(i+1)+'_live',scope:'live_api',status:'not_run',expected:'Normal request allowed; forbidden request denied',actual:null,requestId:null,checkedAt:null
    }))],
    assault:{total:41,measured:0,notRun:41,status:'not_run',source:'judge',
      reason:'The engine attack catalogue and judge results have not been imported; local fixtures are not the 41 attacks.'}};
}
