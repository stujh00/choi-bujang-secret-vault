import {test} from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync,mkdirSync,copyFileSync,writeFileSync,readFileSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {restorePlan,restoreApply} from '../scripts/restore-policy.mjs';
import {appendAudit,getAuditHistory} from '../src/restore-state.mjs';

test('policy apply re-verifies reviewed snapshot, requires exact version, preserves other files and audit',()=>{
 const root=mkdtempSync(join(tmpdir(),'vault-policy-'));
 try {
  for(const dir of ['src','backups/step10','artifacts'])mkdirSync(join(root,dir),{recursive:true});
  for(const file of ['backups/step10/safe-policy.json','backups/step10/safe-policy.sha256','src/decider.mjs'])
    copyFileSync(new URL('../'+file,import.meta.url),join(root,file));
  const source=readFileSync(join(root,'src/decider.mjs'),'utf8');
  writeFileSync(join(root,'src/decider.mjs'),source+'\n// changed test policy\n');
  writeFileSync(join(root,'src/other-service.mjs'),'preserved');
  const owner='policy-test-owner';appendAudit({ownerId:owner,id:'policy',action:'test',result:'before',status:200});
  const audit=getAuditHistory(owner),plan=restorePlan(root);
  assert.equal(plan.changed,true);assert.ok(plan.differences.length);
  writeFileSync(join(root,'artifacts/policy-restore-plan.json'),JSON.stringify(plan));
  assert.throws(()=>restoreApply('wrong',root));
  const result=restoreApply(plan.version,root);assert.equal(result.applied,true);
  assert.equal(readFileSync(join(root,'src/decider.mjs'),'utf8').replace(/\r\n/g,'\n'),source.replace(/\r\n/g,'\n'));
  assert.equal(readFileSync(join(root,'src/other-service.mjs'),'utf8'),'preserved');
  assert.deepEqual(getAuditHistory(owner),audit);
  writeFileSync(join(root,'backups/step10/safe-policy.json'),'{}');
  assert.throws(()=>restorePlan(root));assert.throws(()=>restoreApply(plan.version,root));
 } finally {rmSync(root,{recursive:true,force:true});}
});

test('step10 bundle check performs only GET/HEAD and reports mutation check not_run',async()=>{
 const {runAttackChecks}=await import('../src/attack-check.mjs');
 const config=JSON.parse(readFileSync(new URL('../aleph.config.json',import.meta.url),'utf8'));
 const original=globalThis.fetch,methods=[];
 globalThis.fetch=async(url,options={})=>{
  const method=options.method??'GET';methods.push(method);
  assert.ok(['GET','HEAD'].includes(method));
  const path=new URL(url).pathname;
  if(path==='/data.json')return Response.json({notes:[]});
  if(path==='/aleph.json')return Response.json({step:10});
  if(path==='/')return new Response('<main>Vault</main>');
  return new Response(null,{status:403});
 };
 try {
  const results=await runAttackChecks(config);
  assert.ok(results.find(x=>x.attackId==='anonymous_source_api_update').observed.includes('not_run'));
  assert.ok(methods.every(method=>method==='GET'||method==='HEAD'));
 }finally{globalThis.fetch=original;}
});
