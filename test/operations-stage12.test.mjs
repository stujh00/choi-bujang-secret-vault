import test from 'node:test';
import assert from 'node:assert/strict';
import {operationsReport} from '../src/operations-room.mjs';
import handler from '../api/operations.js';
import {appendAudit,getAuditHistory,recordCheck} from '../src/restore-state.mjs';

test('operations executes real server fixtures, retains honest live and judge gaps',async()=>{
 const audit=appendAudit({ownerId:'private-owner',id:'private-id',action:'restore',result:'ok',status:200});
 recordCheck('note_restore',{status:'measured',passed:true,httpStatus:200});
 const report=await operationsReport();
 assert.equal(report.schema,'vault.operations.v1');
 assert.equal(report.decision.results.length,6);
 assert.ok(report.decision.results.every(x=>x.passed&&x.status==='measured'&&x.requestId&&x.checkedAt));
 assert.ok(report.detection.results.every(x=>x.passed));
 assert.equal(report.assault.measured,0);assert.equal(report.assault.notRun,41);
 assert.equal(report.revocation.status,'not_run');
 assert.ok(report.regression.filter(x=>x.scope==='live_api').every(x=>x.status==='not_run'&&x.actual===null));
 assert.equal(report.restore.status,'measured');
 const serialized=JSON.stringify(report);assert.ok(!serialized.includes('private-owner'));assert.ok(!serialized.includes('private-id'));
 assert.equal(getAuditHistory('private-owner').at(-1).eventId,audit);
});
test('operations GET returns metadata; mutation is rejected',async()=>{
 const res={headers:{},setHeader(k,v){this.headers[k]=v;},status(code){this.code=code;return this;},json(body){this.body=body;return this;}};
 await handler({method:'POST'},res);assert.equal(res.code,405);
 await handler({method:'GET'},res);assert.equal(res.code,200);assert.equal(res.headers['Cache-Control'],'no-store');
 assert.equal(res.body.regression.length,19);
});
