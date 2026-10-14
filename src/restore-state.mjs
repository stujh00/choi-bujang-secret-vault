import {randomUUID} from 'node:crypto';

// Share state across module reloads within this server runtime. Restore never clears it.
const slot=Symbol.for('vault.step10.append-only.v2');
if(!globalThis[slot]) Object.defineProperty(globalThis,slot,{value:{auditHistory:[],checks:[]}});
const state=globalThis[slot];
export function appendAudit({ownerId,id,action,result,status}) {
  const entry=Object.freeze({eventId:randomUUID(),time:new Date().toISOString(),ownerId,id,action,result,status});
  state.auditHistory.push(entry);
  return entry.eventId;
}
export function getAuditHistory(ownerId) {
  return state.auditHistory.filter(entry=>entry.ownerId===ownerId)
    .map(({ownerId:_,...safe})=>({...safe}));
}
export function recordCheck(name,{status,passed,httpStatus=null}={}) {
  state.checks.push(Object.freeze({name,status,passed,httpStatus,time:new Date().toISOString()}));
}
export function getOperations() {
  return ['backup_sha256','note_restore','own_read','other_read_denied'].map(name=>{
    const evidence=state.checks.filter(check=>check.name===name);
    return {name,status:evidence.length?evidence.at(-1).status:'not_run',evidence:evidence.map(check=>({...check}))};
  });
}
