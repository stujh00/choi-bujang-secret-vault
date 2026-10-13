import { randomUUID } from 'node:crypto';
import { appendFile, mkdir, readFile, rename, rm, writeFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { decide } from './decide.mjs';

const DEFAULT_ROOT = fileURLToPath(new URL('../', import.meta.url));
const SCHEMA = 'aleph.xdr.persistence.isolation-candidates.v1';
const ALERT_ID = /^ps-\d+$/;
const DEFAULT_TTL_MS = 15 * 60 * 1000;
const MAX_TTL_MS = 24 * 60 * 60 * 1000;
const BLOCK_REASONS = new Set([
  '서명 없는 신규·변경 서비스 지속성',
  '낯선 예약 작업의 임시 실행 파일',
  '비인가 시작 프로그램 및 예약 작업 연계',
]);

function timestamp(input) {
  const value = input instanceof Date ? input.getTime()
    : typeof input === 'number' ? input : Date.parse(input);
  return Number.isFinite(value) ? value : null;
}
function agentName(input) {
  return typeof input === 'string' && /^[a-z][a-z0-9._-]{1,127}$/i.test(input) ? input.toLowerCase() : null;
}
function validRule(r) {
  const created = timestamp(r?.createdAt),expires = timestamp(r?.expiresAt);
  return r && typeof r === 'object' && /^xdr-persistence-[0-9a-f-]{36}$/i.test(r.ruleId)
    && r.action === 'deny' && agentName(r.deviceName) !== null
    && BLOCK_REASONS.has(r.reason)
    && Array.isArray(r.evidenceAlertIds) && r.evidenceAlertIds.length > 0
    && r.evidenceAlertIds.every((id) => typeof id === 'string' && ALERT_ID.test(id))
    && created !== null && expires !== null && expires > created && expires - created <= MAX_TTL_MS;
}
async function maybeRead(path) {
  try { return await readFile(path, 'utf8'); }
  catch(e) { if(e?.code === 'ENOENT') return null; throw e; }
}
async function loadLog(path) {
  const contents = await maybeRead(path);
  return contents === null ? [] : contents.split(/\r?\n/).filter(Boolean).map((s) => JSON.parse(s));
}
async function loadRules(path) {
  const contents = await maybeRead(path);
  if(contents === null) return [];
  const store = JSON.parse(contents);
  if(store?.schema !== SCHEMA || !Array.isArray(store.rules) || !store.rules.every(validRule))
    throw new Error('invalid_rule_store');
  return store.rules;
}
async function saveRules(path,rules) {
  await mkdir(dirname(path),{recursive:true});
  const temp = path + '.' + randomUUID() + '.tmp';
  try {
    await writeFile(temp,JSON.stringify({schema:SCHEMA,rules},null,2) + '\n',{flag:'wx'});
    await rename(temp,path);
  } catch(e) {
    await rm(temp,{force:true}).catch(()=>{});
    throw e;
  }
}
function matchesDecision(alert,reported) {
  if(!reported || typeof reported !== 'object') return false;
  const expected=decide(alert);
  return expected.action === reported.action && expected.confidence === reported.confidence
    && expected.reason === reported.reason && Number.isFinite(reported.confidence)
    && reported.confidence>=0 && reported.confidence<=1
    && (reported.action !== 'block' || BLOCK_REASONS.has(reported.reason));
}

export async function respond(alert,reported,options={}) {
  const id=typeof alert?.id==='string' && ALERT_ID.test(alert.id) ? alert.id : null;
  if(id===null) return {action:'record',result:'invalid_alert_id',ruleCreated:false};
  if(!matchesDecision(alert,reported))
    return {alertId:id,action:'record',result:'invalid_decision',ruleCreated:false};
  const now=options.now===undefined?Date.now():
    timestamp(typeof options.now==='function'?options.now():options.now);
  const ttlMs=options.ttlMs===undefined?DEFAULT_TTL_MS:options.ttlMs;
  if(now===null || !Number.isSafeInteger(ttlMs) || ttlMs<1 || ttlMs>MAX_TTL_MS)
    return {alertId:id,action:reported.action,result:'invalid_clock_or_ttl',ruleCreated:false};
  const root=typeof options.root==='string'?options.root:DEFAULT_ROOT;
  const logPath=join(root,'alerts.log'),rulePath=join(root,'persistence','deny-rules.json');
  let existingLogs,rules;
  try{
    existingLogs=await loadLog(logPath);
    rules=await loadRules(rulePath);
  }catch{
    return {alertId:id,action:reported.action,result:'read_failed',ruleCreated:false};
  }
  if(existingLogs.some((log)=>log?.alertId===id))
    return {alertId:id,action:reported.action,result:'duplicate_alert',ruleCreated:false};

  const active=rules.filter((rule)=>timestamp(rule.expiresAt)>now);
  let status=reported.action==='alert'?'alert_only':'record_only';
  let created=false,updated=false;
  if(reported.action==='block' && BLOCK_REASONS.has(reported.reason)){
    const device=agentName(alert?.agent?.name);
    const protectedDevices=[
      ...(Array.isArray(options.protectedDevices)?options.protectedDevices:[]),
      ...(Array.isArray(options.exemptDevices)?options.exemptDevices:[]),
    ].map(agentName);
    if(!device || protectedDevices.includes(device)
      || (Array.isArray(options.protectedUsers)
        && options.protectedUsers.includes(alert?.data?.srcuser))){
      status='excluded_device_or_user';
    }else{
      const rule=active.find((item)=>item.deviceName===device);
      if(rule?.evidenceAlertIds.includes(id)) status='duplicate_rule';
      else if(rule){
        rule.evidenceAlertIds=[...rule.evidenceAlertIds,id];
        rule.confidence=Math.max(rule.confidence,reported.confidence);
        updated=true;status='rule_updated';
      }else{
        active.push({
          ruleId:'xdr-persistence-'+randomUUID(),
          action:'deny',
          deviceName:device,
          evidenceAlertIds:[id],
          confidence:reported.confidence,
          reason:reported.reason,
          createdAt:new Date(now).toISOString(),
          expiresAt:new Date(now+ttlMs).toISOString(),
        });
        created=true;status='rule_created';
      }
    }
  }
  // Audit before saving an isolation candidate; no network access or real ZTNA changes.
  try{
    await mkdir(dirname(logPath),{recursive:true});
    await appendFile(logPath,JSON.stringify({
      alertId:id,action:reported.action,confidence:reported.confidence,
      reason:reported.reason,result:status,at:new Date(now).toISOString(),
    })+'\n','utf8');
  }catch{
    return {alertId:id,action:reported.action,result:'log_write_failed_no_rule',ruleCreated:false};
  }
  if(created||updated){
    try{await saveRules(rulePath,active);}
    catch{return {alertId:id,action:reported.action,result:'rule_write_failed',ruleCreated:false};}
  }
  return {alertId:id,action:reported.action,result:status,ruleCreated:created,ruleUpdated:updated};
}

// Matches a simulated endpoint NAME, not an engine-verified deviceId.
// There is no trustworthy mapping to the current ZTNA request contract.
export function isDeniedByXdrRules(deviceName,ruleSet,now=new Date(),options={}) {
  const device=agentName(deviceName),at=timestamp(now);
  const items=Array.isArray(ruleSet)?ruleSet:ruleSet?.rules;
  if(!device || at===null || !Array.isArray(items)
     || (Array.isArray(options.protectedDevices) && options.protectedDevices.map(agentName).includes(device))) return false;
  return items.some((r)=>validRule(r) && r.deviceName===device
     && timestamp(r.createdAt)<=at && at<timestamp(r.expiresAt));
}
