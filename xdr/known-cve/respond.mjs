import { randomUUID } from 'node:crypto';
import { appendFile, mkdir, readFile, rename, rm, writeFile } from 'node:fs/promises';
import { isIP } from 'node:net';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { decide } from './decide.mjs';

const ROOT = fileURLToPath(new URL('../', import.meta.url));
const SCHEMA = 'aleph.xdr.known-cve.deny-rules.v1';
const TTL = 900000;
const MAX_TTL = 86400000;
const ID = /^kc-\d+$/;
const BLOCK = new Set(['JNDI 머리글 원격 조회 구문', 'JNDI URL 인자 원격 조회 구문']);

function time(value) {
  const n = value instanceof Date ? value.getTime() :
    typeof value === 'number' ? value : Date.parse(value);
  return Number.isFinite(n) ? n : null;
}
function ipOf(value) {
  if (typeof value !== 'string') return null;
  const ip = value.trim().toLowerCase();
  return isIP(ip) > 0 && !ip.includes('%') && !ip.startsWith('::ffff:') ? ip : null;
}
function docIp(ip) {
  if (isIP(ip) === 4) return /^(?:192\.0\.2|198\.51\.100|203\.0\.113)\./.test(ip);
  return /^2001:(?:db8|0db8)(?::|$)/.test(ip);
}
function protectedIp(ip, opts = {}) {
  const exceptions = [...(Array.isArray(opts.exemptIps) ? opts.exemptIps : []),
    ...(Array.isArray(opts.protectedIps) ? opts.protectedIps : [])];
  if (exceptions.some((x) => ipOf(x) === ip)) return true;
  if (docIp(ip)) return opts.allowDocumentationIps !== true;
  if (isIP(ip) === 4) {
    const [a,b] = ip.split('.').map(Number);
    return a === 0 || a === 10 || a === 127 || a >= 224 ||
      (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && b === 168) || (a === 100 && b >= 64 && b <= 127);
  }
  return ip === '::' || ip === '::1' || /^(fc|fd|fe8|fe9|fea|feb|ff)/.test(ip);
}
function validRule(r) {
  return r && r.action === 'deny' && /^xdr-known-cve-[0-9a-f-]{36}$/i.test(r.ruleId) &&
    ipOf(r.sourceIp) !== null && BLOCK.has(r.reason) &&
    Array.isArray(r.evidenceAlertIds) && r.evidenceAlertIds.length > 0 &&
    r.evidenceAlertIds.every((id) => typeof id === 'string' && ID.test(id)) &&
    time(r.createdAt) !== null && time(r.expiresAt) > time(r.createdAt) &&
    time(r.expiresAt) - time(r.createdAt) <= MAX_TTL;
}
async function optionalFile(path) {
  try { return await readFile(path, 'utf8'); }
  catch (e) { if (e?.code === 'ENOENT') return null; throw e; }
}
async function getRules(path) {
  const source = await optionalFile(path);
  if (source === null) return [];
  const store = JSON.parse(source);
  if (store?.schema !== SCHEMA || !Array.isArray(store.rules) || !store.rules.every(validRule))
    throw new Error('invalid_rule_store');
  return store.rules;
}
async function getEvents(path) {
  const source = await optionalFile(path);
  return source === null ? [] : source.split(/\r?\n/).filter(Boolean).map((row) => JSON.parse(row));
}
async function saveRules(path, rules) {
  await mkdir(dirname(path), { recursive: true });
  const temp = path + '.' + randomUUID() + '.tmp';
  try {
    await writeFile(temp, JSON.stringify({ schema: SCHEMA, rules }, null, 2) + '\n', {flag:'wx'});
    await rename(temp, path);
  } catch (error) {
    await rm(temp, { force: true }).catch(() => {});
    throw error;
  }
}

export async function respond(alert, outcome, options = {}) {
  const id = typeof alert?.id === 'string' && ID.test(alert.id) ? alert.id : null;
  if (!id) return { action:'record', result:'invalid_alert_id', ruleCreated:false };
  const expected = decide(alert);
  if (!outcome || outcome.action !== expected.action || outcome.confidence !== expected.confidence ||
      outcome.reason !== expected.reason) return { alertId:id, action:'record', result:'invalid_decision', ruleCreated:false };
  const now = options.now === undefined ? Date.now() :
    time(typeof options.now === 'function' ? options.now() : options.now);
  const ttlMs = options.ttlMs === undefined ? TTL : options.ttlMs;
  if (now === null || !Number.isSafeInteger(ttlMs) || ttlMs <= 0 || ttlMs > MAX_TTL)
    return { alertId:id, action:outcome.action, result:'bad_time_or_ttl', ruleCreated:false };
  const root = typeof options.root === 'string' ? options.root : ROOT;
  const logFile = join(root, 'alerts.log'), ruleFile = join(root,'known-cve','deny-rules.json');
  let events, rules;
  try { events = await getEvents(logFile); rules = await getRules(ruleFile); }
  catch { return { alertId:id, action:outcome.action, result:'read_failed', ruleCreated:false }; }
  if (events.some((entry) => entry?.alertId === id))
    return { alertId:id, action:outcome.action, result:'duplicate_alert', ruleCreated:false };
  const active = rules.filter((r) => time(r.expiresAt) > now);
  let result = outcome.action === 'alert' ? 'alert_only' : 'record_only';
  let created = false, updated = false;
  if (outcome.action === 'block' && BLOCK.has(outcome.reason)) {
    const ip = ipOf(alert?.data?.srcip);
    if (!ip || protectedIp(ip, options) ||
      (Array.isArray(options.protectedUsers) && options.protectedUsers.includes(alert?.data?.srcuser))) {
      result = 'protected_source';
    } else {
      const prior = active.find((r) => r.sourceIp === ip);
      if (prior?.evidenceAlertIds.includes(id)) result = 'duplicate_rule';
      else if (prior) {
        prior.evidenceAlertIds = [...prior.evidenceAlertIds,id];
        prior.confidence = Math.max(prior.confidence, outcome.confidence);
        updated = true; result = 'rule_updated';
      } else {
        active.push({
          ruleId:'xdr-known-cve-' + randomUUID(), action:'deny', sourceIp:ip,
          evidenceAlertIds:[id], reason:outcome.reason, confidence:outcome.confidence,
          createdAt:new Date(now).toISOString(), expiresAt:new Date(now + ttlMs).toISOString(),
        });
        created = true; result = 'rule_created';
      }
    }
  }
  // Never persist a new deny rule if audit logging is unavailable.
  try {
    await mkdir(dirname(logFile), { recursive:true });
    await appendFile(logFile, JSON.stringify({
      alertId:id, action:outcome.action, confidence:outcome.confidence,
      reason:outcome.reason, result, at:new Date(now).toISOString(),
    }) + '\n','utf8');
  } catch { return { alertId:id, action:outcome.action, result:'log_failed', ruleCreated:false }; }
  if (created || updated) {
    try { await saveRules(ruleFile, active); }
    catch { return { alertId:id, action:outcome.action, result:'rule_write_failed', ruleCreated:false }; }
  }
  return { alertId:id, action:outcome.action, result, ruleCreated:created, ruleUpdated:updated };
}

export function isDeniedByXdrRules(sourceIp, ruleSet, now = new Date(), options = {}) {
  const ip = ipOf(sourceIp), at = time(now);
  const rules = Array.isArray(ruleSet) ? ruleSet : ruleSet?.rules;
  return Boolean(ip && at !== null && !protectedIp(ip, options) && Array.isArray(rules) &&
    rules.some((r) => validRule(r) && r.sourceIp === ip &&
      time(r.createdAt) <= at && at < time(r.expiresAt)));
}
