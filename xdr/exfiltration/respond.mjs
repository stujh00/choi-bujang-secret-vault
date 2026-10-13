import { randomUUID } from 'node:crypto';
import { appendFile, mkdir, readFile, rename, rm, writeFile } from 'node:fs/promises';
import { isIP } from 'node:net';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { decide } from './decide.mjs';

const DEFAULT_ROOT = fileURLToPath(new URL('../', import.meta.url));
const STORE_SCHEMA = 'aleph.xdr.exfiltration.deny-candidates.v1';
const ALERT_ID = /^ex-\d+$/;
const DEFAULT_TTL_MS = 15 * 60 * 1000;
const MAX_TTL_MS = 24 * 60 * 60 * 1000;
const BLOCK_REASONS = new Set([
  '미확인 목적지로 대량 자료 전송',
  '비정상 시간 압축 파일 반출',
  '반복·우회 경로의 대량 외부 전송',
]);

function timestamp(value) {
  const parsed = value instanceof Date ? value.getTime()
    : typeof value === 'number' ? value : Date.parse(value);
  return Number.isFinite(parsed) ? parsed : null;
}
function destinationIp(value) {
  if (typeof value !== 'string') return null;
  const ip = value.trim().toLowerCase();
  return !ip.includes('%') && !ip.startsWith('::ffff:') && isIP(ip) !== 0 ? ip : null;
}
function documentationIp(ip) {
  if (isIP(ip) === 4) {
    const [a, b, c] = ip.split('.').map(Number);
    return (a === 192 && b === 0 && c === 2)
      || (a === 198 && b === 51 && c === 100)
      || (a === 203 && b === 0 && c === 113);
  }
  return /^2001:(?:db8|0db8)(?::|$)/i.test(ip);
}
function protectedDestination(ip, options = {}) {
  const exceptions = [
    ...(Array.isArray(options.protectedDestinations) ? options.protectedDestinations : []),
    ...(Array.isArray(options.exemptDestinations) ? options.exemptDestinations : []),
  ];
  if (exceptions.some(entry => destinationIp(entry) === ip)) return true;
  if (documentationIp(ip)) return options.allowDocumentationIps !== true;
  if (isIP(ip) === 4) {
    const [a, b] = ip.split('.').map(Number);
    return a === 0 || a === 10 || a === 127 || a >= 224
      || (a === 169 && b === 254)
      || (a === 172 && b >= 16 && b <= 31)
      || (a === 192 && b === 168)
      || (a === 100 && b >= 64 && b <= 127);
  }
  return ip === '::' || ip === '::1' || /^(fc|fd|fe8|fe9|fea|feb|ff)/i.test(ip);
}
function validRule(rule) {
  const createdAt = timestamp(rule?.createdAt);
  const expiresAt = timestamp(rule?.expiresAt);
  return rule && typeof rule === 'object'
    && /^xdr-exfiltration-[0-9a-f-]{36}$/i.test(rule.ruleId)
    && rule.action === 'deny'
    && destinationIp(rule.destinationIp) !== null
    && BLOCK_REASONS.has(rule.reason)
    && typeof rule.confidence === 'number'
    && rule.confidence >= 0.85 && rule.confidence <= 1
    && Array.isArray(rule.evidenceAlertIds) && rule.evidenceAlertIds.length > 0
    && rule.evidenceAlertIds.every(id => typeof id === 'string' && ALERT_ID.test(id))
    && createdAt !== null && expiresAt !== null && expiresAt > createdAt
    && expiresAt - createdAt <= MAX_TTL_MS;
}
async function readOptional(path) {
  try { return await readFile(path, 'utf8'); }
  catch (error) {
    if (error?.code === 'ENOENT') return null;
    throw error;
  }
}
async function readEvents(path) {
  const content = await readOptional(path);
  return content === null ? [] : content.split(/\r?\n/).filter(Boolean).map(line => JSON.parse(line));
}
async function readRules(path) {
  const content = await readOptional(path);
  if (content === null) return [];
  const store = JSON.parse(content);
  if (store?.schema !== STORE_SCHEMA || !Array.isArray(store.rules) || !store.rules.every(validRule)) {
    throw new Error('invalid_rule_store');
  }
  return store.rules;
}
async function writeRules(path, rules) {
  await mkdir(dirname(path), { recursive: true });
  const temp = path + '.' + randomUUID() + '.tmp';
  try {
    await writeFile(temp, JSON.stringify({ schema: STORE_SCHEMA, rules }, null, 2) + '\n', { flag: 'wx' });
    await rename(temp, path);
  } catch (error) {
    await rm(temp, { force: true }).catch(() => {});
    throw error;
  }
}
function approvedDecision(alert, proposed) {
  if (!proposed || typeof proposed !== 'object' || Array.isArray(proposed)
      || !Number.isFinite(proposed.confidence)
      || proposed.confidence < 0 || proposed.confidence > 1) return false;
  const calculated = decide(alert);
  return calculated.action === proposed.action && calculated.confidence === proposed.confidence
    && calculated.reason === proposed.reason
    && (proposed.action !== 'block' || BLOCK_REASONS.has(proposed.reason));
}

// Creates a candidate rule, never an actual firewall policy or live ZTNA block.
export async function respond(alert, decision, options = {}) {
  const alertId = typeof alert?.id === 'string' && ALERT_ID.test(alert.id) ? alert.id : null;
  if (!alertId) return { action: 'record', result: 'invalid_alert_id', ruleCreated: false };
  if (!approvedDecision(alert, decision)) {
    return { alertId, action: 'record', result: 'invalid_decision', ruleCreated: false };
  }
  const now = options.now === undefined ? Date.now()
    : timestamp(typeof options.now === 'function' ? options.now() : options.now);
  const ttlMs = options.ttlMs === undefined ? DEFAULT_TTL_MS : options.ttlMs;
  if (now === null || !Number.isSafeInteger(ttlMs) || ttlMs < 1
      || ttlMs > MAX_TTL_MS || !Number.isFinite(now + ttlMs)) {
    return { alertId, action: decision.action, result: 'invalid_clock_or_ttl', ruleCreated: false };
  }
  const root = typeof options.root === 'string' ? options.root : DEFAULT_ROOT;
  const logPath = join(root, 'alerts.log');
  const rulePath = join(root, 'exfiltration', 'deny-rules.json');
  let log, rules;
  try {
    log = await readEvents(logPath);
    rules = await readRules(rulePath);
  } catch {
    return { alertId, action: decision.action, result: 'store_read_failed', ruleCreated: false };
  }
  if (log.some(entry => entry?.alertId === alertId)) {
    return { alertId, action: decision.action, result: 'duplicate_alert', ruleCreated: false };
  }
  const activeRules = rules.filter(rule => timestamp(rule.expiresAt) > now);
  let response = decision.action === 'alert' ? 'alert_only' : 'record_only';
  let created = false;
  let updated = false;

  if (decision.action === 'block') {
    const destination = destinationIp(alert?.data?.dstip);
    const exemptUser = Array.isArray(options.protectedUsers)
      && options.protectedUsers.includes(alert?.data?.srcuser);
    if (!destination || protectedDestination(destination, options) || exemptUser) {
      response = 'excluded_destination_or_user';
    } else {
      const match = activeRules.find(rule => rule.destinationIp === destination);
      if (match?.evidenceAlertIds.includes(alertId)) {
        response = 'duplicate_rule';
      } else if (match) {
        match.evidenceAlertIds = [...match.evidenceAlertIds, alertId];
        match.confidence = Math.max(match.confidence, decision.confidence);
        updated = true;
        response = 'rule_updated';
      } else {
        activeRules.push({
          ruleId: 'xdr-exfiltration-' + randomUUID(),
          action: 'deny',
          destinationIp: destination,
          evidenceAlertIds: [alertId],
          reason: decision.reason,
          confidence: decision.confidence,
          createdAt: new Date(now).toISOString(),
          expiresAt: new Date(now + ttlMs).toISOString(),
        });
        created = true;
        response = 'rule_created';
      }
    }
  }

  // Audit first: never persist a new deny rule when audit logging fails.
  try {
    await mkdir(dirname(logPath), { recursive: true });
    await appendFile(logPath, JSON.stringify({
      alertId, action: decision.action, confidence: decision.confidence,
      reason: decision.reason, result: response, at: new Date(now).toISOString(),
    }) + '\n', 'utf8');
  } catch {
    return { alertId, action: decision.action, result: 'log_write_failed_no_rule', ruleCreated: false };
  }
  if (created || updated) {
    try { await writeRules(rulePath, activeRules); }
    catch {
      return { alertId, action: decision.action, result: 'rule_write_failed', ruleCreated: false };
    }
  }
  return { alertId, action: decision.action, result: response,
    ruleCreated: created, ruleUpdated: updated };
}

// Independent simulated destination match; not a verified ZTNA route or a firewall action.
export function isDeniedByXdrRules(destination, ruleSet, now = new Date(), options = {}) {
  const ip = destinationIp(destination);
  const at = timestamp(now);
  const rules = Array.isArray(ruleSet) ? ruleSet : ruleSet?.rules;
  if (!ip || at === null || protectedDestination(ip, options)
      || !Array.isArray(rules)) return false;
  return rules.some(rule => validRule(rule) && rule.destinationIp === ip
    && timestamp(rule.createdAt) <= at && at < timestamp(rule.expiresAt));
}
