import { randomUUID } from 'node:crypto';
import { appendFile, mkdir, readFile, rename, rm, writeFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { decide } from './decide.mjs';

const DEFAULT_ROOT = fileURLToPath(new URL('../', import.meta.url));
const SCHEMA = 'aleph.xdr.privilege.revoke-candidates.v1';
const ALERT_ID = /^pv-\d+$/;
const BLOCK_REASONS = new Set([
  '비정상 관리자 그룹 권한 획득',
  '새 관리자 권한 또는 도용 권한 명령 실행',
  '관리자 권한 재부여 및 대량 변경',
]);
const DEFAULT_TTL_MS = 15 * 60 * 1000;
const MAX_TTL_MS = 24 * 60 * 60 * 1000;

function timeOf(value) {
  const valueMs = value instanceof Date ? value.getTime()
    : typeof value === 'number' ? value : Date.parse(value);
  return Number.isFinite(valueMs) ? valueMs : null;
}
function accountOf(value) {
  return typeof value === 'string' && /^[a-z0-9][a-z0-9_.@-]{1,127}$/i.test(value)
    ? value.toLowerCase() : null;
}
function validRule(rule) {
  const createdAt = timeOf(rule?.createdAt);
  const expiresAt = timeOf(rule?.expiresAt);
  return rule && typeof rule === 'object'
    && /^xdr-privilege-[0-9a-f-]{36}$/i.test(rule.ruleId)
    && rule.action === 'deny'
    && accountOf(rule.account) !== null
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
async function loadEvents(path) {
  const content = await readOptional(path);
  return content === null ? [] : content.split(/\r?\n/).filter(Boolean).map(line => JSON.parse(line));
}
async function loadRules(path) {
  const content = await readOptional(path);
  if (content === null) return [];
  const store = JSON.parse(content);
  if (store?.schema !== SCHEMA || !Array.isArray(store.rules) || !store.rules.every(validRule)) {
    throw new Error('invalid_rule_store');
  }
  return store.rules;
}
async function storeRules(path, rules) {
  await mkdir(dirname(path), { recursive: true });
  const temp = path + '.' + randomUUID() + '.tmp';
  try {
    await writeFile(temp, JSON.stringify({ schema: SCHEMA, rules }, null, 2) + '\n', { flag: 'wx' });
    await rename(temp, path);
  } catch (error) {
    await rm(temp, { force: true }).catch(() => {});
    throw error;
  }
}
function matchesDecision(alert, given) {
  if (!given || typeof given !== 'object' || Array.isArray(given)
      || !Number.isFinite(given.confidence) || given.confidence < 0 || given.confidence > 1) {
    return false;
  }
  const expected = decide(alert);
  return expected.action === given.action && expected.confidence === given.confidence
    && expected.reason === given.reason
    && (given.action !== 'block' || BLOCK_REASONS.has(given.reason));
}
function isProtected(account, options) {
  const protectedUsers = [
    ...(Array.isArray(options.protectedUsers) ? options.protectedUsers : []),
    ...(Array.isArray(options.exemptAccounts) ? options.exemptAccounts : []),
  ];
  return protectedUsers.some(item => accountOf(item) === account);
}

// Generates temporary account-session revocation *candidates*; it cannot revoke a real session.
export async function respond(alert, outcome, options = {}) {
  const id = typeof alert?.id === 'string' && ALERT_ID.test(alert.id) ? alert.id : null;
  if (id === null) return { action: 'record', result: 'invalid_alert_id', ruleCreated: false };
  if (!matchesDecision(alert, outcome)) {
    return { alertId: id, action: 'record', result: 'invalid_decision', ruleCreated: false };
  }
  const now = options.now === undefined ? Date.now()
    : timeOf(typeof options.now === 'function' ? options.now() : options.now);
  const ttlMs = options.ttlMs === undefined ? DEFAULT_TTL_MS : options.ttlMs;
  if (now === null || !Number.isSafeInteger(ttlMs) || ttlMs <= 0 || ttlMs > MAX_TTL_MS
      || !Number.isFinite(now + ttlMs)) {
    return { alertId: id, action: outcome.action, result: 'invalid_clock_or_ttl', ruleCreated: false };
  }

  const root = typeof options.root === 'string' ? options.root : DEFAULT_ROOT;
  const logPath = join(root, 'alerts.log');
  const rulesPath = join(root, 'privilege', 'deny-rules.json');
  let events, rules;
  try {
    events = await loadEvents(logPath);
    rules = await loadRules(rulesPath);
  } catch {
    return { alertId: id, action: outcome.action, result: 'store_read_failed', ruleCreated: false };
  }
  if (events.some(event => event?.alertId === id)) {
    return { alertId: id, action: outcome.action, result: 'duplicate_alert', ruleCreated: false };
  }
  const active = rules.filter(rule => timeOf(rule.expiresAt) > now);
  let response = outcome.action === 'alert' ? 'alert_only' : 'record_only';
  let created = false, updated = false;
  if (outcome.action === 'block') {
    const account = accountOf(alert?.data?.srcuser);
    if (account === null || isProtected(account, options)) {
      response = 'excluded_account';
    } else {
      const existing = active.find(rule => rule.account === account);
      if (existing?.evidenceAlertIds.includes(id)) {
        response = 'duplicate_rule';
      } else if (existing) {
        existing.evidenceAlertIds = [...existing.evidenceAlertIds, id];
        existing.confidence = Math.max(existing.confidence, outcome.confidence);
        updated = true;
        response = 'rule_updated';
      } else {
        active.push({
          ruleId: 'xdr-privilege-' + randomUUID(),
          action: 'deny',
          account,
          reason: outcome.reason,
          confidence: outcome.confidence,
          evidenceAlertIds: [id],
          createdAt: new Date(now).toISOString(),
          expiresAt: new Date(now + ttlMs).toISOString(),
        });
        created = true;
        response = 'rule_created';
      }
    }
  }

  // An unavailable audit log must never leave a newly saved candidate rule.
  try {
    await mkdir(dirname(logPath), { recursive: true });
    await appendFile(logPath, JSON.stringify({
      alertId: id,
      action: outcome.action,
      confidence: outcome.confidence,
      reason: outcome.reason,
      result: response,
      at: new Date(now).toISOString(),
    }) + '\n', 'utf8');
  } catch {
    return { alertId: id, action: outcome.action, result: 'log_write_failed_no_rule', ruleCreated: false };
  }

  if (created || updated) {
    try { await storeRules(rulesPath, active); }
    catch {
      return { alertId: id, action: outcome.action, result: 'rule_write_failed', ruleCreated: false };
    }
  }
  return { alertId: id, action: outcome.action, result: response, ruleCreated: created, ruleUpdated: updated };
}

// Checks simulated account-name candidates only. srcuser is NOT the ZTNA engine's verified subjectId.
export function isDeniedByXdrRules(account, ruleSet, now = new Date(), options = {}) {
  const normalized = accountOf(account);
  const instant = timeOf(now);
  const rules = Array.isArray(ruleSet) ? ruleSet : ruleSet?.rules;
  if (!normalized || instant === null || isProtected(normalized, options)
      || !Array.isArray(rules)) return false;
  return rules.some(rule => validRule(rule) && rule.account === normalized
    && timeOf(rule.createdAt) <= instant && instant < timeOf(rule.expiresAt));
}
