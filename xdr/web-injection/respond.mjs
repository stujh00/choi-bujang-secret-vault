import { randomUUID } from 'node:crypto';
import { appendFile, mkdir, readFile, rename, rm, writeFile } from 'node:fs/promises';
import { isIP } from 'node:net';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { decide as decideAlert } from './decide.mjs';

const DEFAULT_ROOT = fileURLToPath(new URL('./', import.meta.url));
const STORE_SCHEMA = 'aleph.xdr.web-injection.deny-rules.v1';
const ALERT_ID_PATTERN = /^wi-\d{2}$/;
const RULE_ID_PATTERN = /^xdr-web-injection-[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const DEFAULT_TTL_MS = 15 * 60 * 1000;
const MAX_TTL_MS = 24 * 60 * 60 * 1000;

const SAFE_REASONS = new Set([
  '반복 SQL Injection 의심',
  '반복 XSS 스크립트 삽입 표식',
  '반복 Path Traversal 의심',
  '반복 명령 주입 시도',
  '단일·모호한 주입 단서 추가 검토',
  '공격 관련 설명은 있으나 경로·반복·출발지 근거가 부족해 추가 검토가 필요합니다.',
  'T1190만으로는 주입 공격을 입증할 수 없습니다.',
  '구체적인 주입 공격 근거가 없습니다.',
  '경보 객체가 아니어서 판단 근거가 없습니다.',
  '경보 형식이 올바르지 않아 기록만 합니다.',
]);

const BLOCK_REASONS = new Set([
  '반복 SQL Injection 의심',
  '반복 XSS 스크립트 삽입 표식',
  '반복 Path Traversal 의심',
  '반복 명령 주입 시도',
]);

function parseTime(value) {
  if (value instanceof Date) return Number.isFinite(value.getTime()) ? value.getTime() : null;
  if (typeof value === 'number') return Number.isFinite(value) ? value : null;
  if (typeof value !== 'string') return null;
  const time = Date.parse(value);
  return Number.isFinite(time) ? time : null;
}

function getNow(options) {
  const value = typeof options.now === 'function' ? options.now() : options.now;
  const time = value === undefined ? Date.now() : parseTime(value);
  if (!Number.isFinite(time)) throw new Error('invalid_clock');
  return time;
}

function normalizeIp(value) {
  if (typeof value !== 'string') return null;
  const address = value.trim().toLowerCase();
  if (address.includes('%') || address.startsWith('::ffff:') || isIP(address) === 0) return null;
  return address;
}

function isDocumentationIp(address) {
  const family = isIP(address);
  if (family === 4) {
    const [first, second, third] = address.split('.').map(Number);
    return (first === 192 && second === 0 && third === 2)
      || (first === 198 && second === 51 && third === 100)
      || (first === 203 && second === 0 && third === 113);
  }
  return family === 6 && /^2001:(?:db8|0db8)(?::|$)/i.test(address);
}

function isSharedOrReservedIp(address) {
  const family = isIP(address);
  if (family === 4) {
    const octets = address.split('.').map(Number);
    const [first, second, third] = octets;
    return first === 0
      || first === 10
      || first === 127
      || (first === 169 && second === 254)
      || (first === 172 && second >= 16 && second <= 31)
      || (first === 192 && second === 168)
      || (first === 192 && second === 0 && third !== 2)
      || (first === 100 && second >= 64 && second <= 127)
      || first >= 224;
  }
  if (family === 6) {
    if (address === '::' || address === '::1') return true;
    const firstGroup = address.split(':')[0];
    const first = Number.parseInt(firstGroup || '0', 16);
    return (first & 0xfe00) === 0xfc00
      || (first & 0xffc0) === 0xfe80
      || (first & 0xff00) === 0xff00;
  }
  return true;
}

function isExemptIp(address, exemptIps, allowDocumentationIps) {
  if (isSharedOrReservedIp(address)) return true;
  if (isDocumentationIp(address) && !allowDocumentationIps) return true;
  return exemptIps.some((ip) => normalizeIp(ip) === address);
}

function isValidDecision(decision) {
  if (decision === null || typeof decision !== 'object' || Array.isArray(decision)) return false;
  if (!['block', 'alert', 'record'].includes(decision.action)) return false;
  if (typeof decision.confidence !== 'number' || !Number.isFinite(decision.confidence)) return false;
  if (decision.confidence < 0 || decision.confidence > 1) return false;
  if (typeof decision.reason !== 'string' || !SAFE_REASONS.has(decision.reason)) return false;

  const expectedAction = decision.confidence >= 0.85
    ? 'block'
    : decision.confidence >= 0.5 ? 'alert' : 'record';
  if (decision.action !== expectedAction) return false;

  if (decision.action === 'block') {
    return BLOCK_REASONS.has(decision.reason) && decision.confidence >= 0.85;
  }
  return true;
}

function matchesDecider(alert, decision) {
  let expected;
  try {
    expected = decideAlert(alert);
  } catch {
    return false;
  }
  return expected.action === decision.action
    && expected.confidence === decision.confidence
    && expected.reason === decision.reason;
}

function isRule(rule) {
  if (rule === null || typeof rule !== 'object' || Array.isArray(rule)) return false;
  const createdAt = parseTime(rule.createdAt);
  const expiresAt = parseTime(rule.expiresAt);
  return typeof rule.ruleId === 'string'
    && RULE_ID_PATTERN.test(rule.ruleId)
    && rule.action === 'deny'
    && normalizeIp(rule.sourceIp) !== null
    && Array.isArray(rule.evidenceAlertIds)
    && rule.evidenceAlertIds.length > 0
    && rule.evidenceAlertIds.every((alertId) => typeof alertId === 'string' && ALERT_ID_PATTERN.test(alertId))
    && typeof rule.reason === 'string'
    && BLOCK_REASONS.has(rule.reason)
    && typeof rule.confidence === 'number'
    && Number.isFinite(rule.confidence)
    && rule.confidence >= 0.85
    && rule.confidence <= 1
    && createdAt !== null
    && expiresAt !== null
    && expiresAt > createdAt
    && expiresAt - createdAt <= MAX_TTL_MS;
}

function readStoreContents(value) {
  const store = JSON.parse(value);
  if (store?.schema !== STORE_SCHEMA || !Array.isArray(store.rules) || !store.rules.every(isRule)) {
    throw new Error('invalid_rule_store');
  }
  return store.rules;
}

async function loadRules(filePath) {
  try {
    return readStoreContents(await readFile(filePath, 'utf8'));
  } catch (error) {
    if (error?.code === 'ENOENT') return [];
    throw error;
  }
}

async function loadLog(filePath) {
  try {
    const text = await readFile(filePath, 'utf8');
    return text.split(/\r?\n/).filter(Boolean).map((line) => JSON.parse(line));
  } catch (error) {
    if (error?.code === 'ENOENT') return [];
    throw error;
  }
}

async function appendLog(root, entry) {
  await mkdir(root, { recursive: true });
  await appendFile(join(root, 'alerts.log'), `${JSON.stringify(entry)}\n`, 'utf8');
}

async function writeRuleStore(filePath, rules) {
  const temporaryPath = `${filePath}.${randomUUID()}.tmp`;
  try {
    await writeFile(temporaryPath, `${JSON.stringify({ schema: STORE_SCHEMA, rules }, null, 2)}\n`, {
      encoding: 'utf8',
      flag: 'wx',
    });
    await rename(temporaryPath, filePath);
  } catch (error) {
    await rm(temporaryPath, { force: true }).catch(() => {});
    throw error;
  }
}

function makeRule(sourceIp, alertId, reason, confidence, now, ttlMs) {
  return {
    ruleId: `xdr-web-injection-${randomUUID()}`,
    action: 'deny',
    sourceIp,
    evidenceAlertIds: [alertId],
    reason,
    confidence,
    createdAt: new Date(now).toISOString(),
    expiresAt: new Date(now + ttlMs).toISOString(),
  };
}

function makeResult(alertId, action, result, extra = {}) {
  return { alertId, action, result, ruleCreated: false, ...extra };
}

function isProtectedUser(alert, protectedUsers) {
  const sourceUser = alert?.data?.srcuser;
  return typeof sourceUser === 'string' && protectedUsers.includes(sourceUser);
}

export async function respond(alert, decision, options = {}) {
  const settings = options !== null && typeof options === 'object' ? options : {};
  const rawAlertId = alert && typeof alert === 'object' ? alert.id : null;
  const alertId = typeof rawAlertId === 'string' && ALERT_ID_PATTERN.test(rawAlertId) ? rawAlertId : null;
  const safeAction = ['block', 'alert', 'record'].includes(decision?.action) ? decision.action : 'record';

  if (alertId === null) return makeResult(null, safeAction, 'rejected_invalid_alert_id');
  if (!isValidDecision(decision) || !matchesDecider(alert, decision)) {
    return makeResult(alertId, 'record', 'rejected_invalid_decision');
  }

  let now;
  try {
    now = getNow(settings);
  } catch {
    return makeResult(alertId, decision.action, 'rejected_invalid_clock');
  }

  const root = typeof settings.root === 'string' ? settings.root : DEFAULT_ROOT;
  const ttlMs = settings.ttlMs === undefined ? DEFAULT_TTL_MS : settings.ttlMs;
  const exemptIps = [
    ...(Array.isArray(settings.exemptIps) ? settings.exemptIps : []),
    ...(Array.isArray(settings.protectedIps) ? settings.protectedIps : []),
  ];
  const protectedUsers = Array.isArray(settings.protectedUsers)
    ? settings.protectedUsers.filter((user) => typeof user === 'string')
    : [];
  if (!Number.isSafeInteger(ttlMs) || ttlMs <= 0 || ttlMs > MAX_TTL_MS || !Number.isFinite(now + ttlMs)) {
    return makeResult(alertId, decision.action, 'rejected_invalid_ttl');
  }

  let priorEvents;
  try {
    priorEvents = await loadLog(join(root, 'alerts.log'));
  } catch {
    return makeResult(alertId, decision.action, 'log_read_error_no_rule');
  }
  if (priorEvents.some((entry) => entry?.alertId === alertId)) {
    return makeResult(alertId, decision.action, 'duplicate_alert_ignored');
  }

  let result;
  let ruleCreated = false;
  let ruleUpdated = false;
  let responseRule;

  if (decision.action === 'block') {
    const sourceIp = normalizeIp(alert?.data?.srcip);
    if (sourceIp === null) {
      result = 'rejected_invalid_source_ip';
    } else if (isExemptIp(sourceIp, exemptIps, settings.allowDocumentationIps === true)) {
      result = 'rejected_exempt_source_ip';
    } else if (isProtectedUser(alert, protectedUsers)) {
      result = 'rejected_protected_user';
    } else {
      let storedRules;
      try {
        storedRules = await loadRules(join(root, 'deny-rules.json'));
      } catch {
        result = 'rule_store_read_error_no_rule';
      }

      if (storedRules !== undefined) {
        const activeRules = storedRules.filter((rule) => parseTime(rule.expiresAt) > now);
        const existing = activeRules.find((rule) => rule.sourceIp === sourceIp);
        if (existing?.evidenceAlertIds.includes(alertId)) {
          result = 'duplicate_deny_rule';
          responseRule = existing;
        } else {
          let nextRule;
          if (existing) {
            nextRule = {
              ...existing,
              evidenceAlertIds: [...existing.evidenceAlertIds, alertId],
              reason: decision.reason,
              confidence: Math.max(existing.confidence, decision.confidence),
            };
            ruleUpdated = true;
          } else {
            nextRule = makeRule(sourceIp, alertId, decision.reason, decision.confidence, now, ttlMs);
            ruleCreated = true;
          }

          const nextRules = activeRules.filter((rule) => rule.sourceIp !== sourceIp);
          nextRules.push(nextRule);
          try {
            await writeRuleStore(join(root, 'deny-rules.json'), nextRules);
            responseRule = nextRule;
            result = ruleCreated ? 'deny_rule_created' : 'deny_rule_updated';
          } catch {
            result = 'rule_store_write_error_no_rule';
            ruleCreated = false;
            ruleUpdated = false;
            responseRule = undefined;
          }
        }
      }
    }
  } else if (decision.action === 'alert') {
    result = 'alert_logged_no_block';
  } else {
    result = 'record_logged_no_block';
  }

  const logEntry = {
    alertId,
    action: decision.action,
    confidence: decision.confidence,
    reason: decision.reason,
    result,
    at: new Date(now).toISOString(),
  };
  try {
    await appendLog(root, logEntry);
  } catch {
    return makeResult(alertId, decision.action, 'log_write_error');
  }

  return makeResult(alertId, decision.action, result, {
    ruleCreated,
    ...(ruleUpdated ? { ruleUpdated: true } : {}),
    ...(responseRule ? { rule: responseRule } : {}),
  });
}

export function isDeniedByXdrRules(sourceIp, ruleSet, now = new Date(), options = {}) {
  const address = normalizeIp(sourceIp);
  const currentTime = parseTime(now);
  const rules = Array.isArray(ruleSet) ? ruleSet : ruleSet?.rules;
  if (address === null
    || isSharedOrReservedIp(address)
    || (isDocumentationIp(address) && options?.allowDocumentationIps !== true)
    || currentTime === null
    || !Array.isArray(rules)) {
    return false;
  }
  return rules.some((rule) => isRule(rule)
    && rule.action === 'deny'
    && rule.sourceIp === address
    && parseTime(rule.createdAt) <= currentTime
    && currentTime < parseTime(rule.expiresAt));
}