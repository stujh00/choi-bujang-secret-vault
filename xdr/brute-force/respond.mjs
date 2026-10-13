import { createHash, randomUUID } from 'node:crypto';
import { appendFile, mkdir, readFile, rename, rm, writeFile } from 'node:fs/promises';
import { isIP } from 'node:net';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const DEFAULT_ROOT = fileURLToPath(new URL('../', import.meta.url));
const STORE_SCHEMA = 'aleph.xdr.deny-rules.v1';
const ALERT_ID_PATTERN = /^bf-\d{2}$/;
const DEFAULT_TTL_MS = 15 * 60 * 1000;
const MAX_TTL_MS = 24 * 60 * 60 * 1000;

const SAFE_REASONS = new Set([
  '고신뢰 의심: 고빈도 실패와 구체적인 공격 징후',
  '고신뢰 의심: 한 출발 IP의 다계정 실패 시도',
  '고신뢰 의심: 한 출발 IP의 동일 계정 고빈도 실패',
  '검토 필요: 저빈도 또는 맥락이 필요한 실패',
  '고빈도 실패와 출발 IP는 있으나 T1110 근거가 없어 추가 검토가 필요합니다.',
  'T1110 경보지만 count가 없거나 유효하지 않아 반복 횟수를 판단할 수 없습니다.',
  'T1110 실패는 있으나 고신뢰 패턴과 일치하지 않아 검토가 필요합니다.',
  'T1110만으로는 반복 공격을 입증할 수 없습니다.',
  'T1110 또는 반복 실패 근거가 없습니다.',
  '경보 객체가 아니어서 판단 근거가 없습니다.',
  '경보 형식이 올바르지 않아 안전하게 기록만 합니다.',
]);

function parseTime(value) {
  const time = value instanceof Date ? value.getTime() : Date.parse(value);
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
  const address = value.trim();
  if (address.includes('%') || isIP(address) === 0) return null;
  return address.toLowerCase();
}

function isSharedOrReservedIp(address) {
  const family = isIP(address);
  if (family === 4) {
    const octets = address.split('.').map(Number);
    const [first, second] = octets;
    return first === 0
      || first === 10
      || first === 127
      || (first === 169 && second === 254)
      || (first === 172 && second >= 16 && second <= 31)
      || (first === 192 && second === 168)
      || (first === 100 && second >= 64 && second <= 127)
      || first >= 224;
  }
  if (family === 6) {
    const lower = address.toLowerCase();
    if (lower === '::' || lower === '::1') return true;
    const firstGroup = lower.split(':')[0];
    const first = Number.parseInt(firstGroup || '0', 16);
    return (first & 0xfe00) === 0xfc00
      || (first & 0xffc0) === 0xfe80
      || (first & 0xff00) === 0xff00;
  }
  return true;
}

function isExemptIp(address, exemptIps) {
  if (isSharedOrReservedIp(address)) return true;
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
  return decision.action === expectedAction;
}

function isRule(rule) {
  return rule !== null
    && typeof rule === 'object'
    && typeof rule.id === 'string'
    && rule.action === 'deny'
    && normalizeIp(rule.sourceIp) !== null
    && ALERT_ID_PATTERN.test(rule.evidenceAlertId)
    && SAFE_REASONS.has(rule.reason)
    && parseTime(rule.createdAt) !== null
    && parseTime(rule.expiresAt) > parseTime(rule.createdAt);
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

function makeRule(sourceIp, alertId, reason, now, ttlMs) {
  const digest = createHash('sha256').update(`${sourceIp}\n${alertId}`).digest('hex').slice(0, 20);
  return {
    id: `xdr-deny-${digest}`,
    action: 'deny',
    sourceIp,
    evidenceAlertId: alertId,
    reason,
    createdAt: new Date(now).toISOString(),
    expiresAt: new Date(now + ttlMs).toISOString(),
  };
}

function makeResult(alertId, action, result, extra = {}) {
  return { alertId, action, result, ruleCreated: false, ...extra };
}

export async function respond(alert, decision, options = {}) {
  const alertId = alert && typeof alert === 'object' ? alert.id : null;
  if (typeof alertId !== 'string' || !ALERT_ID_PATTERN.test(alertId)) {
    return makeResult(null, decision?.action ?? 'record', 'rejected_invalid_alert_id');
  }
  if (!isValidDecision(decision)) {
    return makeResult(alertId, 'record', 'rejected_invalid_decision');
  }

  let now;
  try {
    now = getNow(options);
  } catch {
    return makeResult(alertId, decision.action, 'rejected_invalid_clock');
  }

  const root = typeof options.root === 'string' ? options.root : DEFAULT_ROOT;
  const ttlMs = options.ttlMs === undefined ? DEFAULT_TTL_MS : options.ttlMs;
  const exemptIps = Array.isArray(options.exemptIps) ? options.exemptIps : [];
  if (!Number.isSafeInteger(ttlMs) || ttlMs <= 0 || ttlMs > MAX_TTL_MS) {
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

  const rawIp = alert?.data?.srcip;
  const sourceIp = normalizeIp(rawIp);
  const validIp = sourceIp !== null;
  const exemptIp = validIp && isExemptIp(sourceIp, exemptIps);
  let candidateRule = null;
  let rules = null;
  let result;

  if (decision.action === 'block') {
    if (!validIp) {
      result = 'rejected_invalid_source_ip';
    } else if (exemptIp) {
      result = 'rejected_shared_or_exempt_source_ip';
    } else {
      try {
        rules = await loadRules(join(root, 'deny-rules.json'));
      } catch {
        result = 'rule_store_read_error_no_rule';
      }
      if (rules !== null) {
        const existing = rules.find((rule) => rule.sourceIp === sourceIp && rule.evidenceAlertId === alertId);
        if (existing && parseTime(existing.expiresAt) > now) {
          result = 'duplicate_deny_rule';
        } else {
          candidateRule = makeRule(sourceIp, alertId, decision.reason, now, ttlMs);
          result = 'deny_rule_candidate_logged';
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
    return makeResult(alertId, decision.action, 'log_write_error_no_rule');
  }

  if (candidateRule !== null && rules !== null) {
    const nextRules = rules.filter((rule) => !(rule.sourceIp === sourceIp && rule.evidenceAlertId === alertId));
    nextRules.push(candidateRule);
    try {
      await writeRuleStore(join(root, 'deny-rules.json'), nextRules);
      return makeResult(alertId, decision.action, 'deny_rule_created', { ruleCreated: true, rule: candidateRule });
    } catch {
      return makeResult(alertId, decision.action, 'rule_store_write_error_no_rule');
    }
  }

  return makeResult(alertId, decision.action, result);
}

export function isDeniedByXdrRules(sourceIp, ruleSet, now = new Date()) {
  const address = normalizeIp(sourceIp);
  const currentTime = parseTime(now);
  const rules = Array.isArray(ruleSet) ? ruleSet : ruleSet?.rules;
  if (address === null || isSharedOrReservedIp(address) || currentTime === null || !Array.isArray(rules)) {
    return false;
  }
  return rules.some((rule) => isRule(rule)
    && rule.action === 'deny'
    && rule.sourceIp === address
    && parseTime(rule.createdAt) <= currentTime
    && currentTime < parseTime(rule.expiresAt));
}