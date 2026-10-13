// Standalone offline XDR judge module; no imports, I/O or network calls.
const PATTERNS = Object.freeze([
  { name: 'JNDI 머리글 원격 조회 구문', action: 'block' },
  { name: 'JNDI URL 인자 원격 조회 구문', action: 'block' },
  { name: '알려진 취약점 단서 추가 검토', action: 'alert' },
]);

function answer(confidence, reason) {
  return {
    action: confidence >= 0.85 ? 'block' : confidence >= 0.5 ? 'alert' : 'record',
    confidence,
    reason,
  };
}

function validIp(ip) {
  if (typeof ip !== 'string' || ip.trim() !== ip) return false;
  const groups = ip.split('.');
  if (groups.length === 4) {
    return groups.every((group) => /^\d{1,3}$/.test(group) && Number(group) <= 255
      && String(Number(group)) === group);
  }
  if (!ip.includes(':') || ip.includes('%') || !/^[\da-f:]+$/i.test(ip)) return false;
  const compressed = ip.includes('::');
  if (compressed && ip.indexOf('::') !== ip.lastIndexOf('::')) return false;
  const hex = ip.split(':').filter(Boolean);
  return hex.every((group) => /^[\da-f]{1,4}$/i.test(group))
    && (compressed ? hex.length < 8 : hex.length === 8);
}

function asStrings(value, depth = 0) {
  if (depth > 2) return [];
  if (typeof value === 'string') return [value.slice(0, 8192)];
  if (Array.isArray(value)) return value.slice(0, 32).flatMap((item) => asStrings(item, depth + 1));
  if (value === null || typeof value !== 'object') return [];
  return Object.values(value).slice(0, 32).flatMap((item) => asStrings(item, depth + 1));
}

function normalizedOnce(value) {
  if (typeof value !== 'string') return '';
  try { return decodeURIComponent(value.replace(/\+/g, ' ')); }
  catch { return value; }
}

function hasRemoteJndi(value) {
  // A complete remote lookup expression; CVE names or the word jndi alone are insufficient.
  const signature = /\x24\x7b\s*jndi\s*:\s*(?:ldap|ldaps|rmi|dns|iiop)\s*:\s*\/\/[^\s}]+\}/i;
  return asStrings(value).some((item) => signature.test(item) || signature.test(normalizedOnce(item)));
}

export function decide(alert) {
  try {
    if (!alert || typeof alert !== 'object' || Array.isArray(alert)) {
      return answer(0.1, '유효한 경보가 아니므로 기록');
    }
    const data = alert.data, rule = alert.rule;
    if (!data || typeof data !== 'object' || !rule || typeof rule !== 'object') {
      return answer(0.1, '경보 필드가 부족하여 기록');
    }
    const inHeader = hasRemoteJndi([data.useragent, data.headers, data.request_headers, data.http_headers]);
    const inUrl = hasRemoteJndi([data.url, data.uri, data.query]);
    if (inHeader || inUrl) {
      if (!validIp(data.srcip)) return answer(0.65, PATTERNS[2].name);
      return answer(0.95, PATTERNS[inHeader ? 0 : 1].name);
    }
    const tagged = Array.isArray(rule.mitre) && rule.mitre.includes('T1190');
    const description = typeof rule.description === 'string' ? rule.description : '';
    const mention = /CVE[-\s]?2021[-\s]?44228|log4shell|log4j|jndi|원격\s*조회|취약점|점검\s*도구|스캐너|lookup/i.test(description)
      || asStrings([data.url, data.useragent]).some((item) =>
        /CVE[-\s]?2021[-\s]?44228|log4shell|log4j|jndi/i.test(item));
    if (tagged || mention) return answer(0.65, PATTERNS[2].name);
    return answer(0.1, '구체적인 알려진 취약점 악용 근거 없음');
  } catch {
    return answer(0.1, '경보 형식 오류로 기록');
  }
}
