const PATTERNS = [
  {
    name: '반복 SQL Injection 의심',
    mitre: ['T1190'],
    classification: 'high_confidence_candidate',
    condition: {
      all: [
        { field: 'rule.mitre', operator: 'array_includes', value: 'T1190' },
        { field: 'data.srcip', operator: 'non_empty_string' },
        { field: 'data.url', operator: 'url_path_in', value: ['/notes', '/search', '/api/notes'] },
        { field: 'data.url', operator: 'url_query_parameter_any', value: ['q', 'id'] },
        { field: 'data.count', operator: 'numeric_string_gte', value: 10 },
        {
          field: 'rule.description',
          operator: 'contains_any',
          value: [
            'SQL 구문을 이어 붙인 요청',
            'SQL 구문 표기가 한 주소에서',
            'SQL 표식이 같은 주소에서 번갈아',
            '데이터베이스 조회를 이어 붙이는 표기',
          ],
        },
      ],
    },
    evidence: 'wi-01/04/05/08은 T1190, 웹 경로와 쿼리 파라미터, SQL 결합 설명 및 해당 경보 count 10~20이 함께 있습니다.',
  },
  {
    name: '반복 XSS 스크립트 삽입 표식',
    mitre: ['T1190'],
    classification: 'high_confidence_candidate',
    condition: {
      all: [
        { field: 'rule.mitre', operator: 'array_includes', value: 'T1190' },
        { field: 'data.srcip', operator: 'non_empty_string' },
        { field: 'data.url', operator: 'url_path_in', value: ['/search'] },
        { field: 'data.url', operator: 'url_query_parameter_any', value: ['q'] },
        { field: 'data.count', operator: 'numeric_string_gte', value: 9 },
        {
          field: 'rule.description',
          operator: 'contains_any',
          value: ['스크립트 삽입 표기가', '스크립트 표식과 SQL 표식이 같은 주소에서 번갈아'],
        },
      ],
    },
    evidence: 'wi-02와 wi-05는 검색 쿼리에서 스크립트 삽입/표식 설명과 각각 9건·15건의 경보 내 반복 횟수가 있습니다.',
  },
  {
    name: '반복 Path Traversal 의심',
    mitre: ['T1190'],
    classification: 'high_confidence_candidate',
    condition: {
      all: [
        { field: 'rule.mitre', operator: 'array_includes', value: 'T1190' },
        { field: 'data.srcip', operator: 'non_empty_string' },
        { field: 'data.url', operator: 'url_path_in', value: ['/files'] },
        { field: 'data.url', operator: 'url_query_parameter_any', value: ['path', 'name'] },
        { field: 'data.count', operator: 'numeric_string_gte', value: 8 },
        {
          field: 'rule.description',
          operator: 'contains_any',
          value: ['경로를 여러 단계 거슬러 올라가는 표기', '경로 이탈 표기가 같은 주소에서'],
        },
      ],
    },
    evidence: 'wi-03/07은 /files의 path/name 쿼리와 상위 경로 이탈 설명, 해당 경보 count 8건·14건이 함께 있습니다.',
  },
  {
    name: '반복 명령 주입 시도',
    mitre: ['T1190'],
    classification: 'high_confidence_candidate',
    condition: {
      all: [
        { field: 'rule.mitre', operator: 'array_includes', value: 'T1190' },
        { field: 'data.srcip', operator: 'non_empty_string' },
        { field: 'data.url', operator: 'url_path_in', value: ['/notes'] },
        { field: 'data.url', operator: 'url_query_parameter_any', value: ['q'] },
        { field: 'data.count', operator: 'numeric_string_gte', value: 8 },
        { field: 'rule.description', operator: 'contains_any', value: ['명령 구분자 표기가 연속 요청'] },
      ],
    },
    evidence: 'T1190, 유효 출발지, /notes?q 문맥, Wazuh의 구체적인 반복 명령 구분자 탐지 설명과 count 8 이상이 함께 있으면 반복 주입 시도 후보로 분류합니다. 이는 명령 실행 성공을 뜻하지 않습니다.',
  },
  {
    name: '단일·모호한 주입 단서 추가 검토',
    mitre: ['T1190'],
    classification: 'review_only',
    condition: {
      all: [
        { field: 'rule.mitre', operator: 'array_includes', value: 'T1190' },
        { field: 'data.srcip', operator: 'non_empty_string' },
        { field: 'data.url', operator: 'non_empty_string' },
        { field: 'data.count', operator: 'numeric_string_eq', value: 1 },
        {
          field: 'rule.description',
          operator: 'contains_any',
          value: [
            '검색어에 따옴표가 한 번',
            'select 라는 수업명이 한 번',
            '스크립트라는 수업 단어가 한 번',
            '경로에 up 이 한 번',
            '요청 주소가 평소보다 깁니다',
            'SQL 이라는 수업 공지 제목을 한 번',
            '이상한 검색 1건 뒤에 정상 조회',
            '주입처럼 보이는 표기가 1건',
            '구분 문자가 1건',
          ],
        },
      ],
    },
    evidence: 'wi-09~17은 모두 T1190과 count 1이지만 문구상 단일 문자·수업 단어·정상 후속 조회 등으로 반복 공격을 입증하지 않습니다.',
  },
];

const SUSPICIOUS_DESCRIPTIONS = PATTERNS.flatMap((pattern) =>
  pattern.condition.all
    .filter((condition) => condition.operator === 'contains_any')
    .flatMap((condition) => condition.value),
);

function result(confidence, reason) {
  const action = confidence >= 0.85 ? 'block' : confidence >= 0.5 ? 'alert' : 'record';
  return { action, confidence, reason };
}

function readField(alert, path) {
  let value = alert;
  for (const key of path.split('.')) {
    if (value === null || typeof value !== 'object' || !Object.prototype.hasOwnProperty.call(value, key)) {
      return undefined;
    }
    value = value[key];
  }
  return value;
}

function isValidIpv4(value) {
  const parts = value.split('.');
  return parts.length === 4 && parts.every((part) => {
    if (!/^\d{1,3}$/.test(part)) return false;
    const number = Number(part);
    return number >= 0 && number <= 255 && String(number) === part;
  });
}

function isValidIp(value) {
  if (typeof value !== 'string' || value.trim() !== value || value.length === 0) return false;
  if (!value.includes(':')) return isValidIpv4(value);
  if (value.includes('%')) return false;

  let address = value;
  if (address.includes('.')) {
    const lastColon = address.lastIndexOf(':');
    const ipv4 = address.slice(lastColon + 1);
    if (!isValidIpv4(ipv4)) return false;
    const octets = ipv4.split('.').map(Number);
    const high = ((octets[0] << 8) | octets[1]).toString(16);
    const low = ((octets[2] << 8) | octets[3]).toString(16);
    address = `${address.slice(0, lastColon)}:${high}:${low}`;
  }

  const doubleColon = address.indexOf('::');
  if (doubleColon !== -1 && address.indexOf('::', doubleColon + 2) !== -1) return false;
  const compressed = doubleColon !== -1;
  const groups = address.split(':').filter(Boolean);
  if (groups.some((group) => !/^[\da-f]{1,4}$/i.test(group))) return false;
  return compressed ? groups.length < 8 : groups.length === 8;
}

function parseCount(value) {
  if (typeof value === 'number') {
    return Number.isSafeInteger(value) && value >= 0 ? value : null;
  }
  if (typeof value !== 'string') return null;
  const normalized = value.trim();
  if (!/^\d+$/.test(normalized)) return null;
  const count = Number(normalized);
  return Number.isSafeInteger(count) ? count : null;
}

function parseAlertUrl(value) {
  if (typeof value !== 'string' || value.length === 0 || value.trim() !== value || /[\u0000-\u0020\\]/.test(value)) {
    return null;
  }

  try {
    let parsed;
    if (value.startsWith('/')) {
      parsed = new URL(value, 'https://xdr.invalid');
    } else if (/^https?:\/\//i.test(value)) {
      parsed = new URL(value);
    } else {
      return null;
    }

    const rawPath = value.startsWith('/')
      ? value.split(/[?#]/, 1)[0]
      : value.replace(/^https?:\/\/[^/?#]*/i, '').split(/[?#]/, 1)[0] || '/';
    if (parsed.pathname !== rawPath || parsed.username || parsed.password) return null;
    return parsed;
  } catch {
    return null;
  }
}

function matchesCondition(condition, alert) {
  if (Array.isArray(condition.all)) return condition.all.every((item) => matchesCondition(item, alert));
  if (Array.isArray(condition.any)) return condition.any.some((item) => matchesCondition(item, alert));

  const value = readField(alert, condition.field);
  switch (condition.operator) {
    case 'array_includes':
      return Array.isArray(value) && value.includes(condition.value);
    case 'non_empty_string':
      return condition.field === 'data.srcip' ? isValidIp(value) : typeof value === 'string' && value.trim().length > 0;
    case 'numeric_string_gte': {
      const count = parseCount(value);
      return count !== null && count >= condition.value;
    }
    case 'numeric_string_eq':
      return parseCount(value) === condition.value;
    case 'contains_any':
      return typeof value === 'string' && condition.value.some((part) => value.includes(part));
    case 'url_path_in': {
      const parsed = parseAlertUrl(value);
      return parsed !== null && condition.value.includes(parsed.pathname);
    }
    case 'url_query_parameter_any': {
      const parsed = parseAlertUrl(value);
      return parsed !== null && condition.value.some((name) => parsed.searchParams.has(name));
    }
    default:
      return false;
  }
}

function hasTechnique(alert) {
  const mitre = readField(alert, 'rule.mitre');
  return Array.isArray(mitre) && mitre.includes('T1190');
}


// Broader Wazuh evidence: support different descriptions and real injection payloads,
// while requiring repeated attempts before an automatic block.
function analyzeWebEvidence(alert) {
  const description = readField(alert, 'rule.description');
  const url = readField(alert, 'data.url');
  const count = parseCount(readField(alert, 'data.count'));
  const ip = readField(alert, 'data.srcip');
  const tagged = hasTechnique(alert);
  if (typeof description !== 'string' || typeof url !== 'string') return null;

  const urlObject = parseAlertUrl(url);
  const rawWebUrl = /^\/[\w~!function decideSafely(alert) {'()*+,;=:@%./?\-]{1,4096}$/.test(url)
    || (/^https?:\/\//i.test(url) && url.length <= 4096);
  if (!urlObject && !rawWebUrl) return null;

  const queryPart = url.includes('?') ? url.slice(url.indexOf('?') + 1).split('#', 1)[0] : '';
  let query = queryPart;
  try { query = decodeURIComponent(queryPart.replace(/\+/g, ' ')); } catch { /* no repeated decoding */ }
  const context = url.split('?', 1)[0] + '?' + query;
  const benignContext = /(?:수업|강의|공지|정상|아닙니다|없습니다|단순|설명)/i.test(description);
  const clues = [
    {
      name: '반복 SQL Injection 의심',
      description: /(?:SQL|데이터베이스|DB).*?(?:구문|표식|이어|결합|붙이|주입|삽입|인젝션|injection|공격|조작)/i.test(description)
        || /(?:SQL\s*injection|SQLi|쿼리\s*(?:조작|주입))/i.test(description),
      payload: /\bunion\s+(?:all\s+)?select\b|\binformation_schema\b|\b(?:sleep|benchmark)\s*\(|['"]\s*(?:or|and)\s+\d+\s*=\s*\d+|\bdrop\s+table\b/i.test(context),
    },
    {
      name: '반복 XSS 스크립트 삽입 표식',
      description: /(?:XSS|스크립트|script|javascript).*?(?:삽입|표식|주입|실행|태그|injection|attack|payload)/i.test(description),
      payload: /<script\b|<img\b[^>]*\bonerror\s*=|\bon(?:error|load|click)\s*=|javascript\s*:/i.test(context),
    },
    {
      name: '반복 Path Traversal 의심',
      description: /경로.*?(?:이탈|거슬러|상위|탐색)|(?:path|directory)\s+traversal/i.test(description),
      payload: /(?:\.\.\/){2,}|\.\.\/(?:etc|windows|system32|var|home)\b|(?:\.\.\\){2,}/i.test(context),
    },
    {
      name: '반복 명령 주입 시도',
      description: /명령.*?(?:구분자|주입|실행)|(?:command|shell)\s+injection/i.test(description),
      payload: /(?:;|&&|\|\|?|%3b)\s*(?:id|whoami|uname|cat|curl|wget|bash|sh|powershell|cmd)(?:\b|\/)/i.test(context),
    },
  ];

  const suspicious = clues.find((clue) => clue.payload || (clue.description && !benignContext));
  const requestHasInput = Boolean(queryPart) || clues.some((clue) => clue.payload);
  if (suspicious && tagged && isValidIp(ip) && requestHasInput
      && count !== null && count >= 5) {
    return result(0.9, suspicious.name);
  }
  if ((tagged || clues.some((clue) => clue.payload)) && isValidIp(ip) && requestHasInput) {
    return result(0.65, '단일·모호한 주입 단서 추가 검토');
  }
  return null;
}

function decideSafely(alert) {
  if (alert === null || typeof alert !== 'object' || Array.isArray(alert)) {
    return result(0.1, '경보 객체가 아니어서 판단 근거가 없습니다.');
  }

  for (const pattern of PATTERNS) {
    if (!matchesCondition(pattern.condition, alert)) continue;
    return result(
      pattern.classification === 'high_confidence_candidate' ? 0.9 : 0.65,
      pattern.name,
    );
  }

  const broader = analyzeWebEvidence(alert);
  if (broader) return broader;

  const description = readField(alert, 'rule.description');
  const hasSuspiciousDescription = typeof description === 'string'
    && SUSPICIOUS_DESCRIPTIONS.some((clue) => description.includes(clue));

  if (hasSuspiciousDescription) {
    return result(0.62, '공격 관련 설명은 있으나 경로·반복·출발지 근거가 부족해 추가 검토가 필요합니다.');
  }
  if (hasTechnique(alert)) {
    return result(0.35, 'T1190만으로는 주입 공격을 입증할 수 없습니다.');
  }
  return result(0.1, '구체적인 주입 공격 근거가 없습니다.');
}

export function decide(alert) {
  try {
    return decideSafely(alert);
  } catch {
    return result(0.1, '경보 형식이 올바르지 않아 기록만 합니다.');
  }
}