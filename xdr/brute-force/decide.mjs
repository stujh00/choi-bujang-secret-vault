const PATTERNS = [
  {
    name: '한 출발 IP의 동일 계정 고빈도 실패',
    mitreTechnique: 'T1110',
    classification: 'high_confidence_suspicious',
    condition: {
      all: [
        { field: 'rule.mitre', operator: 'array_includes', value: 'T1110' },
        { field: 'data.srcip', operator: 'non_empty_string' },
        { field: 'data.srcuser', operator: 'non_empty_string' },
        { field: 'data.count', operator: 'numeric_string_gte', value: 15 },
        { field: 'rule.description', operator: 'contains_any', value: ['한 계정', '같은 계정'] },
      ],
    },
    evidence: 'bf-04와 bf-08은 T1110, srcip/srcuser가 있고 같은 계정의 실패를 각각 52건과 70건으로 명시합니다; 애매한 T1110 사례의 count는 최대 8입니다.',
  },
  {
    name: '한 출발 IP의 다계정 실패 시도',
    mitreTechnique: 'T1110',
    classification: 'high_confidence_suspicious',
    condition: {
      all: [
        { field: 'rule.mitre', operator: 'array_includes', value: 'T1110' },
        { field: 'data.srcip', operator: 'non_empty_string' },
        {
          any: [
            { field: 'data.accounts', operator: 'comma_separated_count_gte', value: 2 },
            {
              field: 'rule.description',
              operator: 'contains_any',
              value: ['이름을 바꿔 가며 시도', '계정 20개', '서로 다른 계정 15개'],
            },
          ],
        },
      ],
    },
    evidence: 'bf-02는 accounts에 8개 계정이 있고 bf-03/bf-05/bf-09는 여러 계정 시도를 설명합니다; 공통 비밀번호 사용 여부를 검증하는 필드는 없습니다.',
  },
  {
    name: '저빈도 또는 맥락이 필요한 실패',
    mitreTechnique: 'T1110',
    classification: 'review_only',
    condition: {
      all: [
        { field: 'rule.mitre', operator: 'array_includes', value: 'T1110' },
        { field: 'data.srcip', operator: 'non_empty_string' },
        { field: 'data.srcuser', operator: 'non_empty_string' },
        { field: 'data.count', operator: 'numeric_string_between', value: [3, 8] },
      ],
    },
    evidence: 'bf-11~bf-19의 T1110 count는 3~8이며 성공 동반, 비정상 주소, 비밀번호 변경, 두 계정, 불규칙 간격 또는 잠금 후 시도 등 추가 맥락이 있습니다.',
  },
  {
    name: '고빈도 실패와 구체적인 공격 징후',
    mitreTechnique: 'T1110',
    classification: 'high_confidence_suspicious',
    condition: {
      all: [
        { field: 'rule.mitre', operator: 'array_includes', value: 'T1110' },
        { field: 'data.srcip', operator: 'non_empty_string' },
        { field: 'data.srcuser', operator: 'non_empty_string' },
        { field: 'data.count', operator: 'numeric_string_gte', value: 15 },
        {
          field: 'rule.description',
          operator: 'contains_any',
          value: ['같은 주소', '한 글자씩 바꿔', '성공은 없습니다'],
        },
      ],
    },
    evidence: '단시간 같은 주소의 48/61건, 한 글자씩 바꾼 40건, 또는 성공 없는 90건은 T1110과 출발 IP·계정 정보가 함께 기록됩니다.',
  },
];

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

function uniqueAccountCount(value) {
  if (typeof value !== 'string') return null;
  const accounts = value.split(',').map((account) => account.trim()).filter(Boolean);
  return new Set(accounts).size;
}

function matchesCondition(condition, alert) {
  if (Array.isArray(condition.all)) {
    for (const item of condition.all) {
      if (!matchesCondition(item, alert)) return false;
    }
    return true;
  }
  if (Array.isArray(condition.any)) {
    for (const item of condition.any) {
      if (matchesCondition(item, alert)) return true;
    }
    return false;
  }

  const value = readField(alert, condition.field);
  switch (condition.operator) {
    case 'array_includes':
      return Array.isArray(value) && value.includes(condition.value);
    case 'non_empty_string':
      return typeof value === 'string' && value.trim().length > 0;
    case 'numeric_string_gte': {
      const count = parseCount(value);
      return count !== null && count >= condition.value;
    }
    case 'numeric_string_between': {
      const count = parseCount(value);
      return count !== null && count >= condition.value[0] && count <= condition.value[1];
    }
    case 'contains_any':
      return typeof value === 'string' && condition.value.some((part) => value.includes(part));
    case 'comma_separated_count_gte': {
      const count = uniqueAccountCount(value);
      return count !== null && count >= condition.value;
    }
    default:
      return false;
  }
}

function hasTechnique(alert) {
  const mitre = readField(alert, 'rule.mitre');
  return Array.isArray(mitre) && mitre.includes('T1110');
}

function decideSafely(alert) {
  if (alert === null || typeof alert !== 'object' || Array.isArray(alert)) {
    return result(0.1, '경보 객체가 아니어서 판단 근거가 없습니다.');
  }

  for (const pattern of PATTERNS) {
    if (matchesCondition(pattern.condition, alert)) {
      const confidence = pattern.classification === 'review_only' ? 0.65 : 0.9;
      return result(confidence, `${pattern.classification === 'review_only' ? '검토 필요' : '고신뢰 의심'}: ${pattern.name}`);
    }
  }

  const count = parseCount(readField(alert, 'data.count'));
  const description = readField(alert, 'rule.description');
  const hasFailureDescription = typeof description === 'string' && description.includes('실패');
  const hasSourceIp = typeof readField(alert, 'data.srcip') === 'string';
  const techniquePresent = hasTechnique(alert);

  if (!techniquePresent && count !== null && count >= 15 && hasFailureDescription && hasSourceIp) {
    return result(0.6, '고빈도 실패와 출발 IP는 있으나 T1110 근거가 없어 추가 검토가 필요합니다.');
  }
  if (techniquePresent && count === null) {
    return result(0.55, 'T1110 경보지만 count가 없거나 유효하지 않아 반복 횟수를 판단할 수 없습니다.');
  }
  if (techniquePresent && count !== null && count >= 3) {
    return result(0.58, 'T1110 실패는 있으나 고신뢰 패턴과 일치하지 않아 검토가 필요합니다.');
  }
  if (techniquePresent) {
    return result(0.35, 'T1110만으로는 반복 공격을 입증할 수 없습니다.');
  }
  return result(0.1, 'T1110 또는 반복 실패 근거가 없습니다.');
}

export function decide(alert) {
  try {
    return decideSafely(alert);
  } catch {
    return result(0.1, '경보 형식이 올바르지 않아 안전하게 기록만 합니다.');
  }
}