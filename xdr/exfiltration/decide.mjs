// XDR-06: standalone offline evidence-based exfiltration detection.
const PATTERNS = Object.freeze([
  { name: '미확인 목적지로 대량 자료 전송', techniques: ['T1041', 'T1048'], minBytes: 50000000 },
  { name: '비정상 시간 압축 파일 반출', techniques: ['T1048'], minBytes: 50000000 },
  { name: '반복·우회 경로의 대량 외부 전송', techniques: ['T1041', 'T1048'], minCount: 5 },
  { name: '외부 자료 전송 추가 검토', techniques: ['T1041', 'T1048'] },
]);

function outcome(confidence, reason) {
  return {
    action: confidence >= 0.85 ? 'block' : confidence >= 0.5 ? 'alert' : 'record',
    confidence, reason,
  };
}
function nonnegativeInt(value) {
  if (typeof value === 'number') return Number.isSafeInteger(value) && value >= 0 ? value : null;
  if (typeof value !== 'string' || !/^\d+$/.test(value.trim())) return null;
  const converted = Number(value.trim());
  return Number.isSafeInteger(converted) ? converted : null;
}
function addressValid(value) {
  if (typeof value !== 'string' || value.trim() !== value) return false;
  const ip = value.split('.');
  if (ip.length === 4) {
    return ip.every(group => /^\d{1,3}$/.test(group) && Number(group) <= 255
      && String(Number(group)) === group);
  }
  if (!value.includes(':') || /[^a-f\d:]/i.test(value) || value.includes(':::')) return false;
  const compressed = value.includes('::');
  if (compressed && value.indexOf('::') !== value.lastIndexOf('::')) return false;
  const parts = value.split(':').filter(Boolean);
  return parts.every(part => /^[a-f\d]{1,4}$/i.test(part))
    && (compressed ? parts.length < 8 : parts.length === 8);
}
function evaluate(alert) {
  const rule = alert?.rule, data = alert?.data;
  if (!rule || typeof rule !== 'object' || !data || typeof data !== 'object') {
    return outcome(0.1, '전송 관련 필드 부족');
  }

  const mitre = Array.isArray(rule.mitre) ? rule.mitre : [];
  const technique = mitre.includes('T1041') || mitre.includes('T1048');
  const desc = typeof rule.description === 'string' ? rule.description.slice(0, 4096) : '';
  const bytes = nonnegativeInt(data.bytes);
  const files = nonnegativeInt(data.files);
  const count = nonnegativeInt(data.count);
  const destination = addressValid(data.dstip);
  const source = addressValid(data.srcip);
  const unknown = /처음\s*보는|낯선|평소(?:에)?\s*쓰지\s*않던\s*(?:목적지|주소)|미확인\s*(?:목적지|주소)|unknown\s*(?:destination|address)|unfamiliar\s*(?:destination|address)|new\s*destination/i.test(desc);
  const unusualPort = /평소(?:에)?\s*쓰지\s*않던\s*포트|비표준\s*포트|unusual\s*port|nonstandard\s*port/i.test(desc);
  const compressed = /압축\s*(?:파일|자료)|zip|archive/i.test(desc);
  const offHours = /수업\s*시간\s*밖|업무\s*시간\s*밖|영업\s*시간\s*외|근무\s*시간\s*밖|off.hours|outside\s*(?:business|work)\s*hours|after\s*hours/i.test(desc);
  const repeating = /반복|연속|여러\s*번|여러\s*차례|repeated|consecutive|multiple\s*times/i.test(desc);
  const bulkSignal = /대용량|큰\s*파일|대량|한\s*번에|묶음|자료실\s*전체|짧은\s*시간|rapid\s*transfer|bulk\s*transfer|large\s*(?:file|upload|transfer)/i.test(desc);
  const copiedWhole = /자료실\s*전체|전체.*(?:복사|전송)|entire\s*(?:folder|repository)/i.test(desc);
  const commandChannel = /명령\s*통로|명령\s*채널|command[-\s]*(?:and[-\s]*control|channel|tunnel)|\bC2\b/i.test(desc);
  const alteredChannel = unusualPort || commandChannel;
  const splitDestination = /목적지\s*두\s*곳|여러\s*목적지|multiple\s*destinations?/i.test(desc);
  const transferred = /나갔|전송|반출|업로드|올라갔|복사됐|보냈|uploaded|sent|outbound|exfiltrat/i.test(desc);
  const explicitlyUnsent = /전송은\s*아직\s*없|전송은\s*없|전송이\s*실패|failed\s*transfer|not\s*(?:sent|transferred)/i.test(desc);
  const routine = /수업\s*자료\s*주소|평소\s*예약|작은\s*동기화|자료실.*저장|내\s*메모.*(?:읽|저장)|공지를\s*읽|화면\s*새로고침|세션\s*확인|로그아웃|small\s*sync|routine\s*backup/i.test(desc);

  const large = bytes !== null && bytes >= PATTERNS[0].minBytes;
  const manyFiles = files !== null && files >= 40;
  const manyRepeated = count !== null && count >= PATTERNS[2].minCount;
  const strongUnknown = unknown && (manyFiles || bulkSignal || (compressed && (offHours || repeating || splitDestination)) || manyRepeated);
  const strongUnusual = (alteredChannel && (repeating || manyFiles || unknown));
  const strongRepetition = (repeating || manyRepeated) && manyRepeated
    && (offHours || bulkSignal || commandChannel);
  const strongArchive = compressed && (offHours || (unknown && (repeating || splitDestination)));
  const entireCopy = copiedWhole && (manyFiles || bulkSignal);

  // Explicit transmission, validated endpoint and multiple corroborating clues.
  // This is a strong attempt indicator, not proof of successful data theft.
  if (technique && source && destination && transferred && !explicitlyUnsent && large) {
    if (strongUnknown || entireCopy) return outcome(0.93, PATTERNS[0].name);
    if (strongArchive) return outcome(0.93, PATTERNS[1].name);
    if (strongUnusual || strongRepetition) return outcome(0.93, PATTERNS[2].name);
  }

  // A MITRE tag or elevated Wazuh rule level alone never suffices.
  const evidence = /파일|자료|목적지|주소|전송|압축|백업|동기화|통로|포트|upload|transfer|archive|file|destination|network/i.test(desc);
  if (technique && evidence && (unknown || offHours || compressed
    || unusualPort || repeating || bulkSignal || explicitlyUnsent
    || (bytes !== null && bytes >= 100000)
    || (files !== null && files >= 5)
    || (count !== null && count >= 2))) {
    if (routine && bytes !== null && bytes < 100000 && !unknown && !offHours
        && !unusualPort && !explicitlyUnsent) {
      return outcome(0.1, '평소 범위의 정상 자료 이동');
    }
    return outcome(0.65, PATTERNS[3].name);
  }
  return outcome(0.1, '구체적인 비정상 반출 근거 없음');
}

export function decide(alert) {
  try {
    if (!alert || typeof alert !== 'object' || Array.isArray(alert)) {
      return outcome(0.1, '유효한 경보 객체 없음');
    }
    return evaluate(alert);
  } catch {
    return outcome(0.1, '경보 형식 오류로 기록');
  }
}
