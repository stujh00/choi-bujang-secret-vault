// XDR-05 standalone decision engine. No external dependencies or state.
const PATTERNS = Object.freeze([
  { name: '비정상 관리자 그룹 권한 획득', technique: 'T1078' },
  { name: '새 관리자 권한 또는 도용 권한 명령 실행', technique: 'T1068/T1078' },
  { name: '관리자 권한 재부여 및 대량 변경', technique: 'T1078' },
  { name: '권한 변화 및 사용 정황 추가 검토', technique: 'T1068/T1078' },
]);

function decision(confidence, reason) {
  return {
    action: confidence >= 0.85 ? 'block' : confidence >= 0.5 ? 'alert' : 'record',
    confidence, reason,
  };
}
function countOf(v) {
  if (typeof v === 'number') return Number.isSafeInteger(v) && v >= 0 ? v : null;
  if (typeof v !== 'string' || !/^\d+$/.test(v.trim())) return null;
  const n = Number(v.trim());
  return Number.isSafeInteger(n) ? n : null;
}
function userOf(v) {
  return typeof v === 'string' && /^[a-z0-9][a-z0-9_.@-]{1,127}$/i.test(v) ? v : null;
}
function validIp(v) {
  if (typeof v !== 'string' || v.trim() !== v) return false;
  const parts = v.split('.');
  if (parts.length === 4) return parts.every(p => /^\d{1,3}$/.test(p)
    && Number(p) <= 255 && String(Number(p)) === p);
  if (!v.includes(':') || /[^0-9a-f:]/i.test(v) || v.includes(':::')) return false;
  const compressed = v.includes('::');
  if (compressed && v.indexOf('::') !== v.lastIndexOf('::')) return false;
  const p = v.split(':').filter(Boolean);
  return p.every(g => /^[0-9a-f]{1,4}$/i.test(g))
    && (compressed ? p.length < 8 : p.length === 8);
}
function analyze(a) {
  const rule = a?.rule, data = a?.data;
  if (!rule || typeof rule !== 'object' || !data || typeof data !== 'object') {
    return decision(0.1, '권한 이벤트 근거 부족');
  }
  const desc = typeof rule.description === 'string' ? rule.description.slice(0, 4096) : '';
  const tags = Array.isArray(rule.mitre) ? rule.mitre : [];
  const tagged = tags.includes('T1068') || tags.includes('T1078');
  const user = userOf(data.srcuser);
  const ip = validIp(data.srcip);
  const group = typeof data.group === 'string' ? data.group.trim().toLowerCase() : '';
  const adminGroup = /^(administrators?|local[ -]?administrators?|domain[ -]?admins?|enterprise[ -]?admins?|sudo|wheel|root)$/.test(group);
  const otherGroup = group.length > 0 && !adminGroup;
  const adminGroupDesc = /관리자\s*그룹|admin(?:istrator)?s?\s*group|domain\s*admins|sudo\s*group|wheel\s*group/i.test(desc);
  const added = /추가(?:됐|되었|되었습니다|됨|한|된)?|들어가|들어왔|승격|assigned|added|joined|granted|member\s*added/i.test(desc);
  const remote = /원격\s*주소|remote\s*(?:ip|address)/i.test(desc);
  const unknown = /처음\s*보는\s*주소|요청\s*주소는\s*처음|낯선\s*주소|unknown\s*(?:ip|address)|new\s*(?:ip|address)/i.test(desc);
  const unusualTime = /수업\s*시간\s*밖|업무처럼\s*보이지\s*않는\s*시각|업무\s*시간\s*밖|out(?:side)?\s*(?:of\s*)?(?:business\s*)?hours|after\s*hours|off.hours/i.test(desc);
  const adminCommand = /관리자\s*명령|권한\s*명령|admin(?:istrator)?\s*command|elevated\s*command/i.test(desc);
  const command = adminCommand || /명령\s*실행|execut(?:e|ed)\s*(?:a\s*)?command/i.test(desc);
  const newlyAdmin = /방금\s*관리자가\s*된|곧바로\s*권한\s*명령|관리자\s*그룹에\s*들어가고|recent(?:ly)?\s*(?:promoted|elevated)/i.test(desc);
  const ordinary = /평범한\s*계정|일반\s*계정|standard\s*user|non.admin/i.test(desc);
  const sessionElevated = /세션.*(?:관리자\s*권한|높은\s*권한).*(?:바뀌|변경|상승)|session.*(?:elevated|privilege\s*change)/i.test(desc);
  const otherIdentity = /다른\s*계정의\s*권한|다른\s*사용자의\s*권한|impersonat|another\s*account.s\s*privilege/i.test(desc);
  const reAdded = /(?:빠진|제거|탈퇴).*(?:다시\s*관리자|재추가|재가입)|(?:removed|left).*(?:readded|rejoined|added\s*back)/i.test(desc);
  const manyAccounts = /계정\s*\d+\s*개|여러\s*계정|multiple\s*accounts|several\s*accounts/i.test(desc);
  const repeated = countOf(data.count);
  const negativeMembership = /관리자\s*그룹은\s*아닙니다|not\s*(?:an?\s*)?admin/i.test(desc);

  const joinedAdmins = !otherGroup && !negativeMembership
    && (adminGroup || adminGroupDesc) && added;

  if (tagged && user && ip) {
    if (joinedAdmins && reAdded) return decision(0.93, PATTERNS[2].name);
    if (joinedAdmins && manyAccounts && repeated !== null && repeated >= 3) {
      return decision(0.93, PATTERNS[2].name);
    }
    if (joinedAdmins && (remote || (ordinary && command) || (unusualTime && command))) {
      return decision(0.93, PATTERNS[0].name);
    }
    if ((newlyAdmin && adminCommand) || (unusualTime && unknown && adminCommand)
      || (sessionElevated && unknown) || (otherIdentity && adminCommand)) {
      return decision(0.93, PATTERNS[1].name);
    }
  }

  if (tagged && /관리자|권한|그룹|계정|elevat|admin|privilege|group|account/i.test(desc)) {
    return decision(0.65, PATTERNS[3].name);
  }
  return decision(0.1, '실제 권한 상승 또는 도용 근거 없음');
}

export function decide(alert) {
  try {
    if (!alert || typeof alert !== 'object' || Array.isArray(alert)) {
      return decision(0.1, '유효한 경보 객체 없음');
    }
    return analyze(alert);
  } catch {
    return decision(0.1, '경보 형식 오류로 기록');
  }
}
