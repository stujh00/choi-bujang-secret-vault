// Standalone XDR evaluation: no imports, external state or filesystem access.
const PATTERNS = Object.freeze([
  { name:'서명 없는 신규·변경 서비스 지속성', mitre:'T1543', minimumCount:3 },
  { name:'낯선 예약 작업의 임시 실행 파일', mitre:'T1053' },
  { name:'비인가 시작 프로그램 및 예약 작업 연계', mitre:'T1543/T1053' },
  { name:'지속성 의심 이벤트 추가 검토', mitre:'T1543/T1053' },
]);
function output(confidence, reason) {
  return {action:confidence >= 0.85?'block':confidence >= 0.5?'alert':'record',confidence,reason};
}
function countOf(v) {
  if(typeof v==='number')return Number.isSafeInteger(v)&&v>=0?v:null;
  if(typeof v!=='string'||!/^\d+$/.test(v.trim()))return null;
  const n=Number(v.trim());return Number.isSafeInteger(n)?n:null;
}
function evaluate(a){
  const rule=a?.rule, data=a?.data;
  if(!rule||typeof rule!=='object'||!data||typeof data!=='object')
    return output(0.1,'지속성 판정에 필요한 경보 필드 없음');
  const desc=typeof rule.description==='string'?rule.description.slice(0,4096):'';
  const path=typeof data.path==='string'?data.path.slice(0,4096):'';
  const mitre=Array.isArray(rule.mitre)?rule.mitre:[];
  const serviceTech=mitre.includes('T1543'),taskTech=mitre.includes('T1053');
  const service=/서비스|service|daemon/i.test(desc);
  const task=/예약\s*작업|scheduled\s*task|task\s*scheduler|schtasks/i.test(desc);
  const startup=/시작\s*(?:폴더|프로그램|항목)|startup|run\s*key/i.test(desc);
  const unsigned=/서명(?:이|은)?\s*(?:없는|없습니다|없음|되지|안\s*된)|미서명|서명\s*검증\s*실패|unsigned|untrusted\s*signature/i.test(desc);
  const registered=/새(?:로운)?|처음|등록|추가|생성|생겼|new\b|creat|install|register|persist|남도록/i.test(desc);
  const changedBinary=/실행\s*파일.*(?:바뀌|변경|교체)|(?:binary|executable|image\s*path).*(?:changed|replaced|modified)/i.test(desc);
  const unlisted=/평소\s*목록에\s*없는|목록에\s*없는|처음\s*보는|낯선|모르는|알지\s*못|평소\s*없던|미등록|알\s*수\s*없는|unexpected|unknown|unrecognized/i.test(desc);
  const offHours=/시간\s*밖|야간|비정상\s*시간|outside\s*hours|off.hours/i.test(desc);
  const randomName=/임의\s*문자열|무작위\s*이름|random\s*name|randomized\s*name/i.test(desc);
  const repeated=/연속|반복|여러\s*건|multiple|repeated/i.test(desc);
  const persists=/다시\s*켜도\s*남|재부팅\s*후|자동\s*실행|살아남|persist|autostart/i.test(desc);
  const added=/추가|등록|생겼|새(?:로운)?|creat|added|installed/i.test(desc);
  const tempExecutable=/(?:^|[\\/])(?:temp|tmp)[\\/][^\\/]*\.(?:exe|dll|cmd|bat|ps1|sh)$/i.test(path)
    || /appdata[\\/]local[\\/]temp[\\/].+\.(?:exe|dll|cmd|bat|ps1)$/i.test(path);
  const startupFolder=/[\\/]start menu[\\/]programs[\\/]startup[\\/]|[\\/]startup[\\/]/i.test(path);
  const count=countOf(data.count);
  const highService=serviceTech&&service&&(
    unsigned&&(registered||changedBinary)&&(tempExecutable||(repeated&&count!==null&&count>=PATTERNS[0].minimumCount))
    ||unlisted&&(registered||persists)&&tempExecutable);
  const highTask=taskTech&&task&&tempExecutable&&(unlisted||randomName||(registered&&offHours));
  const combined=serviceTech&&taskTech&&startup&&task&&tempExecutable;
  const highStartup=serviceTech&&startup&&unlisted&&added&&startupFolder;
  if(highService||highTask||combined||highStartup){
    return output(0.92,highService?PATTERNS[0].name:highTask?PATTERNS[1].name:PATTERNS[2].name);
  }
  // Benign maintenance with ATT&CK tags is still ordinary activity.
  if(/운영체제\s*업데이트.*평소|기존.*서명된\s*채|시작\s*프로그램\s*목록을\s*읽기만|기존\s*예약\s*작업.*복사를\s*마쳤|normal\s*(?:update|scheduled)|signed\s*existing\s*service/i.test(desc))
    return output(0.1,'기존 정상 작업으로 기록');
  if((serviceTech||taskTech)&&(service||task||startup||tempExecutable||changedBinary||unlisted||registered))
    return output(0.65,PATTERNS[3].name);
  return output(0.1,'구체적인 지속성 공격 근거 없음');
}
export function decide(alert){
  try{
    if(!alert||typeof alert!=='object'||Array.isArray(alert))return output(0.1,'유효한 경보 객체 없음');
    return evaluate(alert);
  }catch{return output(0.1,'경보 형식 오류로 기록');}
}
