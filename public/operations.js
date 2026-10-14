const $=id=>document.getElementById(id);
function line(parent,text){const p=document.createElement('p');p.textContent=text;parent.append(p);}
async function refresh(){
  $('rows').replaceChildren();$('summary').replaceChildren();$('assault').textContent='미확인';
  $('state').textContent='서버 확인 중…';
  try {
    const response=await fetch('/api/operations',{cache:'no-store',credentials:'omit'});
    if(!response.ok)throw new Error('HTTP '+response.status);
    const data=await response.json();if(data.schema!=='vault.operations.v1')throw new Error('응답 형식 오류');
    $('state').textContent=`HTTP ${response.status} · 요청 ${data.requestId} · ${data.checkedAt} · 커밋 ${data.commit??'로컬 미지정'}`;
    line($('summary'),'판정기 규칙: '+data.policyRules.join(', '));
    line($('summary'),'탐지 가상 사건: '+data.detection.results.map(x=>`${x.name} → ${x.actual}`).join(' / '));
    line($('summary'),'실제 신원 회수: '+data.revocation.status+' · 제안은 회수 완료가 아닙니다.');
    line($('summary'),`복구 사본 버전 ${data.restore.version} · 메모 복구 ${data.restore.status} · 정책 적용 ${data.restore.policyApply.status}`);
    for(const check of data.checks)line($('summary'),`${check.name}: ${check.status} · 현재 런타임 기록 ${check.evidence.length}개`);
    for(const row of data.regression){const tr=document.createElement('tr');for(const text of [row.name+' / '+row.scope,row.status,row.expected,row.actual??'미실행',(row.requestId??'—')+' / '+(row.checkedAt??'—')]){const td=document.createElement('td');td.textContent=text;tr.append(td);}$('rows').append(tr);}
    for(const [name,path,expected] of [['public_operations','/api/operations',200],['anonymous_notes','/api/notes',401]]){
      const requestId=crypto.randomUUID(),checkedAt=new Date().toISOString();
      let actual;try{actual=(await fetch(path+'?checkId='+requestId,{cache:'no-store',credentials:'omit'})).status;}catch{actual='network_error';}
      const tr=document.createElement('tr');for(const text of [name+' / live_api','measured',String(expected),String(actual),requestId+' / '+checkedAt]){const td=document.createElement('td');td.textContent=text;tr.append(td);}$('rows').append(tr);
    }
    $('assault').textContent=`총 ${data.assault.total}종 · 실측 ${data.assault.measured} · 미실행 ${data.assault.notRun} · 판정 출처 ${data.assault.source}. 서버 연습을 총공세 통과로 합산하지 않습니다.`;
  }catch(error){$('state').textContent='확인 실패: '+error.message;}
}
$('refresh').addEventListener('click',refresh);refresh();
