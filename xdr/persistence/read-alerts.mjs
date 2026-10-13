import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
const source = new URL('../fixtures/persistence.json', import.meta.url);
const fields = ['timestamp','srcip','srcuser','level','description'];
const text = (v) => typeof v === 'string' ? v : null;
export async function readAlerts() {
  const doc = JSON.parse(await readFile(source,'utf8'));
  if(doc?.schema!=='aleph.xdr.fixture.v1'||doc.moduleKey!=='persistence'||!Array.isArray(doc.alerts))
    throw new Error('경보 파일 형식 오류');
  return doc.alerts.map((a)=>({
    timestamp:text(a?.timestamp),srcip:text(a?.data?.srcip),srcuser:text(a?.data?.srcuser),
    level:typeof a?.rule?.level==='number'&&Number.isFinite(a.rule.level)?a.rule.level:null,
    description:text(a?.rule?.description)
  }));
}
const main = process.argv[1] && resolve(process.argv[1])===resolve(fileURLToPath(import.meta.url));
if(main){
  try{
    const rows=await readAlerts();
    console.log(JSON.stringify({extractedCount:rows.length,missingFields:Object.fromEntries(
      fields.map(f=>[f,rows.filter(row=>row[f]===null).length]))},null,2));
  }catch{console.error('경보 읽기 실패');process.exitCode=1;}
}
