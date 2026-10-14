import {readFile,mkdir,writeFile} from 'node:fs/promises';
import {randomUUID} from 'node:crypto';
const config=JSON.parse(await readFile(new URL('../aleph.config.json',import.meta.url),'utf8'));
const base=new URL(config.publicAppUrl);
const results=[];
for(const [name,path,expected] of [['public_operations','/api/operations',200],['anonymous_notes','/api/notes',401],['public_static_data','/data.json',200]]){
 const requestId=randomUUID();const checkedAt=new Date().toISOString();
 try {const response=await fetch(new URL(path+'?checkId='+requestId,base),{redirect:'error',signal:AbortSignal.timeout(10000)});
 results.push({name,scope:'live_api',status:'measured',expected,actual:response.status,passed:response.status===expected,requestId,checkedAt});
 }catch{results.push({name,scope:'live_api',status:'measured',expected,actual:'network_error',passed:false,requestId,checkedAt});}
}
await mkdir(new URL('../artifacts/',import.meta.url),{recursive:true});
await writeFile(new URL('../artifacts/operations-check.json',import.meta.url),JSON.stringify({results,assault:{total:41,status:'not_run'}},null,2)+'\n');
for(const row of results)console.log(`${row.name}: expected ${row.expected}, actual ${row.actual}, ${row.requestId}, ${row.checkedAt}`);
if(results.some(x=>!x.passed))process.exitCode=1;
