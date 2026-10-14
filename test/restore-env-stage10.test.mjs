import assert from 'node:assert/strict';
import {test} from 'node:test';
import {createHash} from 'node:crypto';
import {readVerifiedBackup} from '../src/restore-backup.mjs';
import {getAuditHistory,restoreOneNote} from '../src/restore-env.mjs';
const ID='00000000-0000-4000-8000-000000000005';
const A='11111111-1111-4111-8111-111111111111';
const B='22222222-2222-4222-8222-222222222222';
const sha=s=>createHash('sha256').update(s).digest('hex');
const note={id:ID,owner_id:B,title:'Test note',content:'safe baseline',contentSha256:sha('safe baseline')};
const serialized=JSON.stringify({note});
const env={RESTORE_NOTE_BACKUP_JSON:serialized,RESTORE_NOTE_BACKUP_SHA256:sha(serialized)};
const res=()=>{const state={status:0,payload:null};return {state,setHeader(){},status(code){state.status=code;return {json:(x)=>{state.payload=x;}}}}};
function fakeDb(initial={...note,content:'changed'}) {
 const state={row:initial ? {...initial} : null,writes:0};
 return {state,
 get:async()=>({data:state.row}),
 insert:async(id,owner,title,content)=>{state.writes++;state.row={id,owner_id:owner,title,content};return {data:state.row};},
 update:async(_id,_owner,title,content)=>{state.writes++;state.row={...state.row,title,content};return {data:state.row};},
 getOwned:async(_id,owner)=>({data:state.row?.owner_id===owner?state.row:null}),
 };
}
async function run({body=undefined,user=B,backup=env,id=ID,db=fakeDb(),method='POST'}={}) {
 const response=res();
 await restoreOneNote({method,url:'/api/restore/notes/'+id,
   headers:{authorization:'Bearer fake.jwt.example'},body},response,{
   verifyUser:async()=>user?{userId:user}:null,db,env:backup});
 return {response:response.state,db};
}
test('private snapshot validates both outer raw bytes and inner content hash',()=>{
 assert.equal(readVerifiedBackup(env).ok,true);
 assert.equal(readVerifiedBackup({...env,RESTORE_NOTE_BACKUP_SHA256:'0'.repeat(64)}).ok,false);
 assert.equal(readVerifiedBackup({...env,RESTORE_NOTE_BACKUP_JSON:JSON.stringify({...JSON.parse(serialized),extra:true})}).ok,false);
 const bad=JSON.stringify({note:{...note,contentSha256:'0'.repeat(64)}});
 assert.equal(readVerifiedBackup({RESTORE_NOTE_BACKUP_JSON:bad,RESTORE_NOTE_BACKUP_SHA256:sha(bad)}).ok,false);
 assert.equal(readVerifiedBackup({}).code,'BACKUP_UNAVAILABLE');
});
test('only authenticated B with empty body restores one existing record and runs retests',async()=>{
 const {response,db}=await run();
 assert.equal(response.status,200);assert.equal(db.state.writes,1);
 assert.equal(db.state.row.content,note.content);
 assert.equal(response.payload.contentSha256,note.contentSha256);
 assert.equal(response.payload.retests.ownRead.measured,true);
 assert.equal(response.payload.retests.otherReadDenied.measured,true);
 assert.equal(JSON.stringify(response.payload).includes(note.content),false);
});
test('missing backup never restores',async()=>{
 const {response,db}=await run({backup:{}});
 assert.equal(response.status,503);assert.equal(db.state.writes,0);
});
test('owner mismatch and body injection never restore',async()=>{
 for(const opts of [{user:A},{body:{role:'admin'}},{body:{id:ID}},{id:A}]){
  const {response,db}=await run(opts);
  assert.ok([400,403,404].includes(response.status));assert.equal(db.state.writes,0);
 }
});
test('deleted B note is restored from verified backup with its original ID and owner',async()=>{
 const db=fakeDb(null);
 const {response}=await run({db});
 assert.equal(response.status,200);assert.equal(db.state.writes,1);
 assert.equal(db.state.row.id,ID);assert.equal(db.state.row.owner_id,B);
 assert.equal(db.state.row.content,note.content);
});

test('post-restore read verification failure must not be declared successful',async()=>{
 const db=fakeDb();
 db.getOwned=async(_id,owner)=>({data:owner===B?null:db.state.row});
 const response=res();
 await restoreOneNote({
  method:'POST',url:'/api/restore/notes/'+ID,
  headers:{authorization:'Bearer fake.jwt.example'},body:undefined,
 },response,{verifyUser:async()=>({userId:B}),db,env});
 assert.equal(response.state.status,503);
 assert.equal(response.state.payload.error,'POST_RESTORE_RETEST_FAILED');
 assert.equal(response.state.payload.retests.ownRead.passed,false);
 assert.equal(response.state.payload.retests.otherReadDenied.passed,true);
});

test('all supplied JSON bodies are rejected without writes', async()=>{
 for(const body of [{},[],false,0,'{}','null']) {
  const {response,db}=await run({body});
  assert.equal(response.status,400);assert.equal(db.state.writes,0);
 }
});

test('audit belongs to the verified owner and survives later restores',async()=>{
 const before=getAuditHistory(B).length;
 await run();await run();
 assert.equal(getAuditHistory(B).length,before+4);
 assert.equal(getAuditHistory(A).length,0);
 assert.equal(JSON.stringify(getAuditHistory(B)).includes(note.content),false);
});
test('retest evidence records dispatched GET status in restore.retests',async()=>{
 const {response}=await run();
 assert.equal(response.payload.restore.retests.ownRead.method,'GET');
 assert.equal(response.payload.restore.retests.ownRead.status,200);
 assert.equal(response.payload.restore.retests.otherReadDenied.status,404);
});
