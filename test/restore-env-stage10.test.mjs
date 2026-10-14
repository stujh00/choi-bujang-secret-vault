import assert from 'node:assert/strict';
import {test} from 'node:test';
import {randomUUID} from 'node:crypto';
import {sha256,readVerifiedBackup} from '../src/restore-backup.mjs';
import {restoreOneNote,getAuditHistory} from '../src/restore-env.mjs';
import {readOwnedNote} from '../src/note-read.mjs';
import {getOperations} from '../src/restore-state.mjs';
const ID='00000000-0000-4000-8000-000000000005';
const OTHER='00000000-0000-4000-8000-000000000004';
const A='11111111-1111-4111-8111-111111111111';
const B='22222222-2222-4222-8222-222222222222';
const baseline=()=>({id:ID,owner_id:B,title:'Test',content:randomUUID()});
function environment(document) {
 const raw=JSON.stringify(document);
 return {RESTORE_NOTE_BACKUP_JSON:raw,RESTORE_NOTE_BACKUP_SHA256:sha256(raw)};
}
function response() {return {code:0,payload:null,setHeader(){},status(n){this.code=n;return this;},json(x){this.payload=x;}};}
function database(note,deleted=false) {
 const foreign={id:OTHER,owner_id:A,title:'Other',content:randomUUID()};
 const rows=new Map([[OTHER,foreign]]);
 if(!deleted) rows.set(ID,{...note,content:randomUUID()});
 const writes=[];
 return {rows,writes,get:async id=>({data:rows.get(id)??null}),
 getOwned:async(id,owner)=>({data:rows.get(id)?.owner_id===owner?rows.get(id):null}),
 findForeign:async owner=>({data:[...rows.values()].find(row=>row.owner_id!==owner)??null}),
 insert:async(id,owner_id,title,content)=>{writes.push(id);const row={id,owner_id,title,content};rows.set(id,row);return {data:row};},
 update:async(id,owner_id,title,content)=>{writes.push(id);const row={...rows.get(id),owner_id,title,content};rows.set(id,row);return {data:row};}};
}
async function run(options={}) {
 const note=options.note??baseline();note.contentSha256=sha256(note.content);
 const db=options.db??database(note,options.deleted);
 const env=options.env??environment({note});
 const calls=[];const res=response();
 const request={method:options.method??'POST',url:options.url??'/api/restore/notes/'+ID,headers:{authorization:'test-credential'},body:options.body};
 await restoreOneNote(request,res,{env,db,verifyUser:async()=>options.user===null?null:{userId:options.user??B},
 readRequest:options.noReads?undefined:async req=>{
  calls.push({method:req.method,path:req.url,credentialSame:req.headers.authorization===request.headers.authorization});
  const r=response();await readOwnedNote(req,r,{login:{userId:options.user??B},db});return {status:r.code};
 }});
 return {res,db,note,calls};
}
test('both hashes checked and serialized backup is freshly read',()=>{
 const note=baseline();note.contentSha256=sha256(note.content);
 const env=environment({note});assert.equal(readVerifiedBackup(env,ID).ok,true);
 assert.equal(readVerifiedBackup({...env,RESTORE_NOTE_BACKUP_SHA256:'0'.repeat(64)},ID).ok,false);
 const bad=environment({note:{...note,contentSha256:'0'.repeat(64)}});
 assert.equal(readVerifiedBackup(bad,ID).ok,false);
 assert.equal(readVerifiedBackup({},ID).status,503);
 assert.equal(readVerifiedBackup(env,OTHER).status,404);
});
test('title is not an extra mandatory backup contract field',()=>{
 const note=baseline();note.contentSha256=sha256(note.content);delete note.title;
 assert.equal(readVerifiedBackup(environment({note}),ID).ok,true);
});
test('restore one corrupted row, preserve foreign row, run real GET paths with same credential',async()=>{
 const {res,db,note,calls}=await run();
 assert.equal(res.code,200);assert.deepEqual(db.writes,[ID]);assert.equal(db.rows.get(ID).content,note.content);
 assert.deepEqual(calls.map(c=>c.path),['/api/notes/'+ID,'/api/notes/'+OTHER]);
 assert.ok(calls.every(c=>c.credentialSame&&c.method==='GET'));
 assert.equal(res.payload.restore.retests.ownRead.httpStatus,200);
 assert.equal(res.payload.restore.retests.otherReadDenied.httpStatus,404);
 assert.equal(JSON.stringify(res.payload).includes(note.content),false);
});
test('a deleted note is inserted once using backup ID and owner',async()=>{
 const {res,db}=await run({deleted:true});assert.equal(res.code,200);
 assert.deepEqual(db.writes,[ID]);assert.equal(db.rows.get(ID).owner_id,B);
});
test('body fields, primitives and arrays return exactly 400 with no writes',async()=>{
 for(const body of [{owner_id:B},{role:'admin'},{content:'injection'},[],false,0,'broken','null']) {
  const {res,db}=await run({body});assert.equal(res.code,400);assert.equal(db.writes.length,0);
 }
});
test('framework empty-body representations supply no restore input',async()=>{
 for(const body of [undefined,null,'',{},'{}']) assert.equal((await run({body})).res.code,200);
});
test('missing snapshot 503, wrong ID 404, other owner 403, no login 401, no writes',async()=>{
 for(const [options,expected] of [[{env:{}},503],[{url:'/api/restore/notes/'+OTHER},404],[{user:A},403],[{user:null},401]]) {
  const {res,db}=await run(options);assert.equal(res.code,expected);assert.equal(db.writes.length,0);
 }
});
test('tampered outer or inner snapshot never mutates DB',async()=>{
 const note=baseline();note.contentSha256=sha256(note.content);
 for(const env of [{...environment({note}),RESTORE_NOTE_BACKUP_SHA256:'0'.repeat(64)},environment({note:{...note,contentSha256:'0'.repeat(64)}})]) {
  const {res,db}=await run({env});assert.equal(res.code,503);assert.equal(db.writes.length,0);
 }
});
test('audit is append-only, owner-filtered, and response mutation cannot erase history',async()=>{
 const before=getAuditHistory(B);await run();const first=getAuditHistory(B);
 assert.deepEqual(first.slice(0,before.length),before);first.splice(0);await run();
 assert.ok(getAuditHistory(B).length>before.length);
 assert.ok(getAuditHistory(A).every(entry=>entry.result==='RESTORE_FORBIDDEN'));
});
test('module reload preserves audit history in the runtime',async()=>{
 await run();const before=getAuditHistory(B);
 const reloaded=await import('../src/restore-state.mjs?reload='+randomUUID());
 assert.deepEqual(reloaded.getAuditHistory(B),before);
});
test('unexecuted checks stay not_run, and failures are measured failures',async()=>{
 const {res}=await run({noReads:true});assert.equal(res.payload.restore.retests.ownRead.status,'not_run');
 const {res:failed}=await run({env:{}});assert.equal(failed.code,503);
 assert.equal(getOperations().find(x=>x.name==='backup_sha256').evidence.at(-1).passed,false);
});
test('database exceptions become safe failures without leaking content',async()=>{
 const note=baseline();const db=database(note);db.get=async()=>{throw new Error(note.content);};
 const {res}=await run({note,db});assert.equal(res.code,503);assert.equal(JSON.stringify(res.payload).includes(note.content),false);
});
