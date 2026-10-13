import assert from 'node:assert/strict';
import {test} from 'node:test';
import {restoreAuthorizedTestNote,TEST_B_NOTE_ID} from '../src/restore-note.mjs';

function response() {
 const state={statusCode:null,body:null,headers:new Map()};
 state.res={setHeader:(name,value)=>state.headers.set(name,value),status:(code)=>({json:(value)=>{state.statusCode=code;state.body=value;return state.res;}})};
 return state;
}
const hash='a'.repeat(64);
const reply={data:{restored:true,noteId:TEST_B_NOTE_ID,ownerVerified:true,contentSha256:hash}};
const access={kind:'judge',identity:'b',runId:'11111111-1111-4111-8111-111111111111'};
async function call(overrides={},options={}) {
 let count=0;
 const state=response();
 await restoreAuthorizedTestNote({
  method:'POST',url:'/api/restore',
  headers:{authorization:'Bearer abc.def.ghi'},
  body:{id:TEST_B_NOTE_ID},
  ...overrides,
 },state.res,{
  verifyAuthorization:options.verifyAuthorization ?? (async()=>access),
  restoreFromBackup:async()=>{count++;return options.result ?? reply;},
 });
 return {...state,count};
}
test('verified judge B may restore exactly one matching private backup',async()=>{
 const done=await call();
 assert.equal(done.statusCode,200);
 assert.equal(done.count,1);
 assert.deepEqual(done.body,{restored:true,noteId:TEST_B_NOTE_ID,contentSha256:hash,ownerVerified:true});
 assert.equal(done.headers.get('Cache-Control'),'no-store');
});
test('unauthenticated, students, and judge A cannot call recovery',async()=>{
 for(const val of [null,{kind:'student',userId:'x'},{kind:'judge',identity:'a',runId:'id'}]){
  const done=await call({}, {verifyAuthorization:async()=>val});
  assert.equal(done.statusCode,val?403:401);
  assert.equal(done.count,0);
 }
 const none=await call({headers:{}});
 assert.equal(none.statusCode,401);assert.equal(none.count,0);
});
test('only configured restore route and exact B target accepted',async()=>{
 for(const url of ['/api/restore?force=1','/api/restore/','/api/restor%65']){
  const done=await call({url});assert.equal(done.statusCode,404);assert.equal(done.count,0);
 }
 for(const body of [{id:'00000000-0000-4000-8000-000000000001'},{noteId:'other'},{targetId:1}]){
  const done=await call({body});assert.equal(done.statusCode,403);assert.equal(done.count,0);
 }
 assert.equal((await call({method:'GET'})).statusCode,405);
});
test('backup unavailable or invalid hash is fail closed',async()=>{
 for(const result of [{error:{message:'missing'}},{data:{...reply.data,contentSha256:'bad'}},{data:{...reply.data,ownerVerified:false}}]){
  const done=await call({}, {result});assert.equal(done.statusCode,503);
 }
});
