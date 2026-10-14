import assert from 'node:assert/strict';
import {test} from 'node:test';
import {createServer} from 'node:http';
import {readFileSync} from 'node:fs';
import {randomUUID} from 'node:crypto';
import {generateKeyPair,exportJWK,SignJWT} from 'jose';
import restore from '../api/restore/notes/[id].js';
import noteRead from '../api/notes/[id].js';
import audit from '../api/notes/audit.js';
import operations from '../api/operations.js';
import {sha256} from '../src/restore-backup.mjs';

test('HTTP flow with signed tokens: real restore, public GET retests, audit retention, rejection contracts',async()=>{
 const config=JSON.parse(readFileSync(new URL('../aleph.config.json',import.meta.url)));
 const {publicKey,privateKey}=await generateKeyPair('ES256');
 const jwk={...await exportJWK(publicKey),kid:'runtime-test',alg:'ES256',use:'sig'};
 const A=randomUUID(),B=randomUUID(),run=randomUUID(),id=randomUUID(),otherId=randomUUID();
 const pristine={id,owner_id:B,title:'Test',content:randomUUID()};
 const foreign={id:otherId,owner_id:A,title:'Other',content:randomUUID()};
 const rows=new Map([[id,{...pristine,content:randomUUID()}],[otherId,{...foreign}]]);
 const requests=[],mutations=[];
 const raw=JSON.stringify({note:{...pristine,contentSha256:sha256(pristine.content)}});
 const names=['SUPABASE_URL','SUPABASE_SECRET_KEY','RESTORE_NOTE_BACKUP_JSON','RESTORE_NOTE_BACKUP_SHA256'];
 const saved=names.map(name=>[name,process.env[name]]);
 Object.assign(process.env,{SUPABASE_URL:new URL(config.identityProvider.issuer).origin,
   SUPABASE_SECRET_KEY:'test-only-server-key',RESTORE_NOTE_BACKUP_JSON:raw,RESTORE_NOTE_BACKUP_SHA256:sha256(raw)});
 const realFetch=globalThis.fetch;
 globalThis.fetch=async(input,init={})=>{
  const url=new URL(typeof input==='string'?input:input.url??input.href);
  if(url.hostname==='127.0.0.1') return realFetch(input,init);
  if(url.href===config.judgeIssuer+'/.well-known/jwks.json') return new Response(JSON.stringify({keys:[jwk]}),{headers:{'content-type':'application/json'}});
  assert.equal(url.origin,new URL(config.identityProvider.issuer).origin);
  assert.equal(url.pathname,'/rest/v1/vault_notes');
  const method=init.method??'GET';
  const headers=new Headers(init.headers);
  requests.push({method,id:url.searchParams.get('id'),owner:url.searchParams.get('owner_id')});
  let selected=[...rows.values()];
  for(const [name,condition] of url.searchParams) {
   if(!['id','owner_id'].includes(name)) continue;
   const [op,...parts]=condition.split('.');const value=parts.join('.');
   selected=selected.filter(row=>op==='eq'?row[name]===value:op==='neq'?row[name]!==value:true);
  }
  if(method==='PATCH') {
   const patch=JSON.parse(init.body);selected=selected.map(row=>({...row,...patch}));
   for(const row of selected){rows.set(row.id,row);mutations.push(row.id);}
  } else if(method==='POST') {
   const row=JSON.parse(init.body);rows.set(row.id,row);mutations.push(row.id);selected=[row];
  } else assert.equal(method,'GET');
  if(url.searchParams.get('limit')) selected=selected.slice(0,Number(url.searchParams.get('limit')));
  const body=headers.get('accept')?.includes('vnd.pgrst.object')?selected[0]:selected;
  return new Response(JSON.stringify(body),{headers:{'content-type':'application/json'}});
 };
 const server=createServer(async(req,res)=>{
  let body='';for await(const chunk of req) body+=chunk;
  req.body=body?JSON.parse(body):undefined;
  const response={setHeader:(k,v)=>res.setHeader(k,v),status(code){res.statusCode=code;return this;},json(data){res.setHeader('Content-Type','application/json');res.end(JSON.stringify(data));}};
  try {
   if(req.url.startsWith('/api/restore/notes/')) await restore(req,response);
   else if(req.url==='/api/notes/audit') await audit(req,response);
   else if(req.url==='/api/operations') await operations(req,response);
   else await noteRead(req,response);
  }catch{res.statusCode=500;res.end('{}');}
 });
 await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
 const base='http://127.0.0.1:'+server.address().port;
 const token=async(owner,identity)=>new SignJWT({aleph_run:run,aleph_role:'judge',aleph_identity:identity})
   .setProtectedHeader({alg:'ES256',kid:jwk.kid}).setIssuer(config.judgeIssuer)
   .setAudience(new URL(config.publicAppUrl).hostname).setSubject(owner)
   .setIssuedAt().setExpirationTime('5m').sign(privateKey);
 const bToken=await token(B,'b'),aToken=await token(A,'a');
 const call=async(path,method='GET',credential=bToken,body)=>{
  const r=await fetch(base+path,{method,headers:{Authorization:'Bearer '+credential,...(body!==undefined?{'content-type':'application/json'}:{})},...(body!==undefined?{body:JSON.stringify(body)}:{})});
  return {status:r.status,data:await r.json()};
 };
 try {
  const before=(await call('/api/notes/audit')).data.entries;
  const restored=await call('/api/restore/notes/'+id,'POST');
  assert.equal(restored.status,200);assert.equal(restored.data.restored,true);
  assert.equal(restored.data.restore.retests.ownRead.httpStatus,200);
  assert.equal(restored.data.restore.retests.otherReadDenied.httpStatus,404);
  assert.equal(rows.get(id).content,pristine.content);assert.deepEqual(rows.get(otherId),foreign);
  assert.deepEqual(mutations,[id]);
  assert.equal(JSON.stringify(restored.data).includes(pristine.content),false);
  assert.ok(requests.some(x=>x.method==='GET'&&x.id==='eq.'+otherId&&x.owner==='eq.'+B));
  const history=(await call('/api/notes/audit')).data.entries;
  assert.deepEqual(history.slice(0,before.length),before);assert.ok(history.some(x=>x.action==='restore'));
  assert.equal((await call('/api/notes/audit','GET',aToken)).data.entries.length,0);
  assert.equal((await call('/api/restore/notes/'+id,'POST',aToken)).status,403);
  assert.equal((await call('/api/restore/notes/'+id,'POST',bToken,{owner_id:B})).status,400);
  assert.equal((await call('/api/restore/notes/'+otherId,'POST')).status,404);
  delete process.env.RESTORE_NOTE_BACKUP_JSON;
  assert.equal((await call('/api/restore/notes/'+id,'POST')).status,503);
  process.env.RESTORE_NOTE_BACKUP_JSON=raw;
  process.env.RESTORE_NOTE_BACKUP_SHA256='0'.repeat(64);
  assert.equal((await call('/api/restore/notes/'+id,'POST')).status,503);
  assert.deepEqual(mutations,[id]);
  const op=(await call('/api/operations')).data;
  assert.equal(op.checks.find(x=>x.name==='backup_sha256').evidence.at(-1).passed,false);
  assert.equal(op.checks.find(x=>x.name==='stage1_to9_full_live_regression').status,'not_run');
  assert.equal(JSON.stringify(op).includes(pristine.content),false);
 } finally {
  globalThis.fetch=realFetch;
  await new Promise(resolve=>server.close(resolve));
  for(const [name,value] of saved){if(value===undefined)delete process.env[name];else process.env[name]=value;}
 }
});
