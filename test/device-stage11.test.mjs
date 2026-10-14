import {createServer} from 'node:http';
import assert from 'node:assert/strict';
import {test} from 'node:test';
import {randomUUID} from 'node:crypto';
import {readFileSync} from 'node:fs';
import {runInNewContext} from 'node:vm';
import {generateKeyPair,exportJWK,SignJWT} from 'jose';
import sessionHandler from '../api/auth/session.js';
import notesHandler from '../api/notes.js';
import noteHandler from '../api/notes/[id].js';
import {writeSessionCookie,readSessionCookie} from '../src/auth-session.mjs';
import {safeDeviceState} from '../src/device-registration.mjs';

const response=()=>({headers:new Map(),code:0,data:null,setHeader(k,v){this.headers.set(k.toLowerCase(),v);},status(n){this.code=n;return this;},json(data){this.data=data;return this;}});
test('pending device cannot read, server approval opens own notes, revocation closes it; client claims cannot approve',async()=>{
 const config=JSON.parse(readFileSync(new URL('../aleph.config.json',import.meta.url)));
 const {publicKey,privateKey}=await generateKeyPair('ES256');
 const jwk={...await exportJWK(publicKey),kid:'device-fixture',alg:'ES256',use:'sig'};
 const owner=randomUUID(),other=randomUUID(),noteId=randomUUID(),otherId=randomUUID();
 const user={id:owner,email:'device-fixture@example.test',aud:'authenticated',role:'authenticated'};
 const token=await new SignJWT({role:'authenticated'}).setProtectedHeader({alg:'ES256',kid:jwk.kid})
   .setIssuer(config.identityProvider.issuer).setAudience(config.identityProvider.audience).setSubject(owner)
   .setIssuedAt().setExpirationTime('10m').sign(privateKey);
 const otherToken=await new SignJWT({role:'authenticated'}).setProtectedHeader({alg:'ES256',kid:jwk.kid})
   .setIssuer(config.identityProvider.issuer).setAudience(config.identityProvider.audience).setSubject(other)
   .setIssuedAt().setExpirationTime('10m').sign(privateKey);
 const names=['SUPABASE_URL','SUPABASE_PUBLISHABLE_KEY','SUPABASE_SECRET_KEY'];
 const old=names.map(name=>[name,process.env[name]]);
 Object.assign(process.env,{SUPABASE_URL:new URL(config.identityProvider.issuer).origin,SUPABASE_PUBLISHABLE_KEY:'fixture-public',SUPABASE_SECRET_KEY:'fixture-private'});
 const originalFetch=globalThis.fetch,devices=[];let noteRequests=0,unavailable=false;
 const content=randomUUID();const records=[{id:noteId,owner_id:owner,title:'Own',content},{id:otherId,owner_id:other,title:'Other',content:randomUUID()}];
 globalThis.fetch=async(input,options={})=>{
  const url=new URL(String(input));
  if(url.hostname==='127.0.0.1')return originalFetch(input,options);
  if(url.pathname.endsWith('/.well-known/jwks.json'))return Response.json({keys:[jwk]});
  if(url.pathname.endsWith('/user'))return Response.json(user);
  if(url.pathname.endsWith('/rest/v1/vault_devices')) {
   if(unavailable)return Response.json({message:'unavailable'},{status:503});
   if(options.method==='POST') {
    const row={id:randomUUID(),...JSON.parse(options.body)};devices.push(row);return Response.json(row,{status:201});
   }
   const matches=devices.filter(row=>url.searchParams.get('owner_id')==='eq.'+row.owner_id&&url.searchParams.get('device_id')==='eq.'+row.device_id);
   return Response.json(matches);
  }
  assert.ok(url.pathname.endsWith('/rest/v1/vault_notes'));noteRequests++;
  return Response.json(records.filter(row=>(!url.searchParams.get('id')||url.searchParams.get('id')==='eq.'+row.id||(url.searchParams.get('id').startsWith('neq.')&&url.searchParams.get('id').slice(4)!==row.id))
    &&url.searchParams.get('owner_id')==='eq.'+row.owner_id));
 };
 let cookie;
 const c=response();writeSessionCookie(c,{access_token:token,refresh_token:'fixture-refresh',device_id:'1234567890abcdef'},process.env.SUPABASE_SECRET_KEY);
 cookie=c.headers.get('set-cookie').split(';')[0];
 const server=createServer(async(req,res)=>{
  let body='';for await(const part of req)body+=part;
  req.body=body?JSON.parse(body):undefined;
  const handler=req.url==='/api/auth/session'?sessionHandler:req.url==='/api/notes'?notesHandler:noteHandler;
  const out={setHeader:(name,value)=>res.setHeader(name,value),status(code){res.statusCode=code;return this;},json(value){res.setHeader('Content-Type','application/json');res.end(JSON.stringify(value));}};
  try {await handler(req,out);}catch{res.statusCode=500;res.end('{}');}
 });
 await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
 const base='http://127.0.0.1:'+server.address().port;
 const invoke=async(_handler,method,url,body,extra={})=>{
  const r=await fetch(base+url,{method,headers:{cookie,host:'vault.example',origin:'https://vault.example','x-forwarded-host':'vault.example','x-forwarded-proto':'https',
    ...(body!==undefined?{'Content-Type':'application/json'}:{}),...extra},
    ...(body!==undefined?{body:JSON.stringify(body)}:{})});
  const set=r.headers.get('set-cookie');if(set)cookie=set.split(';')[0];
  return {code:r.status,data:await r.json()};
 };
 try {
  assert.equal((await invoke(notesHandler,'GET','/api/notes')).code,403);assert.equal(noteRequests,0);
  const pending=await invoke(sessionHandler,'POST','/api/auth/session',{action:'request'});
  assert.equal(pending.code,202);assert.equal(pending.data.device.registered,false);assert.equal(devices.length,1);
  assert.equal(readSessionCookie({headers:{cookie}},process.env.SUPABASE_SECRET_KEY).device_id,'1234567890abcdef');
  assert.equal((await invoke(sessionHandler,'POST','/api/auth/session',{action:'request',registered:true})).code,400);
  assert.equal((await invoke(notesHandler,'GET','/api/notes',undefined,{'x-device-approved':'true'})).code,403);
  assert.equal(noteRequests,0);
  devices[0].status='approved';devices[0].approved_at=new Date(Date.now()-1000).toISOString();devices[0].expires_at=new Date(Date.now()+60000).toISOString();
  const approved=await invoke(sessionHandler,'GET','/api/auth/session');assert.equal(approved.data.device.registered,true);
  const own=await invoke(notesHandler,'GET','/api/notes');assert.equal(own.code,200);assert.equal(own.data.length,1);
  assert.equal((await invoke(noteHandler,'GET','/api/notes/'+otherId)).code,404);
  assert.equal((await invoke(notesHandler,'GET','/api/notes',undefined,{authorization:'Bearer '+otherToken})).code,403);
  const audit=JSON.stringify(approved.data);assert.equal(audit.includes(token),false);assert.equal(audit.includes('fixture-refresh'),false);
  unavailable=true;assert.equal((await invoke(notesHandler,'GET','/api/notes')).code,503);unavailable=false;
  devices[0].status='revoked';assert.equal((await invoke(notesHandler,'GET','/api/notes')).code,403);
  const blocked=await invoke(sessionHandler,'POST','/api/auth/session',{action:'request'},{origin:'https://evil.example'});assert.equal(blocked.code,403);
  assert.equal(devices.length,1);
 } finally {
  await new Promise(resolve=>server.close(resolve));
  globalThis.fetch=originalFetch;for(const [name,value]of old){if(value===undefined)delete process.env[name];else process.env[name]=value;}
 }
});

test('expired or foreign-owned approval is never registered',()=>{
 const row={id:randomUUID(),owner_id:'owner',device_id:'1234567890abcdef',status:'approved',approved_at:new Date(Date.now()-2000).toISOString(),expires_at:new Date(Date.now()-1000).toISOString()};
 assert.equal(safeDeviceState(row,'owner',row.device_id).registered,false);
 row.expires_at=new Date(Date.now()+60000).toISOString();assert.equal(safeDeviceState(row,'other',row.device_id).registered,false);
});

test('browser makes no protected request before server approval, including after approval-button click',async()=>{
 const elements=new Map(),calls=[];let approved=false;
 const el=()=>({hidden:false,disabled:false,value:'',events:new Map(),addEventListener(name,cb){this.events.set(name,cb);},replaceChildren(){},reset(){},textContent:'',className:''});
 const document={querySelector(selector){if(!elements.has(selector))elements.set(selector,el());return elements.get(selector);},createTextNode:value=>value};
 const window={confirm:()=>false};
 const fetch=async(path,options={})=>{
  calls.push({path,method:options.method??'GET'});
  if(path==='/api/auth/session')return Response.json({user:{email:'fixture@example.test'},device:{registered:approved,status:approved?'approved':'pending',source:'server',requestId:'fixture'}},{status:options.method==='POST'?202:200});
  assert.equal(path,'/api/notes');assert.equal(approved,true);return Response.json([]);
 };
 const html=readFileSync(new URL('../public/index.html',import.meta.url),'utf8');
 const script=html.match(/<script type="module">([\s\S]*?)<\/script>/)[1].replace(/import \{ showDeviceStatus \} from "\/pwa.js";/,'');
 await runInNewContext('(async()=>{'+script+'})()',{document,window,navigator:{onLine:true},fetch,Response,showDeviceStatus(){}});
 assert.equal(calls.filter(x=>x.path==='/api/notes').length,0);assert.equal(elements.get('#notePanel').hidden,true);
 await elements.get('#requestDeviceButton').events.get('click')();
 assert.equal(calls.filter(x=>x.path==='/api/notes').length,0);assert.equal(elements.get('#notePanel').hidden,true);
 approved=true;await elements.get('#refreshDeviceButton').events.get('click')();
 assert.equal(calls.filter(x=>x.path==='/api/notes').length,1);assert.equal(elements.get('#notePanel').hidden,false);
});
