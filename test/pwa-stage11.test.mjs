import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {runInNewContext} from 'node:vm';

test('offline worker caches only the public fallback and never handles API or mutation requests',async()=>{
 const handlers=new Map(),cached=[],deleted=[];
 let offline=false,networkCalls=0;
 const fallback=new Response('public offline notice');
 const context={URL,Response,
  self:{location:{origin:'https://vault.example'},clients:{claim:async()=>{}},addEventListener:(type,handler)=>handlers.set(type,handler)},
  caches:{open:async()=>({add:async path=>cached.push(path),match:async path=>path==='/offline.html'?fallback:null}),keys:async()=>['vault-public-offline-old','unrelated-cache'],delete:async key=>deleted.push(key)},
  fetch:async()=>{networkCalls++;if(offline)throw new Error('offline');return new Response('network only');},
 };
 runInNewContext(readFileSync(new URL('../public/sw.js',import.meta.url),'utf8'),context);
 let work;handlers.get('install')({waitUntil:promise=>work=promise});await work;
 assert.deepEqual(cached,['/offline.html']);
 handlers.get('activate')({waitUntil:promise=>work=promise});await work;
 assert.deepEqual(deleted,['vault-public-offline-old']);
 for(const [url,method,mode] of [
  ['https://vault.example/api/notes','GET','same-origin'],
  ['https://vault.example/api/auth/session','GET','same-origin'],
  ['https://vault.example/api/notes','POST','same-origin'],
  ['https://vault.example/api/notes/audit','GET','navigate'],
  ['https://foreign.example/','GET','navigate'],
 ]) handlers.get('fetch')({request:{url,method,mode},respondWith(){assert.fail('protected request intercepted');}});
 assert.equal(networkCalls,0);
 handlers.get('fetch')({request:{url:'https://vault.example/',method:'GET',mode:'navigate'},respondWith:promise=>work=promise});
 assert.equal(await (await work).text(),'network only');assert.deepEqual(cached,['/offline.html']);
 offline=true;
 handlers.get('fetch')({request:{url:'https://vault.example/',method:'GET',mode:'navigate'},respondWith:promise=>work=promise});
 assert.equal(await (await work).text(),'public offline notice');assert.deepEqual(cached,['/offline.html']);
});

test('installation event never approves a device; offline clears visible protected data',()=>{
 const elements=new Map();
 const element=()=>({textContent:'',hidden:false,className:'',addEventListener(){},replaceChildren(){this.cleared=true;},reset(){this.cleared=true;}});
 const document={querySelector:selector=>{if(!elements.has(selector))elements.set(selector,element());return elements.get(selector);}};
 const events=new Map();
 const context={document,navigator:{onLine:true},window:{matchMedia:()=>({matches:false}),addEventListener:(name,handler)=>events.set(name,handler),location:{reload(){}}}};
 const script=readFileSync(new URL('../public/pwa.js',import.meta.url),'utf8').replace('export function showDeviceStatus','function showDeviceStatus');
 runInNewContext(script,context);
 context.showDeviceStatus({user:{},device:{registered:false,source:'server'}});
 const before=elements.get('#deviceStatus').textContent;
 events.get('appinstalled')();assert.equal(elements.get('#deviceStatus').textContent,before);
 context.showDeviceStatus({user:{},device:{registered:true,source:'browser'}});
 assert.ok(elements.get('#deviceStatus').textContent.includes('미완료'));
 context.navigator.onLine=false;events.get('offline')();
 assert.equal(elements.get('#notePanel').hidden,true);
 assert.equal(elements.get('#notes').cleared,true);
 assert.equal(elements.get('#noteForm').cleared,true);
});
