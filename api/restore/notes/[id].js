import fs from 'node:fs';
import {createClient} from '@supabase/supabase-js';
import {createLoginVerifier} from '../../../src/verify-login.mjs';
import {readSessionCookie,requestOriginAllowed} from '../../../src/auth-session.mjs';
import {restoreOneNote} from '../../../src/restore-env.mjs';
import noteHandler from '../../notes/[id].js';

// Return only status metadata from the actual public GET handler; discard its body.
export async function executeNoteRead(request) {
  let status=0;
  const response={setHeader(){},status(value){status=value;return this;},json(){},end(){}};
  await noteHandler(request,response);
  return {status};
}
export function createRestoreHandler({verifyUser,db,readRequest,env=process.env}) {
  return (req,res)=>restoreOneNote(req,res,{verifyUser,db,readRequest,env});
}
export default async function handler(req,res) {
  res.setHeader('Cache-Control','no-store');
  const url=process.env.SUPABASE_URL,key=process.env.SUPABASE_SECRET_KEY;
  if(!url||!key) return res.status(503).json({error:'SERVICE_UNAVAILABLE'});
  let config;
  try {config=JSON.parse(fs.readFileSync(new URL('../../../aleph.config.json',import.meta.url),'utf8'));}
  catch {return res.status(503).json({error:'SERVICE_UNAVAILABLE'});}
  const verify=createLoginVerifier({config,supabaseSecretKey:key});
  const client=createClient(url,key,{auth:{autoRefreshToken:false,persistSession:false,detectSessionInUrl:false}});
  const select='id,owner_id,title,content';
  const db={
    get:id=>client.from('vault_notes').select(select).eq('id',id).maybeSingle(),
    findForeign:owner=>client.from('vault_notes').select('id,owner_id')
      .neq('owner_id',owner).neq('id','00000000-0000-4000-8000-0000000000f0').limit(1).maybeSingle(),
    insert:(id,owner,title,content)=>client.from('vault_notes').insert({id,owner_id:owner,title,content}).select(select).single(),
    update:(id,owner,title,content)=>client.from('vault_notes').update({title,content}).eq('id',id).eq('owner_id',owner).select(select).maybeSingle(),
  };
  return createRestoreHandler({db,readRequest:executeNoteRead,verifyUser:async authorization=>{
    if(!authorization) {
      const cookie=readSessionCookie(req,key);
      if(cookie&&!requestOriginAllowed(req)) return null;
      if(cookie) authorization='Bearer '+cookie.access_token;
    }
    const login=await verify(authorization);
    return login?.userId?login:null;
  }})(req,res);
}
