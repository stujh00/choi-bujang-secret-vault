import {readSessionCookie,requestOriginAllowed} from '../../../src/auth-session.mjs';
import fs from 'node:fs';
import {createClient} from '@supabase/supabase-js';
import {createLoginVerifier} from '../../../src/verify-login.mjs';
import {restoreOneNote} from '../../../src/restore-env.mjs';

export default async function handler(request,response) {
  response.setHeader('Cache-Control','no-store');
  const url=process.env.SUPABASE_URL, key=process.env.SUPABASE_SECRET_KEY;
  if(!url||!key) return response.status(503).json({error:'SERVICE_UNAVAILABLE'});
  let config;
  try {config=JSON.parse(fs.readFileSync(new URL('../../../aleph.config.json',import.meta.url),'utf8'));}
  catch {return response.status(503).json({error:'SERVICE_UNAVAILABLE'});}
  const verify=createLoginVerifier({config,supabaseSecretKey:key});
  const supabase=createClient(url,key,{auth:{autoRefreshToken:false,persistSession:false,detectSessionInUrl:false}});
  const db={
    get: async id => supabase.from('vault_notes').select('id,owner_id,title,content').eq('id',id).maybeSingle(),
    getOwned: async(id,owner)=>supabase.from('vault_notes').select('id,owner_id,title,content').eq('id',id).eq('owner_id',owner).maybeSingle(),
    insert: async(id,owner,title,content)=>supabase.from('vault_notes').insert({id,owner_id:owner,title,content}).select('id,owner_id,title,content').single(),
    update: async(id,owner,title,content)=>supabase.from('vault_notes').update({title,content}).eq('id',id).eq('owner_id',owner).select('id,owner_id,title,content').maybeSingle(),
  };
  return restoreOneNote(request,response,{
    verifyUser:async authorization=>{
      if(!authorization) {
        const session=readSessionCookie(request,key);
        if(session && !requestOriginAllowed(request)) return null;
        if(session) authorization='Bearer '+session.access_token;
      }
      const login=await verify(authorization);
      if(login?.userId) return {userId:login.userId};
      return null;
    },
    db,
  });
}
