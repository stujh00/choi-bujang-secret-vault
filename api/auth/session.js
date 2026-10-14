import {createClient} from '@supabase/supabase-js';
import fs from 'node:fs';
import {randomBytes} from 'node:crypto';
import {authEnvironment,clearSessionCookie,readSessionCookie,writeSessionCookie,readJsonBody,requestOriginAllowed} from '../../src/auth-session.mjs';
import {createLoginVerifier} from '../../src/verify-login.mjs';
import {deviceRegistry,safeDeviceState} from '../../src/device-registration.mjs';

const unverified=()=>({registered:false,status:'unverified',source:'server',requestId:null});
function anonymous(response){clearSessionCookie(response);return response.status(200).json({user:null,device:unverified()});}
export default async function handler(req,res) {
  res.setHeader('Cache-Control','no-store');
  if(!['GET','POST'].includes(req.method))return res.status(405).json({error:'METHOD_NOT_ALLOWED'});
  if(req.method==='POST'&&!requestOriginAllowed(req))return res.status(403).json({error:'ORIGIN_NOT_ALLOWED'});
  const env=authEnvironment();
  if(env.error)return res.status(503).json({error:'AUTH_UNAVAILABLE',message:env.error});
  const session=readSessionCookie(req,env.secretKey);
  if(!session)return req.method==='GET'?anonymous(res):res.status(401).json({error:'AUTH_REQUIRED'});
  try {
    const config=JSON.parse(fs.readFileSync(new URL('../../aleph.config.json',import.meta.url),'utf8'));
    const auth=createClient(env.url,env.publishableKey,{auth:{autoRefreshToken:false,persistSession:false,detectSessionInUrl:false}});
    const {data,error}=await auth.auth.setSession(session);
    if(error||!data.session)return req.method==='GET'?anonymous(res):res.status(401).json({error:'AUTH_REQUIRED'});
    const login=await createLoginVerifier({config,supabaseSecretKey:env.secretKey})('Bearer '+data.session.access_token);
    if(login?.kind!=='student')return res.status(401).json({error:'AUTH_REQUIRED'});
    const identity=await auth.auth.getUser(data.session.access_token);
    if(identity.error||identity.data?.user?.id!==login.userId)return res.status(401).json({error:'AUTH_REQUIRED'});
    const id=session.device_id??randomBytes(8).toString('hex');
    writeSessionCookie(res,{...data.session,device_id:id},env.secretKey);
    const client=createClient(env.url,env.secretKey,{auth:{autoRefreshToken:false,persistSession:false,detectSessionInUrl:false}});
    const registry=deviceRegistry(client);
    let row;
    if(req.method==='POST') {
      let body;try{body=readJsonBody(req);}catch{return res.status(400).json({error:'INVALID_BODY'});}
      if(!body||Array.isArray(body)||Object.keys(body).join(',')!=='action'||body.action!=='request')
        return res.status(400).json({error:'INVALID_BODY'});
      row=await registry.request(login.userId,id);
    } else row=await registry.get(login.userId,id);
    if(row.error)return res.status(503).json({error:'DEVICE_REGISTRY_UNAVAILABLE'});
    const device=safeDeviceState(row.data,login.userId,id);
    return res.status(req.method==='POST'&&!device.registered?202:200).json({user:{email:identity.data.user.email??null},device});
  }catch{return res.status(502).json({error:'AUTH_PROVIDER_UNAVAILABLE'});}
}
