import {readSessionCookie} from '../../src/auth-session.mjs';
import fs from 'node:fs';
import {createLoginVerifier} from '../../src/verify-login.mjs';
import {getAuditHistory} from '../../src/restore-state.mjs';

export default async function handler(request,response) {
 response.setHeader('Cache-Control','no-store');
 if(request.method!=='GET') return response.status(405).json({error:'METHOD_NOT_ALLOWED'});
 if(request.url?.split('?')[0]!=='/api/notes/audit')
  return response.status(404).json({error:'RESOURCE_NOT_FOUND'});
 const secretKey=process.env.SUPABASE_SECRET_KEY;
 if(!secretKey) return response.status(503).json({error:'SERVICE_UNAVAILABLE'});
 let config;
 try{config=JSON.parse(fs.readFileSync(new URL('../../aleph.config.json',import.meta.url),'utf8'));}
 catch{return response.status(503).json({error:'SERVICE_UNAVAILABLE'});}
 let authorization=request.headers?.authorization;
 if(!authorization){
  const cookie=readSessionCookie(request,secretKey);
  if(cookie) authorization='Bearer '+cookie.access_token;
 }
 let session;
 try{session=await createLoginVerifier({config,supabaseSecretKey:secretKey})(authorization);}
 catch{session=null;}
 if(!session) return response.status(401).json({error:'AUTH_REQUIRED'});
 const auditHistory=getAuditHistory(session.userId);
 return response.status(200).json({auditHistory,entries:auditHistory,scope:'current_runtime'});
}
