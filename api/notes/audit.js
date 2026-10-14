import fs from 'node:fs';
import {createLoginVerifier} from '../../src/verify-login.mjs';
import {readVerifiedBackup} from '../../src/restore-backup.mjs';
import {getAuditHistory} from '../../src/restore-env.mjs';

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
 let session;
 try{session=await createLoginVerifier({config,supabaseSecretKey:secretKey})(request.headers?.authorization);}
 catch{session=null;}
 if(!session) return response.status(401).json({error:'AUTH_REQUIRED'});
 const verified=readVerifiedBackup();
 if(!verified.ok) return response.status(503).json({error:'BACKUP_UNAVAILABLE'});
 const owner=verified.backup.ownerId;
 if(!(session.kind==='judge'&&session.identity==='b') &&
   !(session.kind==='student'&&session.userId===owner))
   return response.status(403).json({error:'AUDIT_FORBIDDEN'});
 // This log is process-local; production platform stdout also stores events.
 return response.status(200).json({entries:getAuditHistory().filter(x=>x.id===verified.backup.id),scope:'current_runtime'});
}
