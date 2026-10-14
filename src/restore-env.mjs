import {readVerifiedBackup,sha256,equalDigest} from './restore-backup.mjs';
import {appendAudit,getAuditHistory,getOperations,recordCheck} from './restore-state.mjs';
export {getAuditHistory};
export const getRestoreOperations = getOperations;

function hasBody(body) {
  if(body===undefined||body===null||body==='') return false;
  if(typeof body==='string') {
    if(!body.trim()) return false;
    try {body=JSON.parse(body);} catch {return true;}
  }
  // Frameworks may represent a zero-field JSON body as {}; it supplies no data.
  return body===null||typeof body!=='object'||Array.isArray(body)||Object.keys(body).length!==0;
}
export async function restoreOneNote(req,res,{verifyUser,db,readRequest,env=process.env}) {
  res.setHeader('Cache-Control','no-store');
  const send=(status,payload)=>res.status(status).json(payload);
  if(req.method!=='POST') return send(405,{error:'METHOD_NOT_ALLOWED'});
  const match=/^\/api\/(?:restore\/notes|notes\/restore)\/([a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12})\/?$/i.exec(req.url??'');
  if(!match) return send(404,{error:'RESOURCE_NOT_FOUND'});
  if(hasBody(req.body)) return send(400,{error:'BODY_NOT_ALLOWED'});
  let user;
  try {user=await verifyUser(req.headers?.authorization);} catch {user=null;}
  if(typeof user?.userId!=='string'||!user.userId) return send(401,{error:'AUTH_REQUIRED'});
  const reject=(status,error)=>{
    appendAudit({ownerId:user.userId,id:match[1],action:'restore',result:error,status});
    return send(status,{error});
  };
  const verified=readVerifiedBackup(env,match[1]);
  recordCheck('backup_sha256',{status:'measured',passed:verified.ok,httpStatus:verified.ok?200:verified.status});
  if(!verified.ok) return reject(verified.status,verified.code);
  const backup=verified.backup;
  if(user.userId.toLowerCase()!==backup.ownerId.toLowerCase()) return reject(403,'RESTORE_FORBIDDEN');
  try {
    const original=await db.get(backup.id);
    if(original.error) return reject(503,'DATABASE_UNAVAILABLE');
    if(original.data&&original.data.owner_id.toLowerCase()!==backup.ownerId.toLowerCase())
      return reject(403,'RESTORE_FORBIDDEN');
    const title=backup.title??original.data?.title??'';
    const write=original.data?await db.update(backup.id,backup.ownerId,title,backup.content)
      :await db.insert(backup.id,backup.ownerId,title,backup.content);
    if(write.error||!write.data) return reject(503,'RESTORE_FAILED');
    const check=await db.get(backup.id);
    const restored=!check.error&&check.data?.id===backup.id
      &&check.data?.owner_id===backup.ownerId&&typeof check.data.content==='string'
      &&equalDigest(sha256(check.data.content),backup.contentSha256);
    recordCheck('note_restore',{status:'measured',passed:restored,httpStatus:restored?200:503});
    if(!restored) return reject(503,'RESTORE_VERIFICATION_FAILED');
    appendAudit({ownerId:user.userId,id:backup.id,action:'restore',result:'restored',status:200});
    // Execute authenticated GET requests using the exact original request credentials.
    // The forbidden case reads a real foreign note, never an invented principal.
    async function retest(name,id,expected) {
      if(typeof readRequest!=='function'||!id) return {status:'not_run',measured:false,passed:null};
      const request={method:'GET',url:'/api/notes/'+id,headers:{...req.headers}};
      try {
        const result=await readRequest(request);
        const passed=expected.includes(result.status);
        recordCheck(name,{status:'measured',passed,httpStatus:result.status});
        appendAudit({ownerId:user.userId,id,action:'retest',result:passed?'passed':'failed',status:result.status});
        return {status:'measured',measured:true,method:'GET',path:request.url,httpStatus:result.status,passed};
      } catch {
        recordCheck(name,{status:'measured',passed:false,httpStatus:503});
        return {status:'measured',measured:true,httpStatus:503,passed:false};
      }
    }
    const ownRead=await retest('own_read',backup.id,[200]);
    let foreign;
    if(typeof db.findForeign==='function') {
      try {foreign=await db.findForeign(user.userId);} catch {foreign=null;}
    }
    const otherId=!foreign?.error&&foreign?.data?.owner_id!==user.userId?foreign?.data?.id:null;
    const otherReadDenied=await retest('other_read_denied',otherId,[403,404]);
    const retests={ownRead,otherReadDenied};
    return send(200,{id:backup.id,ownerVerified:true,contentSha256:backup.contentSha256,restored:true,
      restore:{retests}});
  } catch {return reject(503,'RESTORE_FAILED');}
}
