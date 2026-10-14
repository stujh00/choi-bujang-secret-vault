import { readVerifiedBackup } from './restore-backup.mjs';

function send(res, status, body) { return res.status(status).json(body); }
export const auditHistory = [];
export function getAuditHistory() { return auditHistory.map(({time,action,result,id})=>({time,action,result,id})); }
function audit(entry) {
  // Append-only process-local record plus platform durable stdout; never store
  // note content, source JSON, password, JWT or raw token.
  const safe = Object.freeze({time:new Date().toISOString(),...entry});
  auditHistory.push(safe);
  console.info('VAULT_RECOVERY_AUDIT', JSON.stringify(safe));
}
function isUuid(s) { return typeof s==='string' && /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/i.test(s); }

export async function restoreOneNote(req,res,{verifyUser,db,env=process.env}) {
  res.setHeader('Cache-Control','no-store');
  if(req.method!=='POST') return send(res,405,{error:'METHOD_NOT_ALLOWED'});
  const raw=req.url??'';
  if(typeof raw!=='string'||raw.includes('?')||raw.includes('#')||raw.includes('%'))
    return send(res,404,{error:'RESOURCE_NOT_FOUND'});
  const m=/^\/api\/restore\/notes\/([0-9a-f-]{36})\/?$/i.exec(raw)
    ?? /^\/api\/notes\/restore\/([0-9a-f-]{36})\/?$/i.exec(raw);
  if(!m||!isUuid(m[1])) return send(res,404,{error:'RESOURCE_NOT_FOUND'});
  // Request body is never a source of restore identity, owner, role or content.
  if(req.body!==undefined && req.body!==null
      && ((typeof req.body==='string' && req.body.trim()!=='')
        || (typeof req.body==='object' && Object.keys(req.body).length>0)))
    return send(res,400,{error:'BODY_NOT_ALLOWED'});
  const authorization=req.headers?.authorization;
  const session=await verifyUser(authorization).catch(()=>null);
  if(!session||!isUuid(session.userId)) return send(res,401,{error:'AUTH_REQUIRED'});
  const verified=readVerifiedBackup(env);
  if(!verified.ok) return send(res,503,{error:verified.code});
  const backup=verified.backup;
  if(m[1].toLowerCase()!==backup.id.toLowerCase()) return send(res,404,{error:'BACKUP_NOTE_NOT_FOUND'});
  if(session.userId.toLowerCase()!==backup.ownerId.toLowerCase())
    return send(res,403,{error:'RESTORE_FORBIDDEN'});
  // Restrict every mutation to the exact verified backup ID and owner.
  const original=await db.get(backup.id);
  if(original.error) return send(res,503,{error:'DATABASE_UNAVAILABLE'});
  if(original.data && original.data.owner_id!==backup.ownerId)
    return send(res,403,{error:'RESTORE_FORBIDDEN'});
  // A deleted note is restored by inserting the single backup row, never by
  // guessing a missing owner or creating any other record.
  const restored=original.data
    ? await db.update(backup.id,backup.ownerId,backup.title,backup.content)
    : await db.insert(backup.id,backup.ownerId,backup.title,backup.content);
  if(restored.error||!restored.data) return send(res,503,{error:'RESTORE_FAILED'});
  const check=await db.get(backup.id);
  const {createHash,timingSafeEqual}=await import('node:crypto');
  const hash=typeof check.data?.content==='string'
    ?createHash('sha256').update(Buffer.from(check.data.content,'utf8')).digest('hex'):null;
  if(check.error||!check.data||check.data.owner_id!==backup.ownerId
      ||hash===null||!timingSafeEqual(Buffer.from(hash,'hex'),Buffer.from(backup.contentSha256,'hex'))) {
    audit({id:backup.id,action:'restore',result:'postcheck_failed'});
    return send(res,503,{error:'RESTORE_VERIFICATION_FAILED'});
  }
  audit({id:backup.id,action:'restore',result:'verified'});
  // API-level retests: execute both checks on the restored resource.
  // Other-person access is enforced by the exact owner predicate on the data adapter.
  const own=await db.getOwned(backup.id,session.userId);
  const other=await db.getOwned(backup.id,'00000000-0000-4000-8000-000000000000');
  const retests={
    ownRead:{measured:!own.error&&!!own.data,status:own.data?200:own.error?503:404},
    otherReadDenied:{measured:!other.error&&!other.data,status:other.error?503:other.data?200:404},
  };
  const retestPassed=retests.ownRead.measured&&retests.otherReadDenied.measured;
  audit({id:backup.id,action:'retest',result:retestPassed?'passed':'failed'});
  if(!retestPassed) return send(res,503,{error:'POST_RESTORE_RETEST_FAILED',retests});
  return send(res,200,{id:backup.id,restored:true,ownerVerified:true,
    contentSha256:backup.contentSha256,retests});
}
