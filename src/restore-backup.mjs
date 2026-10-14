import {createHash, timingSafeEqual} from 'node:crypto';

export const sha256 = value => createHash('sha256').update(value, 'utf8').digest('hex');
export function equalDigest(actual, expected) {
  return typeof actual === 'string' && typeof expected === 'string'
    && /^[a-f0-9]{64}$/i.test(actual) && /^[a-f0-9]{64}$/i.test(expected)
    && timingSafeEqual(Buffer.from(actual,'hex'),Buffer.from(expected,'hex'));
}
const object = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const uuid = value => typeof value === 'string' && /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/i.test(value);

// Only environment bytes are the backup. No DB snapshot, file or live-content fallback.
export function readVerifiedBackup(env=process.env, requestedId) {
  const raw=env.RESTORE_NOTE_BACKUP_JSON;
  const outer=env.RESTORE_NOTE_BACKUP_SHA256;
  if(typeof raw!=='string'||raw.length===0||typeof outer!=='string'||!outer)
    return {ok:false,code:'BACKUP_UNAVAILABLE',status:503};
  if(Buffer.byteLength(raw,'utf8')>1024*1024||!equalDigest(sha256(raw),outer))
    return {ok:false,code:'BACKUP_UNVERIFIED',status:503};
  let document;
  try {document=JSON.parse(raw);} catch {return {ok:false,code:'BACKUP_UNVERIFIED',status:503};}
  const records=Array.isArray(document?.notes)?document.notes
    : Array.isArray(document)?document
    : [document?.note ?? document?.backup?.note ?? document?.memo ?? document];
  if(!records.length||records.some(record=>!object(record)))
    return {ok:false,code:'BACKUP_UNVERIFIED',status:503};
  const matches=requestedId?records.filter(record=>typeof(record.id??record.noteId)==='string'&&(record.id??record.noteId).toLowerCase()===requestedId.toLowerCase()):records;
  if(matches.length===0) return {ok:false,code:'BACKUP_NOTE_NOT_FOUND',status:404};
  if(matches.length!==1) return {ok:false,code:'BACKUP_UNVERIFIED',status:503};
  const record=matches[0];
  const id=record.id??record.noteId;
  const ownerId=record.owner_id??record.ownerId;
  const content=record.content??record.body;
  const contentSha256=record.contentSha256??record.content_sha256??record.bodySha256
    ??document?.contentSha256??document?.content_sha256??document?.bodySha256;
  if(!uuid(id)||!uuid(ownerId)||typeof content!=='string'||content.length>20000
      ||(record.title!==undefined&&(typeof record.title!=='string'||record.title.length>200))
      ||!equalDigest(sha256(content),contentSha256))
    return {ok:false,code:'BACKUP_UNVERIFIED',status:503};
  return {ok:true,backup:Object.freeze({id,ownerId,title:record.title,content,contentSha256:sha256(content)})};
}
