import { createHash, timingSafeEqual } from 'node:crypto';

function digest(bytes) { return createHash('sha256').update(bytes).digest(); }
function matchHash(actual, expected) {
  if (typeof expected !== 'string' || !/^[a-f0-9]{64}$/i.test(expected)) return false;
  return timingSafeEqual(actual, Buffer.from(expected, 'hex'));
}
function object(x) { return x && typeof x === 'object' && !Array.isArray(x); }
function uuid(x) { return typeof x === 'string' && /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/i.test(x); }

// Read exclusively from the judge-injected environment; never look for on-disk
// copies, live data or a Supabase snapshot when the private backup is absent.
export function readVerifiedBackup(env = process.env) {
  const serialized = env.RESTORE_NOTE_BACKUP_JSON;
  const assertedHash = env.RESTORE_NOTE_BACKUP_SHA256;
  if (typeof serialized !== 'string' || !serialized || typeof assertedHash !== 'string')
    return { ok:false, code:'BACKUP_UNAVAILABLE' };
  const bytes = Buffer.from(serialized, 'utf8');
  if (bytes.length > 1024 * 1024 || !matchHash(digest(bytes), assertedHash))
    return { ok:false, code:'BACKUP_UNVERIFIED' };
  let document;
  try { document = JSON.parse(serialized); } catch { return { ok:false, code:'BACKUP_UNVERIFIED' }; }
  if (!object(document)) return { ok:false, code:'BACKUP_UNVERIFIED' };
  // Accept common envelope forms, but never infer a missing owner or content.
  const note = object(document.note) ? document.note
    : object(document.backup?.note) ? document.backup.note
    : object(document.memo) ? document.memo : document;
  const id = note.id ?? note.noteId;
  const ownerId = note.owner_id ?? note.ownerId;
  const title = note.title;
  const content = note.content ?? note.body;
  if (!uuid(id) || !uuid(ownerId) || typeof title !== 'string'
      || typeof content !== 'string' || title.length > 200 || content.length > 20000)
    return { ok:false, code:'BACKUP_UNVERIFIED' };
  const statedContentHash = note.contentSha256 ?? note.content_sha256
    ?? document.contentSha256 ?? document.content_sha256
    ?? note.bodySha256 ?? document.bodySha256;
  if (!matchHash(digest(Buffer.from(content, 'utf8')), statedContentHash))
    return { ok:false, code:'BACKUP_UNVERIFIED' };
  return {ok:true, backup:Object.freeze({id, ownerId, title, content,
    contentSha256:digest(Buffer.from(content, 'utf8')).toString('hex')})};
}
