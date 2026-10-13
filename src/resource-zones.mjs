// Server-side resource boundary definitions. Never derive ownership or roles from UI fields.
export const ANNOUNCEMENT_ID = '00000000-0000-4000-8000-0000000000f0';
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

export function isNoteId(value) {
  return typeof value === 'string' && UUID.test(value) && value.toLowerCase() !== ANNOUNCEMENT_ID;
}
export function isAnnouncementId(value) {
  return typeof value === 'string' && value.toLowerCase() === ANNOUNCEMENT_ID;
}
export function exactRoute(request, group) {
  if (!['notes', 'announcements'].includes(group)) return null;
  let url;
  try { url = new URL(request?.url, 'https://local.invalid'); } catch { return null; }
  // No query selector, percent-encoded path tricks, trailing slash or function alias.
  if (url.search || url.hash || url.pathname.includes('%')) return null;
  const collection = '/api/' + group;
  if (url.pathname === collection) return { type: 'list' };
  if (!url.pathname.startsWith(collection + '/')) return null;
  const id = url.pathname.slice(collection.length + 1);
  if (group === 'notes' ? isNoteId(id) : isAnnouncementId(id)) {
    return { type: 'item', id: id.toLowerCase() };
  }
  return null;
}

export function verifiedStudent(login) {
  return login?.kind === 'student' && typeof login.userId === 'string'
    && /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(login.userId);
}

// Instructor status is a server-managed Supabase Auth app_metadata value.
// This cannot be set through user_metadata, note payloads, request headers or URL.
export async function verifiedInstructor(login, supabase) {
  if (!verifiedStudent(login) || typeof supabase?.auth?.admin?.getUserById !== 'function') return false;
  try {
    const { data, error } = await supabase.auth.admin.getUserById(login.userId);
    return !error && data?.user?.id === login.userId
      && data.user.app_metadata?.vault_role === 'instructor';
  } catch {
    return false;
  }
}

export function validNotePayload(payload) {
  return payload && typeof payload === 'object' && !Array.isArray(payload)
    && typeof payload.title === 'string' && typeof payload.body === 'string'
    && payload.title.length <= 200 && payload.body.length <= 20000
    && !Object.keys(payload).some(key => ['owner_id', 'ownerId', 'role', 'zone', 'isInstructor', 'app_metadata'].includes(key));
}
