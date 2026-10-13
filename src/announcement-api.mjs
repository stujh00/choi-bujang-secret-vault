import fs from 'node:fs';
import { readSessionCookie, requestOriginAllowed, readJsonBody } from './auth-session.mjs';
import { createLoginVerifier } from './verify-login.mjs';
import { ANNOUNCEMENT_ID, exactRoute, validNotePayload, verifiedInstructor } from './resource-zones.mjs';

function readConfig() {
  return JSON.parse(fs.readFileSync(new URL('../aleph.config.json', import.meta.url), 'utf8'));
}
function safeAnnouncement(data) {
  return { id: data.id, title: data.title, body: data.content };
}

// One reserved UUID in the existing table: no existing notes or DB schema are changed.
// Students may read a published announcement but only server-confirmed instructors
// may create, update, or remove it.
export async function handleAnnouncement(request, response, kind) {
  response.setHeader('Cache-Control', 'no-store');
  const route = exactRoute(request, 'announcements');
  if (!route || route.type !== kind) {
    return response.status(404).json({ error: 'RESOURCE_NOT_FOUND' });
  }
  const methodAllowed = (kind === 'list' && ['GET', 'POST'].includes(request.method))
    || (kind === 'item' && ['GET', 'PUT', 'DELETE'].includes(request.method));
  if (!methodAllowed) return response.status(405).json({ error: 'METHOD_NOT_ALLOWED' });

  const secretKey = process.env.SUPABASE_SECRET_KEY;
  const url = process.env.SUPABASE_URL;
  if (!secretKey || !url) {
    return response.status(503).json({ error: 'NOTES_UNAVAILABLE' });
  }
  let authorization = request.headers?.authorization;
  const bearer = typeof authorization === 'string'
    && /^Bearer [A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/u.test(authorization);
  if (!bearer) {
    const session = readSessionCookie(request, secretKey);
    if (session && ['POST', 'PUT', 'DELETE'].includes(request.method)
        && !requestOriginAllowed(request)) {
      return response.status(403).json({ error: 'ORIGIN_NOT_ALLOWED' });
    }
    if (session) authorization = 'Bearer ' + session.access_token;
  }
  const login = await createLoginVerifier({ config: readConfig(), supabaseSecretKey: secretKey })(authorization);
  if (!login || login.kind !== 'student') {
    return response.status(401).json({ error: 'AUTH_REQUIRED' });
  }
  const { createClient } = await import('@supabase/supabase-js');
  const supabase = createClient(url, secretKey);

  if (request.method === 'GET') {
    const { data, error } = await supabase.from('vault_notes')
      .select('id,title,content').eq('id', ANNOUNCEMENT_ID).maybeSingle();
    if (error) return response.status(502).json({ error: 'NOTES_UNAVAILABLE' });
    if (kind === 'list') return response.status(200).json(data ? [safeAnnouncement(data)] : []);
    return data ? response.status(200).json(safeAnnouncement(data))
      : response.status(404).json({ error: 'RESOURCE_NOT_FOUND' });
  }

  // Never read role from a token's unverified claims, user_metadata, request
  // body, query or UI. Auth Admin's app_metadata is server-maintained.
  const instructor = await verifiedInstructor(login, supabase);
  if (!instructor) return response.status(403).json({ error: 'ZONE_FORBIDDEN' });

  if (request.method === 'DELETE') {
    const { data, error } = await supabase.from('vault_notes')
      .delete().eq('id', ANNOUNCEMENT_ID).select('id').maybeSingle();
    if (error) return response.status(502).json({ error: 'NOTES_UNAVAILABLE' });
    return data ? response.status(200).json({ ok: true })
      : response.status(404).json({ error: 'RESOURCE_NOT_FOUND' });
  }

  let payload;
  try { payload = readJsonBody(request); } catch {
    return response.status(400).json({ error: 'INVALID_BODY' });
  }
  if (!validNotePayload(payload)) return response.status(400).json({ error: 'INVALID_BODY' });
  if (payload.id !== undefined && payload.id !== ANNOUNCEMENT_ID) {
    return response.status(400).json({ error: 'INVALID_ID' });
  }

  if (request.method === 'POST' && kind === 'list') {
    const { data: previous, error: lookupError } = await supabase.from('vault_notes')
      .select('id').eq('id', ANNOUNCEMENT_ID).maybeSingle();
    if (lookupError) return response.status(502).json({ error: 'NOTES_UNAVAILABLE' });
    if (previous) return response.status(409).json({ error: 'RESOURCE_EXISTS' });
    const { data, error } = await supabase.from('vault_notes').insert({
      id: ANNOUNCEMENT_ID, owner_id: login.userId, title: payload.title, content: payload.body,
    }).select('id,title,content').single();
    if (error) return response.status(502).json({ error: 'NOTES_UNAVAILABLE' });
    return response.status(201).json(safeAnnouncement(data));
  }

  if (request.method === 'PUT' && kind === 'item') {
    const { data, error } = await supabase.from('vault_notes')
      .update({ title: payload.title, content: payload.body })
      .eq('id', ANNOUNCEMENT_ID).select('id,title,content').maybeSingle();
    if (error) return response.status(502).json({ error: 'NOTES_UNAVAILABLE' });
    return data ? response.status(200).json(safeAnnouncement(data))
      : response.status(404).json({ error: 'RESOURCE_NOT_FOUND' });
  }
  return response.status(405).json({ error: 'METHOD_NOT_ALLOWED' });
}
