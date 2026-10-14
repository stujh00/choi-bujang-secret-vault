import {requireRegisteredDevice} from '../src/device-registration.mjs';
import fs from 'node:fs';
import { ANNOUNCEMENT_ID, exactRoute, validNotePayload, isNoteId } from '../src/resource-zones.mjs';
import { readSessionCookie, requestOriginAllowed } from '../src/auth-session.mjs';
import { createLoginVerifier } from '../src/verify-login.mjs';

function readConfig() {
  return JSON.parse(fs.readFileSync(new URL('../aleph.config.json', import.meta.url), 'utf8'));
}

function normalizeNote(record) {
  if (!record || typeof record !== 'object') return null;
  return {
    id: record.id,
    title: record.title,
    body: record.content,
  };
}

function readBodyJson(request) {
  if (!request.body) return {};
  if (typeof request.body === 'string') {
    return JSON.parse(request.body);
  }
  if (typeof request.body === 'object') {
    return request.body;
  }
  return {};
}

export default async function handler(request, response) {
  response.setHeader('Cache-Control', 'no-store');

  const config = readConfig();
  const secretKey = process.env.SUPABASE_SECRET_KEY;
  const url = process.env.SUPABASE_URL;
  if (!secretKey || !url) {
    return response.status(503).json({ notes: [], error: 'NOTES_UNAVAILABLE' });
  }

  let authorization = request.headers?.authorization;
  if (typeof authorization !== 'string' || !/^Bearer [A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/u.test(authorization)) {
    const session = readSessionCookie(request, secretKey);
    if (session && ['POST', 'PUT', 'DELETE'].includes(request.method)
        && !requestOriginAllowed(request)) {
      return response.status(403).json({ notes: [], error: 'ORIGIN_NOT_ALLOWED' });
    }
    if (session) authorization = `Bearer ${session.access_token}`;
  }
  const verifier = createLoginVerifier({ config, supabaseSecretKey: secretKey });
  const login = await verifier(authorization);
  if (!login || login.kind !== 'student') {
    return response.status(401).json({ notes: [], error: 'AUTH_REQUIRED' });
  }

  const { createClient } = await import('@supabase/supabase-js');
  const supabase = createClient(url, secretKey);
  const deviceDenied=await requireRegisteredDevice(request,login,supabase,secretKey,config.step);
  if(deviceDenied) return response.status(deviceDenied.status).json({error:deviceDenied.error});
  const route = exactRoute(request, 'notes');
  if (!route) return response.status(404).json({ error: 'RESOURCE_NOT_FOUND' });
  const pathname = new URL(request.url, 'https://local.invalid').pathname;
  const noteId = route.type === 'item' ? route.id : null;

  if (request.method === 'GET' && pathname === '/api/notes') {
    const { data, error } = await supabase
      .from('vault_notes')
      .select('id,title,content,owner_id')
      .eq('owner_id', login.userId)
      .neq('id', ANNOUNCEMENT_ID)
      .order('created_at', { ascending: true });

    if (error) {
      return response.status(502).json({ error: 'NOTES_UNAVAILABLE' });
    }

    return response.status(200).json(data.filter(row => row.owner_id === login.userId).map(normalizeNote));
  }

  if (request.method === 'GET' && noteId) {
    const { data, error } = await supabase
      .from('vault_notes')
      .select('id,title,content,owner_id')
      .eq('id', noteId)
      .eq('owner_id', login.userId)
      .maybeSingle();

    if (error) {
      return response.status(502).json({ error: 'NOTES_UNAVAILABLE' });
    }
    if (!data || data.owner_id !== login.userId) {
      return response.status(404).json({ error: 'NOTE_NOT_FOUND' });
    }
    return response.status(200).json(normalizeNote(data));
  }

  if (request.method === 'POST' && pathname === '/api/notes') {
    let payload;
    try {
      payload = readBodyJson(request);
    } catch {
      return response.status(400).json({ error: 'INVALID_BODY' });
    }
    if (!validNotePayload(payload)) {
      return response.status(400).json({ error: 'INVALID_BODY' });
    }

    const rawId = typeof payload.id === 'string' ? payload.id : '';
    if (rawId && !isNoteId(rawId)) {
      return response.status(400).json({ error: 'INVALID_ID' });
    }

    const noteId = rawId || crypto.randomUUID();
    const { data, error } = await supabase
      .from('vault_notes')
      .insert({
        id: noteId,
        owner_id: login.userId,
        title: payload.title,
        content: payload.body,
      })
      .select('id,title,content')
      .single();

    if (error) {
      return response.status(502).json({ error: 'NOTES_UNAVAILABLE' });
    }

    return response.status(201).json({ id: data.id, title: data.title, body: data.content });
  }

  if (request.method === 'PUT' && noteId) {
    let payload;
    try {
      payload = readBodyJson(request);
    } catch {
      return response.status(400).json({ error: 'INVALID_BODY' });
    }
    if (!validNotePayload(payload)) {
      return response.status(400).json({ error: 'INVALID_BODY' });
    }

    const { data, error } = await supabase
      .from('vault_notes')
      .update({ title: payload.title, content: payload.body })
      .eq('id', noteId)
      .eq('owner_id', login.userId)
      .select('id,title,content,owner_id')
      .single();

    if (error || !data || data.owner_id !== login.userId) {
      return response.status(404).json({ error: 'NOTE_NOT_FOUND' });
    }

    return response.status(200).json({ id: data.id, title: data.title, body: data.content });
  }

  if (request.method === 'DELETE' && noteId) {
    const { data, error } = await supabase
      .from('vault_notes')
      .delete()
      .eq('id', noteId)
      .eq('owner_id', login.userId)
      .select('id,owner_id')
      .maybeSingle();

    if (error) {
      return response.status(502).json({ error: 'NOTES_UNAVAILABLE' });
    }
    if (!data || data.owner_id !== login.userId) {
      return response.status(404).json({ error: 'NOTE_NOT_FOUND' });
    }

    return response.status(200).json({ ok: true });
  }

  return response.status(405).json({ error: 'METHOD_NOT_ALLOWED' });
}