import fs from 'node:fs';
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

  const authorization = request.headers?.authorization;
  const verifier = createLoginVerifier({ config, supabaseSecretKey: secretKey });
  const login = await verifier(authorization);
  if (!login || login.kind !== 'student') {
    return response.status(401).json({ notes: [], error: 'AUTH_REQUIRED' });
  }

  const { createClient } = await import('@supabase/supabase-js');
  const supabase = createClient(url, secretKey);
  const requestUrl = new URL(request.url, 'https://local.invalid');
  const pathname = requestUrl.pathname;
  const noteId = pathname.startsWith('/api/notes/') ? pathname.slice('/api/notes/'.length) : null;

  if (request.method === 'GET' && pathname === '/api/notes') {
    const { data, error } = await supabase
      .from('vault_notes')
      .select('id,title,content')
      .eq('owner_id', login.userId)
      .order('created_at', { ascending: true });

    if (error) {
      return response.status(502).json({ error: 'NOTES_UNAVAILABLE' });
    }

    return response.status(200).json(data.map(normalizeNote));
  }

  if (request.method === 'GET' && noteId) {
    const { data, error } = await supabase
      .from('vault_notes')
      .select('id,title,content')
      .eq('id', noteId)
      .maybeSingle();

    if (error) {
      return response.status(502).json({ error: 'NOTES_UNAVAILABLE' });
    }
    if (!data) {
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
    if (!payload || typeof payload.title !== 'string' || typeof payload.body !== 'string') {
      return response.status(400).json({ error: 'INVALID_BODY' });
    }

    const rawId = typeof payload.id === 'string' ? payload.id : '';
    if (rawId && !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu.test(rawId)) {
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
    if (!payload || typeof payload.title !== 'string' || typeof payload.body !== 'string') {
      return response.status(400).json({ error: 'INVALID_BODY' });
    }

    const { data, error } = await supabase
      .from('vault_notes')
      .update({ title: payload.title, content: payload.body })
      .eq('id', noteId)
      .select('id,title,content')
      .single();

    if (error) {
      return response.status(404).json({ error: 'NOTE_NOT_FOUND' });
    }

    return response.status(200).json({ id: data.id, title: data.title, body: data.content });
  }

  if (request.method === 'DELETE' && noteId) {
    const { error } = await supabase
      .from('vault_notes')
      .delete()
      .eq('id', noteId);

    if (error) {
      return response.status(404).json({ error: 'NOTE_NOT_FOUND' });
    }

    return response.status(200).json({ ok: true });
  }

  return response.status(405).json({ error: 'METHOD_NOT_ALLOWED' });
}