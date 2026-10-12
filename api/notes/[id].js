import fs from 'node:fs';
import { createLoginVerifier } from '../../src/verify-login.mjs';

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu;

function readConfig() {
  return JSON.parse(fs.readFileSync(new URL('../../aleph.config.json', import.meta.url), 'utf8'));
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
    return response.status(503).json({ error: 'NOTES_UNAVAILABLE' });
  }

  const authorization = request.headers?.authorization;
  const verifier = createLoginVerifier({ config, supabaseSecretKey: secretKey });
  const login = await verifier(authorization);
  if (!login || login.kind !== 'student') {
    return response.status(401).json({ error: 'AUTH_REQUIRED' });
  }

  const { createClient } = await import('@supabase/supabase-js');
  const supabase = createClient(url, secretKey);
  const noteId = request.query?.id || request.url?.split('/').filter(Boolean).at(-1) || null;

  if (!noteId) {
    return response.status(404).json({ error: 'NOTE_NOT_FOUND' });
  }

  if (request.method === 'GET') {
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
    return response.status(200).json({ id: data.id, title: data.title, body: data.content });
  }

  if (request.method === 'PUT') {
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
      .eq('owner_id', login.userId)
      .select('id,title,content,owner_id')
      .single();

    if (error || !data || data.owner_id !== login.userId) {
      return response.status(404).json({ error: 'NOTE_NOT_FOUND' });
    }
    return response.status(200).json({ id: data.id, title: data.title, body: data.content });
  }

  if (request.method === 'DELETE') {
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
