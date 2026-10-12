import { createClient } from '@supabase/supabase-js';
import fs from 'node:fs';
import { authEnvironment, clearSessionCookie, readSessionCookie, writeSessionCookie } from '../../src/auth-session.mjs';
import { createLoginVerifier } from '../../src/verify-login.mjs';

function readConfig() {
  return JSON.parse(fs.readFileSync(new URL('../../aleph.config.json', import.meta.url), 'utf8'));
}

function anonymous(response) {
  clearSessionCookie(response);
  return response.status(200).json({ user: null });
}

export default async function handler(request, response) {
  response.setHeader('Cache-Control', 'no-store');
  if (request.method !== 'GET') return response.status(405).json({ error: 'METHOD_NOT_ALLOWED' });

  const environment = authEnvironment();
  if (environment.error) {
    return response.status(503).json({ error: 'AUTH_UNAVAILABLE', message: environment.error });
  }
  const session = readSessionCookie(request, environment.secretKey);
  if (!session) return anonymous(response);

  try {
    const supabase = createClient(environment.url, environment.publishableKey, {
      auth: { autoRefreshToken: false, persistSession: false, detectSessionInUrl: false },
    });
    const { data, error } = await supabase.auth.setSession(session);
    if (error || !data.session) return anonymous(response);

    const verifier = createLoginVerifier({
      config: readConfig(), supabaseSecretKey: environment.secretKey,
    });
    const login = await verifier(`Bearer ${data.session.access_token}`);
    if (!login || login.kind !== 'student') return anonymous(response);

    const { data: userData, error: userError } = await supabase.auth.getUser(data.session.access_token);
    if (userError || !userData.user) return anonymous(response);

    writeSessionCookie(response, data.session, environment.secretKey);
    return response.status(200).json({ user: { email: userData.user.email ?? null } });
  } catch {
    return response.status(502).json({ error: 'AUTH_PROVIDER_UNAVAILABLE' });
  }
}