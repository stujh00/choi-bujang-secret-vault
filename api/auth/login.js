import { createClient } from '@supabase/supabase-js';
import { authEnvironment, readJsonBody, requestOriginAllowed, writeSessionCookie } from '../../src/auth-session.mjs';

export default async function handler(request, response) {
  response.setHeader('Cache-Control', 'no-store');
  if (request.method !== 'POST') return response.status(405).json({ error: 'METHOD_NOT_ALLOWED' });
  if (!requestOriginAllowed(request)) return response.status(403).json({ error: 'ORIGIN_NOT_ALLOWED' });

  const environment = authEnvironment();
  if (environment.error) {
    return response.status(503).json({ error: 'AUTH_UNAVAILABLE', message: environment.error });
  }

  let payload;
  try {
    payload = readJsonBody(request);
  } catch {
    return response.status(400).json({ error: 'INVALID_BODY' });
  }
  if (typeof payload?.email !== 'string' || payload.email.length > 320
      || typeof payload.password !== 'string' || !payload.password || payload.password.length > 1024) {
    return response.status(400).json({ error: 'INVALID_BODY' });
  }

  try {
    const supabase = createClient(environment.url, environment.publishableKey, {
      auth: { autoRefreshToken: false, persistSession: false, detectSessionInUrl: false },
    });
    const { data, error } = await supabase.auth.signInWithPassword({
      email: payload.email.trim(), password: payload.password,
    });
    if (error || !data.session || !data.user) {
      return response.status(error?.status === 429 ? 429 : 401).json({ error: 'LOGIN_FAILED' });
    }
    writeSessionCookie(response, data.session, environment.secretKey);
    return response.status(200).json({ user: { email: data.user.email ?? null } });
  } catch {
    return response.status(502).json({ error: 'AUTH_PROVIDER_UNAVAILABLE' });
  }
}