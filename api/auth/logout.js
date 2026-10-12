import { clearSessionCookie, requestOriginAllowed } from '../../src/auth-session.mjs';

export default async function handler(request, response) {
  response.setHeader('Cache-Control', 'no-store');
  if (request.method !== 'POST') return response.status(405).json({ error: 'METHOD_NOT_ALLOWED' });
  if (!requestOriginAllowed(request)) return response.status(403).json({ error: 'ORIGIN_NOT_ALLOWED' });
  clearSessionCookie(response);
  return response.status(200).json({ ok: true });
}