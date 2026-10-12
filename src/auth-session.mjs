import { createHmac, timingSafeEqual } from 'node:crypto';

export const SESSION_COOKIE = '__Host-vault_session';
const SESSION_MAX_AGE = 60 * 60 * 24 * 7;

export function authEnvironment() {
  const required = ['SUPABASE_URL', 'SUPABASE_PUBLISHABLE_KEY', 'SUPABASE_SECRET_KEY'];
  const missing = required.find(name => !process.env[name]?.trim());
  if (missing) return { error: `Missing server environment variable: ${missing}` };
  return {
    url: process.env.SUPABASE_URL,
    publishableKey: process.env.SUPABASE_PUBLISHABLE_KEY,
    secretKey: process.env.SUPABASE_SECRET_KEY,
  };
}

export function requestOriginAllowed(request) {
  const headers = request.headers ?? {};
  const origin = headers.origin;
  const host = (headers['x-forwarded-host'] ?? headers.host ?? '').split(',')[0].trim();
  const forwardedProtocol = (headers['x-forwarded-proto'] ?? '').split(',')[0].trim();
  if (typeof origin !== 'string' || !host || origin === 'null') return false;

  const protocol = forwardedProtocol || (/^(localhost|127\.0\.0\.1|\[::1\])(?::\d+)?$/iu.test(host) ? 'http' : 'https');
  try {
    const parsedOrigin = new URL(origin);
    return parsedOrigin.origin === `${protocol}://${host}`
      && !parsedOrigin.username && !parsedOrigin.password;
  } catch {
    return false;
  }
}

function signature(payload, secretKey) {
  return createHmac('sha256', secretKey)
    .update('vault-session-v1\0')
    .update(payload)
    .digest('base64url');
}

export function writeSessionCookie(response, session, secretKey) {
  if (typeof session?.access_token !== 'string' || typeof session?.refresh_token !== 'string') {
    throw new TypeError('invalid_auth_session');
  }
  const payload = Buffer.from(JSON.stringify({
    accessToken: session.access_token,
    refreshToken: session.refresh_token,
  })).toString('base64url');
  response.setHeader('Set-Cookie', `${SESSION_COOKIE}=${payload}.${signature(payload, secretKey)}; Path=/; Max-Age=${SESSION_MAX_AGE}; HttpOnly; Secure; SameSite=Lax`);
}

export function clearSessionCookie(response) {
  response.setHeader('Set-Cookie', `${SESSION_COOKIE}=; Path=/; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT; HttpOnly; Secure; SameSite=Lax`);
}

export function readSessionCookie(request, secretKey) {
  const cookieHeader = request.headers?.cookie ?? request.headers?.Cookie ?? '';
  const entry = cookieHeader.split(';').map(value => value.trim())
    .find(value => value.startsWith(`${SESSION_COOKIE}=`));
  if (!entry) return null;

  const value = entry.slice(SESSION_COOKIE.length + 1);
  if (value.length > 8192) return null;
  const separator = value.lastIndexOf('.');
  if (separator < 1) return null;
  const payload = value.slice(0, separator);
  const suppliedSignature = Buffer.from(value.slice(separator + 1), 'base64url');
  const expectedSignature = Buffer.from(signature(payload, secretKey), 'base64url');
  if (suppliedSignature.length !== expectedSignature.length
      || !timingSafeEqual(suppliedSignature, expectedSignature)) return null;

  try {
    const session = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8'));
    if (typeof session.accessToken !== 'string' || typeof session.refreshToken !== 'string'
        || session.accessToken.length > 4096 || session.refreshToken.length > 4096) return null;
    return { access_token: session.accessToken, refresh_token: session.refreshToken };
  } catch {
    return null;
  }
}

export function readJsonBody(request) {
  if (!request.body) return {};
  if (typeof request.body === 'string') return JSON.parse(request.body);
  if (typeof request.body === 'object') return request.body;
  return {};
}