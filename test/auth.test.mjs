import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { after, before, test } from 'node:test';
import { exportJWK, generateKeyPair, SignJWT } from 'jose';
import { clearSessionCookie, readSessionCookie, writeSessionCookie } from '../src/auth-session.mjs';

const config = JSON.parse(await readFile(new URL('../aleph.config.json', import.meta.url), 'utf8'));
const { publicKey, privateKey } = await generateKeyPair('ES256');
const publicJwk = await exportJWK(publicKey);
publicJwk.kid = 'auth-test-key';
publicJwk.alg = 'ES256';
publicJwk.use = 'sig';
const userId = '11111111-1111-4111-8111-111111111111';
const userEmail = 'student@example.test';
const secretForTests = 'test-only-fake-secret-value';
const originalEnvironment = Object.fromEntries([
  'SUPABASE_URL', 'SUPABASE_PUBLISHABLE_KEY', 'SUPABASE_SECRET_KEY',
].map(name => [name, process.env[name]]));
const originalFetch = globalThis.fetch;

before(() => {
  process.env.SUPABASE_URL = new URL(config.identityProvider.issuer).origin;
  process.env.SUPABASE_PUBLISHABLE_KEY = 'test-only-publishable-key';
  process.env.SUPABASE_SECRET_KEY = secretForTests;
});

after(() => {
  globalThis.fetch = originalFetch;
  for (const [name, value] of Object.entries(originalEnvironment)) {
    if (value === undefined) delete process.env[name];
    else process.env[name] = value;
  }
});

function captureResponse() {
  const result = { headers: new Map(), statusCode: undefined, body: undefined };
  result.response = {
    setHeader: (name, value) => result.headers.set(name.toLowerCase(), value),
    status: statusCode => {
      result.statusCode = statusCode;
      return { json: body => { result.body = body; return result.response; } };
    },
  };
  return result;
}

function sameOriginHeaders(extra = {}) {
  return {
    host: 'student-defense.vercel.app',
    origin: 'https://student-defense.vercel.app',
    ...extra,
  };
}

async function studentToken(expiresAt = Math.floor(Date.now() / 1000) + 3600) {
  return new SignJWT({ role: 'authenticated' })
    .setProtectedHeader({ alg: 'ES256', kid: publicJwk.kid })
    .setIssuer(config.identityProvider.issuer)
    .setAudience(config.identityProvider.audience)
    .setSubject(userId)
    .setIssuedAt(Math.floor(Date.now() / 1000) - 10)
    .setExpirationTime(expiresAt)
    .sign(privateKey);
}

function cookieFor(session) {
  const response = captureResponse();
  writeSessionCookie(response.response, session, secretForTests);
  return response.headers.get('set-cookie').split(';', 1)[0];
}

test('browser source delegates Auth and never contains Supabase keys or JWT handling', async () => {
  const html = await readFile(new URL('../public/index.html', import.meta.url), 'utf8');
  assert.doesNotMatch(html, /createClient|signInWithPassword|signOut|sb_publishable_|sb_secret_|SUPABASE_SECRET_KEY/u);
  assert.doesNotMatch(html, /access_token|refresh_token|Authorization\s*:\s*[`'"].*Bearer/u);
  assert.match(html, /\/api\/auth\/login/u);
  assert.match(html, /\/api\/auth\/session/u);
});

test('login requires server publishable key and never returns auth tokens', async () => {
  const { default: login } = await import('../api/auth/login.js');
  const savedKey = process.env.SUPABASE_PUBLISHABLE_KEY;
  delete process.env.SUPABASE_PUBLISHABLE_KEY;
  const missing = captureResponse();
  try {
    await login({ method: 'POST', headers: sameOriginHeaders(), body: { email: userEmail, password: 'not-a-real-password' } }, missing.response);
    assert.equal(missing.statusCode, 503);
    assert.match(missing.body.message, /SUPABASE_PUBLISHABLE_KEY/u);
    assert.equal(missing.headers.get('cache-control'), 'no-store');
  } finally {
    process.env.SUPABASE_PUBLISHABLE_KEY = savedKey;
  }

  const accessToken = await studentToken();
  globalThis.fetch = async url => {
    assert.match(String(url), /\/auth\/v1\/token\?grant_type=password/u);
    return Response.json({
      access_token: accessToken,
      token_type: 'bearer',
      expires_in: 3600,
      expires_at: Math.floor(Date.now() / 1000) + 3600,
      refresh_token: 'login-refresh-token',
      user: { id: userId, email: userEmail, aud: 'authenticated', role: 'authenticated' },
    });
  };
  const response = captureResponse();
  await login({
    method: 'POST', headers: sameOriginHeaders(),
    body: { email: userEmail, password: 'test-only-password' },
  }, response.response);

  assert.equal(response.statusCode, 200);
  assert.deepEqual(response.body, { user: { email: userEmail } });
  assert.equal(JSON.stringify(response.body).includes(accessToken), false);
  assert.match(response.headers.get('set-cookie'), /HttpOnly; Secure; SameSite=Lax/u);
  assert.match(response.headers.get('set-cookie'), /Path=\/; Max-Age=/u);
  assert.equal(response.headers.get('cache-control'), 'no-store');
  const session = readSessionCookie({ headers: { cookie: response.headers.get('set-cookie') } }, secretForTests);
  assert.equal(session.access_token, accessToken);
});

test('session refresh rotates the HttpOnly cookie and exposes only verified email', async () => {
  const { default: sessionHandler } = await import('../api/auth/session.js');
  const expiredToken = await studentToken(Math.floor(Date.now() / 1000) - 30);
  const refreshedToken = await studentToken();
  let refreshCount = 0;
  globalThis.fetch = async (input, options = {}) => {
    const url = new URL(String(input));
    if (url.pathname.endsWith('/token') && url.searchParams.get('grant_type') === 'refresh_token') {
      refreshCount += 1;
      return Response.json({
        access_token: refreshedToken,
        token_type: 'bearer',
        expires_in: 3600,
        expires_at: Math.floor(Date.now() / 1000) + 3600,
        refresh_token: 'rotated-refresh-token',
        user: { id: userId, email: userEmail, aud: 'authenticated', role: 'authenticated' },
      });
    }
    if (url.pathname.endsWith('/.well-known/jwks.json')) return Response.json({ keys: [publicJwk] });
    if (url.pathname.endsWith('/rest/v1/vault_devices')) return Response.json([]);
    if (url.pathname.endsWith('/user')) {
      assert.equal(new Headers(options.headers).get('authorization'), `Bearer ${refreshedToken}`);
      return Response.json({ id: userId, email: userEmail, aud: 'authenticated', role: 'authenticated' });
    }
    throw new Error(`Unexpected auth request: ${url.pathname}`);
  };

  const response = captureResponse();
  await sessionHandler({
    method: 'GET',
    headers: { cookie: cookieFor({ access_token: expiredToken, refresh_token: 'old-refresh-token' }) },
  }, response.response);

  assert.equal(response.statusCode, 200);
  assert.deepEqual(response.body, { user: { email: userEmail }, device: { registered: false, status: 'unverified', source: 'server', requestId:null } });
  assert.equal(refreshCount, 1);
  assert.match(response.headers.get('set-cookie'), /HttpOnly; Secure; SameSite=Lax/u);
  const updatedSession = readSessionCookie({ headers: { cookie: response.headers.get('set-cookie') } }, secretForTests);
  assert.equal(updatedSession.access_token, refreshedToken);
  assert.equal(updatedSession.refresh_token, 'rotated-refresh-token');
  assert.equal(response.headers.get('cache-control'), 'no-store');
});

test('logout clears the cookie and subsequent note API requests are rejected', async () => {
  const { default: logout } = await import('../api/auth/logout.js');
  const { default: notes } = await import('../api/notes.js');
  const response = captureResponse();
  await logout({ method: 'POST', headers: sameOriginHeaders() }, response.response);
  assert.equal(response.statusCode, 200);
  assert.match(response.headers.get('set-cookie'), /Max-Age=0/u);
  assert.match(response.headers.get('set-cookie'), /HttpOnly; Secure; SameSite=Lax/u);
  assert.equal(response.headers.get('cache-control'), 'no-store');

  const denied = captureResponse();
  await notes({ method: 'GET', url: '/api/notes', headers: {} }, denied.response);
  assert.equal(denied.statusCode, 401);
  assert.equal(denied.body.error, 'AUTH_REQUIRED');
});

test('cross-origin state changes are rejected', async () => {
  const { default: login } = await import('../api/auth/login.js');
  const { default: logout } = await import('../api/auth/logout.js');
  const session = cookieFor({ access_token: await studentToken(), refresh_token: 'csrf-test-refresh' });
  const badOrigin = { host: 'student-defense.vercel.app', origin: 'https://attacker.example' };

  const loginResponse = captureResponse();
  await login({ method: 'POST', headers: badOrigin, body: {} }, loginResponse.response);
  assert.equal(loginResponse.statusCode, 403);

  const logoutResponse = captureResponse();
  await logout({ method: 'POST', headers: badOrigin, body: { cookie: session } }, logoutResponse.response);
  assert.equal(logoutResponse.statusCode, 403);
});