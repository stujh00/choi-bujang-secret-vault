import assert from 'node:assert/strict';
import { readdir, readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { test } from 'node:test';
import { exportJWK, generateKeyPair, SignJWT } from 'jose';

const baseline = JSON.parse(await readFile(new URL('../package/baseline-functions.json', import.meta.url)));

test('패키징 함수 기준표는 시작 틀의 실제 API와 일치한다', async () => {
  const actual = (await readdir(new URL('../api/', import.meta.url)))
    .filter(name => /\.(?:m?js|ts)$/u.test(name))
    .map(name => join('api', name).replaceAll('\\', '/')).sort();
  assert.equal(baseline.version, 1);
  assert.equal(baseline.starter, 'ChoiTimo/aleph-defense-starter');
  assert.deepEqual(baseline.functions, []);
  assert.deepEqual(baseline.allowedNew, ['api/ai.js', 'api/notes.js', 'api/threat-intel.js']);
  assert.deepEqual(actual, [...baseline.functions, ...baseline.allowedNew].sort());
});

test('미구현 서버 뼈대는 성공이나 로그인 통과로 가장하지 않는다', async () => {
  for (const name of ['ai', 'threat-intel']) {
    const { default: handler } = await import(`../api/${name}.js`);
    const headers = new Map();
    let status;
    let body;
    handler({}, {
      setHeader: (key, value) => headers.set(key.toLowerCase(), value),
      status: value => { status = value; return { json: value => { body = value; } }; },
    });
    assert.equal(status, 501);
    assert.equal(headers.get('cache-control'), 'no-store');
    assert.match(body.error, /NOT_IMPLEMENTED$/u);
  }
});

test('메모 API는 서버 환경 변수가 없으면 값을 노출하지 않는다', async () => {
  const { default: handler } = await import('../api/notes.js');
  const originalUrl = process.env.SUPABASE_URL;
  const originalKey = process.env.SUPABASE_SECRET_KEY;
  delete process.env.SUPABASE_URL;
  delete process.env.SUPABASE_SECRET_KEY;
  let status;
  let body;
  try {
    await handler({ method: 'GET' }, {
      setHeader: () => {},
      status: value => { status = value; return { json: value => { body = value; } }; },
    });
    assert.equal(status, 503);
    assert.deepEqual(body, { notes: [], error: 'NOTES_UNAVAILABLE' });
  } finally {
    if (originalUrl === undefined) delete process.env.SUPABASE_URL;
    else process.env.SUPABASE_URL = originalUrl;
    if (originalKey === undefined) delete process.env.SUPABASE_SECRET_KEY;
    else process.env.SUPABASE_SECRET_KEY = originalKey;
  }
});

test('메모 API는 인증 없는 조회를 거부한다', async () => {
  const { default: handler } = await import('../api/notes.js');
  const originalUrl = process.env.SUPABASE_URL;
  const originalKey = process.env.SUPABASE_SECRET_KEY;
  const originalFetch = globalThis.fetch;
  const requestedUrls = [];
  process.env.SUPABASE_URL = 'https://example.supabase.co';
  process.env.SUPABASE_SECRET_KEY = 'test-only-fake-secret-value';
  globalThis.fetch = async (url, options) => {
    requestedUrls.push(String(url));
    return Response.json({});
  };
  let status;
  let body;
  try {
    await handler({ method: 'GET', url: '/api/notes' }, {
      setHeader: () => {},
      status: value => { status = value; return { json: value => { body = value; } }; },
    });
    assert.equal(status, 401);
    assert.deepEqual(body, { notes: [], error: 'AUTH_REQUIRED' });
    assert.deepEqual(requestedUrls, []);
  } finally {
    globalThis.fetch = originalFetch;
    if (originalUrl === undefined) delete process.env.SUPABASE_URL;
    else process.env.SUPABASE_URL = originalUrl;
    if (originalKey === undefined) delete process.env.SUPABASE_SECRET_KEY;
    else process.env.SUPABASE_SECRET_KEY = originalKey;
  }
});

test('메모 API는 목록과 모든 단건 작업을 소유자에게만 허용한다', async () => {
  const config = JSON.parse(await readFile(new URL('../aleph.config.json', import.meta.url), 'utf8'));
  const { default: notesHandler } = await import('../api/notes.js');
  const { default: noteHandler } = await import('../api/notes/[id].js');
  const { publicKey, privateKey } = await generateKeyPair('ES256');
  const publicJwk = await exportJWK(publicKey);
  publicJwk.kid = 'ownership-test-key';
  publicJwk.alg = 'ES256';
  publicJwk.use = 'sig';

  const ownerA = '11111111-1111-4111-8111-111111111111';
  const ownerB = '22222222-2222-4222-8222-222222222222';
  const noteAId = '00000000-0000-4000-8000-000000000001';
  const noteBId = '00000000-0000-4000-8000-000000000005';
  const records = new Map([
    [noteAId, { id: noteAId, owner_id: ownerA, title: 'A title', content: 'A private body' }],
    [noteBId, { id: noteBId, owner_id: ownerB, title: 'B title', content: 'B private body' }],
  ]);
  const originalUrl = process.env.SUPABASE_URL;
  const originalKey = process.env.SUPABASE_SECRET_KEY;
  const originalFetch = globalThis.fetch;
  process.env.SUPABASE_URL = new URL(config.identityProvider.issuer).origin;
  process.env.SUPABASE_SECRET_KEY = 'test-only-fake-secret-value';

  const tokenFor = async userId => new SignJWT({ role: 'authenticated' })
    .setProtectedHeader({ alg: 'ES256', kid: publicJwk.kid })
    .setIssuer(config.identityProvider.issuer)
    .setAudience(config.identityProvider.audience)
    .setSubject(userId)
    .setIssuedAt()
    .setExpirationTime('5m')
    .sign(privateKey);
  const tokenA = await tokenFor(ownerA);
  const tokenB = await tokenFor(ownerB);

  globalThis.fetch = async (requestUrl, options = {}) => {
    const parsedUrl = new URL(String(requestUrl));
    if (parsedUrl.pathname.endsWith('/.well-known/jwks.json')) {
      return Response.json({ keys: [publicJwk] });
    }
    if (!parsedUrl.pathname.endsWith('/rest/v1/vault_notes')) {
      throw new Error('Unexpected URL in ownership test.');
    }

    const idFilter = parsedUrl.searchParams.get('id');
    const ownerFilter = parsedUrl.searchParams.get('owner_id');
    const matches = record => (!idFilter || idFilter === `eq.${record.id}`)
      && (!ownerFilter || ownerFilter === `eq.${record.owner_id}`);
    const matchedRecords = [...records.values()].filter(matches);
    const accept = new Headers(options.headers).get('accept') || '';
    const respond = (rows, status = 200) => {
      if (accept.includes('application/vnd.pgrst.object+json')) {
        if (rows.length !== 1) {
          return Response.json({ code: 'PGRST116', details: 'No matching row.', message: 'No rows found.' }, { status: 406 });
        }
        return Response.json(rows[0], { status });
      }
      return Response.json(rows, { status });
    };

    if (options.method === 'GET') return respond(matchedRecords);
    if (options.method === 'POST') {
      const inserted = JSON.parse(options.body);
      records.set(inserted.id, inserted);
      return respond([inserted], 201);
    }
    if (options.method === 'PATCH') {
      const updates = JSON.parse(options.body);
      for (const record of matchedRecords) {
        Object.assign(record, updates);
        if (updates.title === 'Trigger owner change') record.owner_id = ownerB;
      }
      return respond(matchedRecords);
    }
    if (options.method === 'DELETE') {
      for (const record of matchedRecords) records.delete(record.id);
      return respond(matchedRecords);
    }
    throw new Error(`Unexpected method in ownership test: ${options.method}`);
  };

  const invoke = async (handler, method, userToken, path, body) => {
    let status;
    let responseBody;
    await handler({
      method,
      url: path,
      query: { id: path.split('/').at(-1) },
      headers: { authorization: `Bearer ${userToken}` },
      body,
    }, {
      setHeader: () => {},
      status: value => { status = value; return { json: value => { responseBody = value; } }; },
    });
    return { status, body: responseBody };
  };

  try {
    const listA = await invoke(notesHandler, 'GET', tokenA, '/api/notes');
    const listB = await invoke(notesHandler, 'GET', tokenB, '/api/notes');
    assert.deepEqual(listA.body, [{ id: noteAId, title: 'A title', body: 'A private body' }]);
    assert.deepEqual(listB.body, [{ id: noteBId, title: 'B title', body: 'B private body' }]);

    const created = await invoke(notesHandler, 'POST', tokenA, '/api/notes', {
      owner_id: ownerB,
      title: 'Created by A',
      body: 'A owns this note',
    });
    assert.equal(created.status, 201);
    assert.deepEqual(Object.keys(created.body).sort(), ['body', 'id', 'title']);
    assert.equal(records.get(created.body.id).owner_id, ownerA);

    const crossAccessCases = [
      { token: tokenB, noteId: noteAId, title: 'A title', body: 'A private body', ownerId: ownerA },
      { token: tokenA, noteId: noteBId, title: 'B title', body: 'B private body', ownerId: ownerB },
    ];
    for (const handler of [noteHandler, notesHandler]) {
      for (const accessCase of crossAccessCases) {
        const otherRead = await invoke(handler, 'GET', accessCase.token, `/api/notes/${accessCase.noteId}`);
        assert.equal(otherRead.status, 404);
        assert.equal(JSON.stringify(otherRead.body).includes(accessCase.body), false);

        const otherUpdate = await invoke(handler, 'PUT', accessCase.token, `/api/notes/${accessCase.noteId}`, {
          title: 'Changed by another account', body: 'Cross-account update must not be applied',
        });
        assert.equal(otherUpdate.status, 404);
        assert.equal(records.get(accessCase.noteId).title, accessCase.title);
        assert.equal(records.get(accessCase.noteId).owner_id, accessCase.ownerId);

        const otherDelete = await invoke(handler, 'DELETE', accessCase.token, `/api/notes/${accessCase.noteId}`);
        assert.equal(otherDelete.status, 404);
        assert.equal(records.get(accessCase.noteId).owner_id, accessCase.ownerId);
      }
    }

    const ownRead = await invoke(noteHandler, 'GET', tokenA, `/api/notes/${noteAId}`);
    assert.equal(ownRead.status, 200);
    assert.deepEqual(ownRead.body, { id: noteAId, title: 'A title', body: 'A private body' });

    const ownUpdate = await invoke(noteHandler, 'PUT', tokenA, `/api/notes/${noteAId}`, {
      title: 'A updated title', body: 'A updated body',
    });
    assert.equal(ownUpdate.status, 200);
    assert.deepEqual(ownUpdate.body, { id: noteAId, title: 'A updated title', body: 'A updated body' });
    assert.equal(records.get(noteAId).owner_id, ownerA);

    const changedOwnerUpdate = await invoke(noteHandler, 'PUT', tokenA, `/api/notes/${noteAId}`, {
      title: 'Trigger owner change', body: 'This response must not be exposed',
    });
    assert.equal(changedOwnerUpdate.status, 404);
    assert.equal(JSON.stringify(changedOwnerUpdate.body).includes('This response must not be exposed'), false);
    Object.assign(records.get(noteAId), { owner_id: ownerA, title: 'A updated title', content: 'A updated body' });

    const ownDelete = await invoke(noteHandler, 'DELETE', tokenA, `/api/notes/${noteAId}`);
    assert.equal(ownDelete.status, 200);
    assert.equal(records.has(noteAId), false);
  } finally {
    globalThis.fetch = originalFetch;
    if (originalUrl === undefined) delete process.env.SUPABASE_URL;
    else process.env.SUPABASE_URL = originalUrl;
    if (originalKey === undefined) delete process.env.SUPABASE_SECRET_KEY;
    else process.env.SUPABASE_SECRET_KEY = originalKey;
  }
});

test('P7 시작 틀 안내는 실제 빌드 조건과 새 배포 시험에 맞는다', async () => {
  const readme = await readFile(new URL('../package/README.md', import.meta.url), 'utf8');
  const selfCheck = await readFile(new URL('../package/SELF-CHECK.md', import.meta.url), 'utf8');
  assert.match(readme, /새 Vercel 프로젝트/u);
  assert.match(readme, /Vercel이 제공하는 저장소·커밋·배포 URL 정보/u);
  assert.doesNotMatch(readme, /npm start/u);
  assert.match(selfCheck, /P7-3\.png/u);
});
