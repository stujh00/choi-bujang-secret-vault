import assert from 'node:assert/strict';
import { test } from 'node:test';
import { deploymentIdentity } from '../scripts/deployment-identity.mjs';
import { runAttackChecks } from '../src/attack-check.mjs';

const config = {
  step: 1,
  judgeIssuer: 'https://aleph-judge-production.up.railway.app/defense/judge',
  sampleMarker: 'SAMPLE_NOTE_1',
  publicAppUrl: 'https://student-defense.vercel.app',
};
const env = {
  VERCEL_GIT_PROVIDER: 'github',
  VERCEL_GIT_REPO_OWNER: 'Student-A',
  VERCEL_GIT_REPO_SLUG: 'aleph-defense',
  VERCEL_GIT_COMMIT_SHA: 'a'.repeat(40),
  VERCEL_URL: 'student-defense-123.vercel.app',
};

test('build identity uses Vercel Git and deployment metadata', () => {
  assert.deepEqual(deploymentIdentity(env, config), {
    schema: 'aleph.defense.deployment.v1',
    step: 1,
    repoUrl: 'https://github.com/student-a/aleph-defense',
    commit: 'a'.repeat(40),
    publicAppUrl: 'https://student-defense-123.vercel.app',
    judgeIssuer: config.judgeIssuer,
    sampleMarker: config.sampleMarker,
  });
  assert.throws(() => deploymentIdentity({ ...env, VERCEL_GIT_PROVIDER: undefined }, config));
  assert.throws(() => deploymentIdentity({ ...env, VERCEL_GIT_COMMIT_SHA: 'short' }, config));
  assert.equal(deploymentIdentity(env, { ...config, step: 2 }).step, 2);
  assert.equal(deploymentIdentity(env, { ...config, step: 3 }).step, 3);
  assert.equal(deploymentIdentity(env, { ...config, step: 4 }).step, 4);
  assert.equal(deploymentIdentity(env, { ...config, step: 5 }).step, 5);
  assert.equal(deploymentIdentity(env, { ...config, step: 6 }).step, 6);
  assert.equal(deploymentIdentity(env, { ...config, step: 7 }).step, 7);
  assert.equal(deploymentIdentity(env, { ...config, step: 8 }).step, 8);
  assert.equal(deploymentIdentity(env, { ...config, step: 9 }).step, 9);
  assert.equal(deploymentIdentity(env, { ...config, step: 10 }).step, 10);
});

test('first attack check reads public data.json without credentials', async () => {
  const originalFetch = globalThis.fetch;
  let requestUrl;
  let options;
  try {
    globalThis.fetch = async (url, init) => {
      requestUrl = String(url);
      options = init;
      return new Response(JSON.stringify({ sampleMarker: 'SAMPLE_NOTE_1', notes: [{ title: '가상' }] }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      });
    };
    const [result] = await runAttackChecks(config);
    assert.equal(requestUrl, 'https://student-defense.vercel.app/data.json');
    assert.equal(options.redirect, 'error');
    assert.match(result.observed, /확인 표시가 보임/u);
    globalThis.fetch = async () => new Response('<html>not the data</html>', { status: 200 });
    const [failed] = await runAttackChecks(config);
    assert.match(failed.observed, /보이지 않음/u);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('second attack check inspects static data and public API without recording note bodies', async () => {
  const originalFetch = globalThis.fetch;
  const requestedUrls = [];
  try {
    globalThis.fetch = async url => {
      requestedUrls.push(String(url));
      if (String(url).endsWith('/data.json')) {
        return Response.json({ notes: [] });
      }
      return Response.json({ notes: [
        { title: '가상 제목', content: '가상 본문 A' },
        { title: '가상 제목', content: '가상 본문 B' },
      ] });
    };
    const results = await runAttackChecks({ ...config, step: 2 });
    assert.deepEqual(requestedUrls, [
      'https://student-defense.vercel.app/data.json',
      'https://student-defense.vercel.app/api/notes',
    ]);
    assert.equal(results.length, 2);
    assert.match(results[0].observed, /메모 없음/u);
    assert.equal(results[0].expected, '공개 정적 JSON에 가상 메모가 없음');
    assert.match(results[1].observed, /메모 2건 응답/u);
    assert.doesNotMatch(JSON.stringify(results), /가상 본문/u);

    globalThis.fetch = async url => String(url).endsWith('/data.json')
      ? Response.json({ notes: [] })
      : Response.json({ notes: [] }, { status: 401 });
    const thirdStageResults = await runAttackChecks({ ...config, step: 3 });
    assert.equal(thirdStageResults.length, 2);
    assert.match(thirdStageResults[1].observed, /401/u);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('fifth attack check audits public files and probes anonymous source access without exposing data', async () => {
  const originalFetch = globalThis.fetch;
  const configStep5 = {
    ...config,
    step: 5,
    originalApiUrl: 'https://student.supabase.co/rest/v1/vault_notes',
  };
  const requests = [];
  globalThis.fetch = async (url, options = {}) => {
    const requestUrl = new URL(String(url));
    const headers = new Headers(options.headers);
    requests.push({ method: options.method ?? 'GET', url: requestUrl, headers, body: options.body });

    if (requestUrl.pathname === '/data.json') return Response.json({ notes: [] });
    if (requestUrl.pathname === '/') {
      return new Response('<script>const key = "sb_publishable_test_key";</script>', { status: 200 });
    }
    if (requestUrl.pathname === '/aleph.json') return Response.json({ schema: 'aleph.defense.deployment.v1' });
    if (requestUrl.pathname === '/rest/v1/vault_notes') return new Response(null, { status: 403 });
    throw new Error('Unexpected URL in stage 5 attack check test.');
  };

  try {
    const results = await runAttackChecks(configStep5);
    assert.deepEqual(results.map(result => result.attackId), [
      'anonymous_static_data_secrecy',
      'anonymous_source_api_read',
      'anonymous_source_api_update',
    ]);
    assert.match(results[0].observed, /비밀값 패턴 있음/u);
    assert.match(results[1].observed, /HTTP 403로 거부/u);
    assert.match(results[2].observed, /HTTP 403로 거부/u);
    assert.doesNotMatch(JSON.stringify(results), /sb_publishable_test_key|가상 본문|Bearer\s|eyJ/u);
    for (const result of results) {
      assert.deepEqual(Object.keys(result).sort(), ['attackId', 'expected', 'observed']);
      assert.ok(result.expected.length <= 300);
      assert.ok(result.observed.length <= 300);
    }

    const sourceRequests = requests.filter(request => request.url.hostname === 'student.supabase.co');
    assert.equal(sourceRequests.length, 2);
    assert.equal(sourceRequests[0].headers.get('apikey'), 'sb_publishable_test_key');
    assert.equal(sourceRequests[0].headers.get('authorization'), null);
    assert.equal(sourceRequests[1].method, 'PATCH');
    assert.equal(sourceRequests[1].url.searchParams.get('id'), 'eq.00000000-0000-0000-0000-000000000000');
    assert.deepEqual(JSON.parse(sourceRequests[1].body), { title: null });
    assert.equal(sourceRequests[1].headers.get('authorization'), null);
    assert.equal(requests.some(request => request.method === 'DELETE'), false);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('sixth attack check retains static/API protection and checks registered device decision locally', async () => {
  const originalFetch = globalThis.fetch;
  const requests = [];
  globalThis.fetch = async (url, options = {}) => {
    const parsed = new URL(String(url));
    requests.push({ pathname: parsed.pathname, method: options.method ?? 'GET' });
    if (parsed.pathname === '/data.json') return Response.json({ notes: [] });
    if (parsed.pathname === '/') return new Response('<main>자료실</main>', { status: 200 });
    if (parsed.pathname === '/aleph.json') return Response.json({ step: 6 });
    if (parsed.pathname === '/rest/v1/vault_notes') return new Response(null, { status: 403 });
    throw new Error('unexpected URL');
  };
  try {
    const results = await runAttackChecks({
      ...config,
      step: 6,
      originalApiUrl: 'https://student.supabase.co/rest/v1/vault_notes',
    });
    assert.equal(results.length, 5);
    assert.deepEqual(results.slice(3).map(item => item.attackId), [
      'registered_device_read_local',
      'unregistered_device_read_local',
    ]);
    assert.match(results[3].observed, /연습 통과/u);
    assert.match(results[4].observed, /연습 통과/u);
    assert.deepEqual(requests.map(item => item.method), ['GET', 'GET', 'GET', 'GET', 'PATCH']);
    assert.equal(JSON.stringify(results).includes('가상 본문'), false);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('seventh attack self-check reports mock step-up before and after engine-verified login', async () => {
  const originalFetch = globalThis.fetch;
  const requests = [];
  globalThis.fetch = async (url, options = {}) => {
    const parsed = new URL(String(url));
    requests.push(options.method ?? 'GET');
    if (parsed.pathname === '/data.json') return Response.json({ notes: [] });
    if (parsed.pathname === '/') return new Response('<main>자료실</main>', { status: 200 });
    if (parsed.pathname === '/aleph.json') return Response.json({ step: 7 });
    if (parsed.pathname === '/rest/v1/vault_notes') return new Response(null, { status: 403 });
    throw new Error('Unexpected stage7 URL');
  };
  try {
    const result = await runAttackChecks({
      ...config,
      step: 7,
      originalApiUrl: 'https://student.supabase.co/rest/v1/vault_notes',
    });
    assert.equal(result.length, 7);
    assert.deepEqual(result.slice(3).map(item => item.attackId), [
      'registered_device_read_local', 'unregistered_device_read_local',
      'suspicious_step_up_local', 'suspicious_reauthenticated_local',
    ]);
    assert.ok(result.slice(3).every(item => item.observed.includes('연습 통과')));
    assert.deepEqual(requests, ['GET', 'GET', 'GET', 'GET', 'PATCH']);
    assert.doesNotMatch(JSON.stringify(result), /Bearer\\s|eyJ|가상 본문/u);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('eighth attack self-check distinguishes resources and marks live cross-user check unexecuted', async () => {
  const originalFetch = globalThis.fetch;
  const calls = [];
  globalThis.fetch = async (url, options = {}) => {
    const path = new URL(String(url)).pathname;
    calls.push([path, options.method ?? 'GET']);
    if (path === '/data.json') return Response.json({ notes: [] });
    if (path === '/') return new Response('<main>자료실</main>', { status: 200 });
    if (path === '/aleph.json') return Response.json({ step: 8 });
    if (path === '/rest/v1/vault_notes') return new Response(null, { status: 403 });
    throw new Error('unexpected stage 8 URL');
  };
  try {
    const out = await runAttackChecks({
      ...config, step: 8,
      originalApiUrl: 'https://student.supabase.co/rest/v1/vault_notes',
    });
    assert.equal(out.length, 10);
    assert.deepEqual(out.slice(-3).map(row => row.attackId), [
      'resource_zone_path_local', 'student_role_spoof_local', 'cross_owner_api_live',
    ]);
    assert.ok(out[7].observed.includes('검증 통과'));
    assert.ok(out[8].observed.includes('검사 통과'));
    assert.match(out[9].observed, /미실행/u);
    assert.deepEqual(calls.map(c => c[1]),['GET','GET','GET','GET','PATCH']);
  } finally { globalThis.fetch = originalFetch; }
});

test('ninth self-check records documented detector exercises, not live revocation', async () => {
  const originalFetch = globalThis.fetch;
  const calls = [];
  globalThis.fetch = async (url, options = {}) => {
    const path = new URL(String(url)).pathname;
    calls.push(options.method ?? 'GET');
    if (path === '/data.json') return Response.json({ notes: [] });
    if (path === '/') return new Response('<main>자료실</main>', { status: 200 });
    if (path === '/aleph.json') return Response.json({ step: 9 });
    if (path === '/rest/v1/vault_notes') return new Response(null, { status: 403 });
    throw new Error('unexpected stage 9 URL');
  };
  try {
    const attempts = await runAttackChecks({
      ...config, step: 9,
      originalApiUrl: 'https://student.supabase.co/rest/v1/vault_notes',
    });
    assert.equal(attempts.length, 16);
    assert.deepEqual(attempts.slice(-6).map(row => row.attackId), [
      'normal_read_observe_local', 'boundary_120_observe_local',
      'burst_121_proposal_local', 'burst_200_proposal_local',
      'mixed_users_observe_local', 'outside_window_observe_local',
    ]);
    assert.ok(attempts.slice(-6).every(row => row.observed.startsWith('가상 탐지 연습 통과')));
    assert.match(attempts[9].observed, /미실행/u);
    assert.deepEqual(calls, ['GET','GET','GET','GET','PATCH']);
    assert.doesNotMatch(JSON.stringify(attempts), /eyJ[A-Za-z0-9_-]{12,}|Bearer\s+[\w.-]+/u);
  } finally {
    globalThis.fetch = originalFetch;
  }
});
