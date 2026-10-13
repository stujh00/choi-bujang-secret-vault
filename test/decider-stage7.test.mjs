import assert from 'node:assert/strict';
import { test } from 'node:test';
import { decide, RULE_IDS } from '../src/decider.mjs';
import { fixtureRequests } from '../scripts/fixture-7.mjs';

const normalFixture = () => fixtureRequests().normal;
const suspiciousFixture = () => fixtureRequests().suspicious;
const expectDecision = async (request, decision, reasonCode) => {
  const response = await decide(request);
  assert.deepEqual(Object.keys(response).sort(), ['decision','reasonCode','requestId','ruleIds','schema']);
  assert.equal(response.requestId, request.requestId);
  assert.equal(response.schema, 'aleph.decision.v1');
  assert.equal(response.decision, decision);
  assert.equal(response.reasonCode, reasonCode);
  assert.ok(response.ruleIds.every(rule => RULE_IDS.includes(rule)));
};

test('등록 기기 정상 요청과 기존 미등록 거부 규칙을 유지합니다', async () => {
  const normal = normalFixture();
  await expectDecision(normal, 'allow', 'approved');
  await expectDecision({ ...normal, deviceRegistered: false }, 'deny', 'device_not_registered');
  await expectDecision({ ...normal, deviceRegistered: undefined }, 'deny', 'device_not_registered');
  await expectDecision({ ...normal, deviceRegistered: 'true' }, 'deny', 'device_not_registered');
});

test('엔진 가상 복합 이상 접속에는 추가 인증을 요구하며 완료 후 읽기만 허용합니다', async () => {
  const suspicious = suspiciousFixture();
  await expectDecision(suspicious, 'step_up', 'step_up_required');
  await expectDecision({ ...suspicious, stepUp: { verified: true, authAgeSeconds: 60 } },
    'allow', 'approved');
  await expectDecision({ ...suspicious, stepUp: { verified: true, authAgeSeconds: 600 } },
    'step_up', 'step_up_required');
  await expectDecision({ ...suspicious, stepUp: { verified: 'true', authAgeSeconds: 60 } },
    'step_up', 'step_up_required');
  await expectDecision({ ...suspicious, stepUp: { verified: false, authAgeSeconds: null } },
    'step_up', 'step_up_required');
});

test('하나의 낯선 지역이나 시각만으로 추가 인증을 요청하지 않습니다', async () => {
  const ordinary = normalFixture();
  await expectDecision({ ...ordinary,
    signals: { source: 'judge_fixture', region: 'foreign', network: 'usual', hour: 14 },
  }, 'allow', 'approved');
  await expectDecision({ ...ordinary,
    signals: { source: 'judge_fixture', region: 'local', network: 'usual', hour: 3 },
  }, 'allow', 'approved');
});

test('client 위치 헤더와 불명확한 신호는 신뢰하지 않습니다', async () => {
  const suspicious = suspiciousFixture();
  await expectDecision({ ...suspicious,
    signals: { ...suspicious.signals, source: 'none' },
    headers: { 'x-forwarded-for': '203.0.113.200', 'x-region': 'foreign' },
  }, 'allow', 'approved');
  await expectDecision({ ...suspicious,
    signals: { ...suspicious.signals, source: 'client_headers' },
  }, 'allow', 'approved');
  await expectDecision({ ...suspicious,
    signals: { source: 'judge_fixture', region: 'unknown', network: 'unknown', hour: null },
    recentEvents: [],
  }, 'allow', 'approved');
});

test('대량 수정은 미인증 시 추가 확인이지만, 확인 후에도 6단계 쓰기 거부가 유지됩니다', async () => {
  const suspicious = suspiciousFixture();
  const write = { ...suspicious, method: 'PUT', route: 'PUT /notes/:id',
    signals: { source: 'judge_fixture', region: 'unknown', network: 'unusual', hour: 14 } };
  await expectDecision(write, 'step_up', 'step_up_required');
  await expectDecision({ ...write, stepUp: { verified: true, authAgeSeconds: 60 } },
    'deny', 'starter_not_ready');
  await expectDecision({ ...write, deviceRegistered: false },
    'deny', 'device_not_registered');
});

test('등록된 기기라도 신원 형식이 불확실한 사건은 허용하지 않습니다', async () => {
  const suspicious = suspiciousFixture();
  await expectDecision({ ...suspicious, subjectId: undefined }, 'deny', 'starter_not_ready');
  await expectDecision({ ...suspicious, deviceId: 'invalid' }, 'deny', 'starter_not_ready');
  await expectDecision({ ...suspicious, service: 'admin', route: 'GET /admin', path: '/admin' },
    'deny', 'starter_not_ready');
});
