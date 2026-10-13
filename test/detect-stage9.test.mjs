import assert from 'node:assert/strict';
import { test } from 'node:test';
import { detect } from '../src/detect.mjs';
import { checkDetection } from '../scripts/detect-test.mjs';

const START = Date.parse('2026-10-01T00:00:00.000Z');
const reads = (n, { sub = 'learner_fixture', interval = 2000, start = START,
    method = 'GET' } = {}) => Array.from({ length: n }, (_, index) => ({
  at: new Date(start + index * interval).toISOString(), method,
  identity: { sub },
}));
const propose = subject => ({ action: 'propose_revocation',
  reasonCode: 'burst_read', subject });

test('the six exact supplied detection-contract fixtures are preserved', async () => {
  const results = await checkDetection(detect);
  assert.equal(results.length, 6);
  assert.ok(results.every(item => item.passed));
});

test('the 120 boundary remains observe; 121 inside 10 minutes proposes revocation', () => {
  assert.deepEqual(detect(reads(120)), { action: 'observe' });
  assert.deepEqual(detect(reads(121)), propose('learner_fixture'));
  assert.deepEqual(detect(reads(121).reverse()), propose('learner_fixture'));
});

test('individual subjects and GET-only events are counted, never combined', () => {
  assert.deepEqual(detect([...reads(100), ...reads(100, {sub:'second_fixture'})]),
    { action: 'observe' });
  assert.deepEqual(detect([...reads(120), ...reads(30, {method:'POST'})]),
    { action: 'observe' });
  assert.deepEqual(detect([...reads(100, {sub:'second_fixture'}), ...reads(121)]),
    propose('learner_fixture'));
});

test('sliding ten-minute windows cannot pool older events or outside-boundary requests', () => {
  assert.deepEqual(detect(reads(200, {interval:7000})), { action: 'observe' });
  assert.deepEqual(detect([...reads(120, {interval:100}), ...reads(1, {start:START + 600000})]),
    { action: 'observe' });
  assert.deepEqual(detect(reads(121, {interval:0})), propose('learner_fixture'));
});

test('malformed or untrusted event shape cannot inflate an identity counter', () => {
  const invalid = [
    { method:'GET', at:'invalid', identity:{sub:'learner_fixture'} },
    { method:'GET', at:'2026-10-01T00:00:00.000Z', identity:{sub:''} },
    { method:'GET', at:'2026-10-01T00:00:00.000Z', identity:{} },
    { method:'PATCH', at:'2026-10-01T00:00:00.000Z', identity:{sub:'learner_fixture'} },
  ];
  assert.deepEqual(detect([...reads(120), ...invalid]), { action: 'observe' });
  assert.throws(() => detect(null), { name: 'TypeError' });
});

test('detection is side-effect-free and does not insert device, token, or location fields', () => {
  const events = reads(121);
  const before = JSON.stringify(events);
  const reply = detect(events);
  assert.equal(JSON.stringify(events), before);
  assert.deepEqual(Object.keys(reply).sort(), ['action','reasonCode','subject']);
  assert.ok(!['deviceId','token','ip','network','region','noteBody'].some(k =>
    Object.hasOwn(reply, k)));
  const routine = detect(reads(40));
  assert.deepEqual(Object.keys(routine), ['action']);
});
