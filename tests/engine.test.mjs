import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createDetector, detectInjection, RULES } from '../src/engine.js';

const T0 = Date.UTC(2026, 10, 24, 2, 0, 0);
const fail = (ip, user, ts) => ({ type: 'auth', ts, ip, user, ok: false });
const ok = (ip, user, ts) => ({ type: 'auth', ts, ip, user, ok: true });

function run(det, events) {
  const alerts = [];
  const actions = [];
  for (const e of events) { const r = det.ingest(e); alerts.push(...r.alerts); actions.push(...r.actions); }
  return { alerts, actions, rules: [...new Set(alerts.map((a) => a.rule))] };
}

test('brute force fires at the threshold, not one before', () => {
  const seven = run(createDetector(), Array.from({ length: 7 }, (_, i) => fail('203.0.113.5', 'admin', T0 + i * 1000)));
  assert.deepEqual(seven.rules, [], 'seven typos in a minute is not an attack yet');
  const eight = run(createDetector(), Array.from({ length: 8 }, (_, i) => fail('203.0.113.5', 'admin', T0 + i * 1000)));
  assert.deepEqual(eight.rules, ['brute-force']);
  assert.equal(eight.alerts[0].mitre, 'T1110.001');
  assert.deepEqual(eight.actions.map((a) => [a.type, a.ip]), [['block', '203.0.113.5']]);
});

test('failures spread outside the window are not a burst', () => {
  const r = run(createDetector(), Array.from({ length: 10 }, (_, i) => fail('203.0.113.5', 'admin', T0 + i * 10_000)));
  assert.ok(!r.rules.includes('brute-force'), '10 failures over 90 seconds stays under 8 per 60s');
});

test('password spray: many accounts, few tries each', () => {
  const users = ['admin', 'aina', 'farid', 'mei', 'raj'];
  const r = run(createDetector(), users.map((u, i) => fail('198.51.100.7', u, T0 + i * 2000)));
  assert.deepEqual(r.rules, ['password-spray']);
  assert.match(r.alerts[0].detail, /5 different accounts/);
});

test('hammering many accounts hard is brute force, not a spray', () => {
  const events = [];
  for (const u of ['a', 'b', 'c', 'd', 'e']) for (let i = 0; i < 4; i++) events.push(fail('198.51.100.7', u, T0 + events.length * 500));
  const r = run(createDetector({ bruteForce: { failures: 4 } }), events);
  assert.ok(r.rules.includes('brute-force'));
  assert.ok(!r.rules.includes('password-spray'), 'four tries per account is over the spray profile');
});

test('distributed brute force locks the account instead of blocking one address', () => {
  const events = Array.from({ length: 12 }, (_, i) => fail(`192.0.2.${10 + (i % 4)}`, 'aina', T0 + i * 3000));
  const det = createDetector();
  const r = run(det, events);
  assert.deepEqual(r.rules, ['distributed-brute-force']);
  assert.deepEqual(r.actions.map((a) => a.type), ['lock']);
  assert.ok(det.isLocked('aina', T0 + 40_000));
  assert.equal(det.isLocked('aina', T0 + 33_000 + det.config.lockMs + 1), null, 'locks expire');
});

test('low and slow brute force, raised once, and not on top of a fast one', () => {
  const det = createDetector();
  const slow = run(det, Array.from({ length: 25 }, (_, i) => fail('203.0.113.200', 'backup', T0 + i * 150_000)));
  assert.deepEqual(slow.rules, ['slow-brute-force']);
  assert.equal(new Set(slow.alerts.map((a) => a.id)).size, 1, 'one alert that keeps updating, not one per guess');

  const fast = run(createDetector(), Array.from({ length: 30 }, (_, i) => fail('203.0.113.45', 'root', T0 + i * 1000)));
  assert.ok(!fast.rules.includes('slow-brute-force'));
});

test('a success after many failures is a critical possible compromise', () => {
  const det = createDetector({ autoBlock: false });
  const events = [...Array.from({ length: 6 }, (_, i) => fail('198.51.100.61', 'deploy', T0 + i * 4000)), ok('198.51.100.61', 'deploy', T0 + 30_000)];
  const r = run(det, events);
  const c = r.alerts.find((a) => a.rule === 'compromise-suspected');
  assert.equal(c.severity, 'critical');
  assert.equal(c.mitre, 'T1078');
  assert.deepEqual(r.actions, [], 'auto-block off means alert only');
});

test('a normal user with one typo raises nothing', () => {
  const r = run(createDetector(), [fail('192.0.2.10', 'aina', T0), ok('192.0.2.10', 'aina', T0 + 5000)]);
  assert.deepEqual(r.alerts, []);
});

test('injection patterns: real attacks caught, real passwords left alone', () => {
  for (const p of ["admin' OR '1'='1' -- ", "' or 1=1#", "x' UNION SELECT user, pass FROM users--", '<script>alert(1)</script>', "admin'--", '${jndi:ldap://x/a}', "1'; DROP TABLE users;--", "'; WAITFOR DELAY '0:0:5'--"]) {
    assert.ok(detectInjection(p), `should flag: ${p}`);
  }
  for (const p of ['Kopi2026#', "O'Brien", 'P@ss/word--2', 'correct horse battery staple', 'tr0ub4dor&3', 'Raj#Payroll#7731', 'select-me-1', 'or=1']) {
    assert.equal(detectInjection(p), null, `should not flag: ${p}`);
  }
});

test('port scan across decoys, and a single touch stays low', () => {
  const det = createDetector();
  const one = run(det, [{ type: 'conn', ts: T0, ip: '203.0.113.88', port: 22, service: 'SSH' }]);
  assert.deepEqual(one.rules, ['honeypot-touch']);
  assert.equal(one.alerts[0].severity, 'low');
  const more = run(det, [21, 23, 3389].map((port, i) => ({ type: 'conn', ts: T0 + (i + 1) * 200, ip: '203.0.113.88', port })));
  assert.deepEqual(more.rules, ['port-scan']);
  assert.ok(det.isBlocked('203.0.113.88', T0 + 1000));
});

test('blocks expire and repeat hits update one alert', () => {
  const det = createDetector({ blockMs: 10_000 });
  const r = run(det, Array.from({ length: 12 }, (_, i) => fail('203.0.113.5', 'admin', T0 + i * 1000)));
  assert.equal(r.actions.length, 1, 'blocked once');
  assert.equal(new Set(r.alerts.map((a) => a.id)).size, 1);
  assert.equal(r.alerts.at(-1).hits, 5);
  assert.ok(det.isBlocked('203.0.113.5', T0 + 12_000));
  assert.equal(det.isBlocked('203.0.113.5', T0 + 30_000), null);
});

test('every rule has the fields the dashboard and README rely on', () => {
  for (const [id, r] of Object.entries(RULES)) {
    for (const k of ['title', 'severity', 'mitre', 'tactic', 'explain', 'respond']) assert.ok(r[k], `${id}.${k}`);
    assert.match(r.mitre, /^T\d{4}(\.\d{3})?$/);
  }
});
