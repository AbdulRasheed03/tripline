import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { parseLine, parseLog } from '../src/parsers.js';
import { createDetector } from '../src/engine.js';

test('classic syslog sshd lines', () => {
  const f = parseLine('Nov 24 02:08:49 web01 sshd[4021]: Failed password for root from 203.0.113.45 port 51122 ssh2', { year: 2026 });
  assert.deepEqual({ ...f, ts: new Date(f.ts).getMonth() }, { type: 'auth', ts: 10, ip: '203.0.113.45', user: 'root', ok: false, knownUser: true, source: 'ssh' });
  const inv = parseLine('Nov  3 02:13:36 web01 sshd[4022]: Failed password for invalid user oracle from 198.51.100.23 port 40000 ssh2');
  assert.equal(inv.user, 'oracle');
  assert.equal(inv.knownUser, false);
  const acc = parseLine('Nov 24 02:38:30 web01 sshd[4023]: Accepted publickey for aina from 192.0.2.10 port 50000 ssh2: ED25519 SHA256:abc');
  assert.equal(acc.ok, true);
  assert.equal(acc.user, 'aina');
});

test('ISO timestamps from newer systems and IPv6 sources', () => {
  const e = parseLine('2026-11-24T02:08:49.123456+08:00 web01 sshd[4021]: Failed password for root from 2001:db8::7 port 51122 ssh2');
  assert.equal(e.ip, '2001:db8::7');
  assert.equal(e.ts, Date.parse('2026-11-24T02:08:49.123456+08:00'));
});

test('lines that are not login results are ignored', () => {
  for (const l of [
    'Nov 24 02:08:49 web01 sshd[1]: Invalid user oracle from 198.51.100.23 port 40000',
    'Nov 24 02:08:49 web01 sshd[1]: Connection closed by authenticating user root 203.0.113.45 port 51130 [preauth]',
    'Nov 24 02:08:49 web01 sshd[1]: pam_unix(sshd:session): session opened for user deploy',
    'Nov 24 02:08:49 web01 CRON[9]: Failed password for root from 1.2.3.4 port 1 ssh2',
    'not a log line',
    '',
  ]) assert.equal(parseLine(l), null, l);
});

test('JSON lines from other tools', () => {
  const e = parseLine('{"type":"auth","ts":"2026-11-24T02:00:00Z","ip":"203.0.113.9","user":"vpn-user","ok":false,"source":"vpn"}');
  assert.equal(e.source, 'vpn');
  assert.equal(e.ts, Date.parse('2026-11-24T02:00:00Z'));
  assert.equal(parseLine('{"type":"other"}'), null);
});

test('the sample auth.log produces exactly one alert per attacker', () => {
  const events = parseLog(readFileSync(new URL('../samples/auth.log', import.meta.url), 'utf8'), { year: 2026 });
  assert.equal(events.length, 82);
  const det = createDetector();
  const alerts = new Map();
  for (const e of events) for (const a of det.ingest(e).alerts) alerts.set(a.id, a);
  const byRule = Object.fromEntries([...alerts.values()].map((a) => [a.rule, a.ip]));
  assert.deepEqual(byRule, {
    'brute-force': '203.0.113.45',
    'password-spray': '198.51.100.23',
    'compromise-suspected': '198.51.100.61',
    'slow-brute-force': '203.0.113.200',
  });
  assert.ok(![...alerts.values()].some((a) => a.ip === '192.0.2.10'), 'the admin with one typo is not flagged');
});
