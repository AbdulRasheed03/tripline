import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createDetector } from '../src/engine.js';
import { parseLine, parseLog } from '../src/parsers.js';

const T0 = Date.UTC(2026, 10, 24, 2, 0, 0);
const http = (ip, path, status = 200, ua = 'Mozilla/5.0', ts = T0) => ({ type: 'http', ts, ip, method: 'GET', path, status, ua });
const rulesOf = (det, events) => {
  const seen = new Map();
  for (const e of events) for (const a of det.ingest(e).alerts) seen.set(a.id, a);
  return [...seen.values()];
};

test('nginx combined and Apache common lines parse', () => {
  const e = parseLine('203.0.113.9 - - [24/Nov/2026:02:10:01 +0800] "GET /wp-login.php?x=1 HTTP/1.1" 404 153 "-" "Mozilla/5.0 (compatible; Nmap Scripting Engine)"');
  assert.deepEqual(e, { type: 'http', ts: Date.parse('2026-11-24T02:10:01+08:00'), ip: '203.0.113.9', method: 'GET', path: '/wp-login.php?x=1', status: 404, ua: 'Mozilla/5.0 (compatible; Nmap Scripting Engine)', source: 'web' });
  const common = parseLine('2001:db8::5 - frank [01/Dec/2026:23:59:59 -0500] "POST /login HTTP/1.0" 401 0');
  assert.equal(common.ip, '2001:db8::5');
  assert.equal(common.status, 401);
  assert.equal(common.ua, '');
});

test('scanner user agents are recognised, browsers are not', () => {
  for (const ua of ['sqlmap/1.8.4#stable', 'Mozilla/5.00 (Nikto/2.5.0)', 'Nuclei - Open-source project', 'gobuster/3.6', 'Fuzz Faster U Fool v2.1.0 ffuf']) {
    const a = rulesOf(createDetector(), [http('203.0.113.1', '/', 200, ua)]);
    assert.ok(a.some((x) => x.rule === 'web-scanner'), ua);
  }
  const normal = rulesOf(createDetector(), [http('192.0.2.1', '/', 200, 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/131.0')]);
  assert.deepEqual(normal, []);
});

test('injection and traversal in URLs, including URL-encoded and double-encoded', () => {
  for (const p of ['/search?q=kopi%27%20OR%201%3D1--', '/item?id=1%20UNION%20SELECT%20NULL', '/dl?f=..%2F..%2F..%2Fetc%2Fpasswd', '/dl?f=%252e%252e%252f%252e%252e%252fwin.ini', '/ping?h=1;cat%20/etc/passwd', '/p?q=%3Cscript%3Ealert(1)%3C/script%3E']) {
    const a = rulesOf(createDetector(), [http('203.0.113.2', p, 400)]);
    assert.ok(a.some((x) => x.rule === 'web-injection'), p);
  }
});

test('scary-looking but harmless URLs do not alert', () => {
  for (const p of ['/blog/union-select-guide', "/search?q=O'Brien+kopi", '/search?q=salt+%26+pepper', '/docs/select-or-insert', '/a/b/c/../d', '/files/report-2026.pdf']) {
    assert.deepEqual(rulesOf(createDetector(), [http('192.0.2.3', p)]).map((a) => a.rule), [], p);
  }
});

test('directory brute forcing fires on a burst of 404s, not on a few', () => {
  const few = rulesOf(createDetector(), Array.from({ length: 19 }, (_, i) => http('198.51.100.4', `/x${i}`, 404, 'Mozilla/5.0', T0 + i * 500)));
  assert.deepEqual(few, []);
  const det = createDetector();
  const many = rulesOf(det, Array.from({ length: 20 }, (_, i) => http('198.51.100.4', `/x${i}`, 404, 'Mozilla/5.0', T0 + i * 500)));
  assert.deepEqual(many.map((a) => a.rule), ['web-dir-bruteforce']);
  assert.ok(det.isBlocked('198.51.100.4', T0 + 11_000));
});

test('a served secret is its own critical alert and is never overwritten by later probes', () => {
  const det = createDetector();
  const alerts = rulesOf(det, [
    http('192.0.2.77', '/.env', 404, 'Mozilla/5.0', T0),
    http('192.0.2.77', '/.git/config', 200, 'Mozilla/5.0', T0 + 1000),
    http('192.0.2.77', '/phpinfo.php', 404, 'Mozilla/5.0', T0 + 2000),
  ]);
  const leak = alerts.find((a) => a.rule === 'web-secret-exposed');
  assert.equal(leak.severity, 'critical');
  assert.equal(leak.mitre, 'T1552.001');
  assert.match(leak.detail, /\.git\/config was served/);
  const probe = alerts.find((a) => a.rule === 'web-sensitive-probe');
  assert.match(probe.detail, /3 secret or admin file\(s\): \/\.env, \/\.git\/config, \/phpinfo\.php/);
});

test('the sample access.log: every attacker caught, no normal visitor flagged', () => {
  const events = parseLog(readFileSync(new URL('../samples/access.log', import.meta.url), 'utf8'));
  assert.equal(events.length, 94);
  const det = createDetector();
  const alerts = rulesOf(det, events);
  const got = alerts.map((a) => `${a.rule} ${a.ip}`).sort();
  assert.deepEqual(got, [
    'web-dir-bruteforce 198.51.100.40',
    'web-injection 203.0.113.120',
    'web-injection 203.0.113.50',
    'web-scanner 198.51.100.40',
    'web-scanner 203.0.113.50',
    'web-secret-exposed 192.0.2.77',
    'web-sensitive-probe 192.0.2.77',
  ]);
  assert.ok(!alerts.some((a) => /^192\.0\.2\.1\d$/.test(a.ip)), 'normal visitors 192.0.2.10-16 stay quiet');
});
