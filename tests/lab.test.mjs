// End to end: a real server, real HTTP and TCP attacks against it.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { request } from 'node:http';
import { createLab } from '../server/lab.mjs';
import { runScenario, assertLoopback } from '../server/attacks.mjs';
import { ACCOUNTS } from '../src/labdata.js';

let lab;
let info;

before(async () => {
  lab = createLab({ port: 0, quiet: true, decoys: ['FTP', 'SSH', 'Telnet', 'VNC'].map((service) => ({ port: 0, service, banner: '' })) });
  info = await lab.start();
});
after(() => lab.stop());

function http(method, path, body, headers = {}) {
  return new Promise((resolve, reject) => {
    const data = body === undefined ? '' : typeof body === 'string' ? body : JSON.stringify(body);
    const req = request({ host: '127.0.0.1', port: info.port, method, path, headers: { 'Content-Length': Buffer.byteLength(data), ...headers } }, (res) => {
      let text = '';
      res.on('data', (c) => { text += c; });
      res.on('end', () => resolve({ status: res.statusCode, text, headers: res.headers }));
    });
    req.on('error', reject);
    req.end(data);
  });
}
const form = (user, pass, extra = {}) => http('POST', '/login', `username=${encodeURIComponent(user)}&password=${encodeURIComponent(pass)}`, { 'Content-Type': 'application/x-www-form-urlencoded', ...extra });

test('the portal works like a normal login form (so Hydra can attack it)', async () => {
  const bad = await form('aina', 'nope');
  assert.equal(bad.status, 401);
  assert.match(bad.text, /Invalid username or password/);
  const good = await form('aina', ACCOUNTS.aina);
  assert.equal(good.status, 200);
  assert.match(good.text, /Welcome back, aina/);
  assert.match(good.headers['content-security-policy'], /default-src 'self'/);
});

test('a brute force run gets blocked mid-attack', async () => {
  const lines = [];
  const result = await runScenario('brute', { port: info.port, speed: 20, say: (l) => lines.push(l) });
  assert.equal(result, 'blocked');
  const alert = lab.detector.alerts.find((a) => a.rule === 'brute-force' && a.ip === '127.0.0.66');
  assert.ok(alert, lines.join('\n'));
  assert.ok(lines.some((l) => l.includes('-> 403 BLOCKED')));
  assert.ok(!lines.some((l) => l.includes('SUCCESS')), 'the block lands before "sunshine" is reached');
});

test('with auto-block off the attacker wins, and Tripline raises a critical alert', async () => {
  await http('POST', '/api/config', { autoBlock: false }, { 'Content-Type': 'application/json' });
  await http('POST', '/api/reset', {}, { 'Content-Type': 'application/json' });
  const result = await runScenario('brute', { port: info.port, speed: 20, quiet: true });
  assert.equal(result, 'cracked');
  const c = lab.detector.alerts.find((a) => a.rule === 'compromise-suspected');
  assert.equal(c.severity, 'critical');
  assert.equal(c.user, 'admin');
  await http('POST', '/api/config', { autoBlock: true }, { 'Content-Type': 'application/json' });
});

test('port scans are caught on the decoys', async () => {
  await runScenario('scan', { port: info.port, decoyPorts: info.decoys.map((d) => d.port), speed: 20, quiet: true });
  assert.ok(lab.detector.alerts.some((a) => a.rule === 'port-scan' && a.ip === '127.0.0.88'));
});

test('injection in the login form is flagged and never logs in', async () => {
  const r = await form("admin' OR '1'='1' -- ", 'x', { 'X-Tripline-Lab-Source': '127.0.0.150' });
  assert.equal(r.status, 401);
  assert.ok(lab.detector.alerts.some((a) => a.rule === 'login-injection' && a.ip === '127.0.0.150'));
  const again = await form('admin', ACCOUNTS.admin, { 'X-Tripline-Lab-Source': '127.0.0.150' });
  assert.equal(again.status, 403, 'blocked, even with the right password');
});

test('passwords never reach alerts, snapshots or the event stream', async () => {
  const secret = 'Tr1pl1ne-should-never-see-this';
  for (let i = 0; i < 9; i++) await form('mei', secret, { 'X-Tripline-Lab-Source': '127.0.0.160' });
  const state = await http('GET', '/api/state');
  assert.ok(state.text.includes('127.0.0.160'));
  assert.ok(!state.text.includes(secret));
});

test('the lab source header only accepts loopback addresses', async () => {
  await form('raj', 'x', { 'X-Tripline-Lab-Source': '8.8.8.8' });
  const state = JSON.parse((await http('GET', '/api/state')).text);
  assert.ok(!state.attackers.some((a) => a.ip === '8.8.8.8'));
});

test('the simulator refuses to attack anything but this machine', () => {
  for (const h of ['example.com', '10.0.0.5', '192.168.1.1', '8.8.8.8', '127.0.0.1.evil.example']) assert.throws(() => assertLoopback(h), /Refusing/);
  for (const h of ['localhost', '127.0.0.1', '127.0.0.66', '::1']) assert.doesNotThrow(() => assertLoopback(h));
});

test('static files cannot be read outside the project', async () => {
  for (const p of ['/../package.json', '/%2e%2e/%2e%2e/package.json', '/src/../../package.json']) {
    const r = await http('GET', p);
    assert.ok([403, 404].includes(r.status), `${p} -> ${r.status}`);
  }
  assert.equal((await http('GET', '/')).status, 200);
  assert.equal((await http('GET', '/src/engine.js')).status, 200);
});

test('the event stream sends hello and a snapshot on connect', async () => {
  const text = await new Promise((resolve, reject) => {
    const req = request({ host: '127.0.0.1', port: info.port, path: '/events' }, (res) => {
      let buf = '';
      res.on('data', (c) => { buf += c; if (buf.includes('event: snapshot')) { req.destroy(); resolve(buf); } });
    });
    req.on('error', (e) => (e.code === 'ECONNRESET' ? null : reject(e)));
    req.end();
  });
  assert.match(text, /event: hello\ndata: \{"mode":"live"/);
  assert.match(text, /event: snapshot/);
});
