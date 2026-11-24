// The live lab: a deliberately attackable login portal, decoy ports, the detection engine,
// and a Server-Sent Events stream that feeds the dashboard in real time.
// Binds to 127.0.0.1 by default. The portal has weak demo passwords on purpose, so do not expose it.

import { createServer as createHttp } from 'node:http';
import { createServer as createTcp } from 'node:net';
import { readFile } from 'node:fs/promises';
import { extname, join, normalize, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createDetector, detectInjection, VERSION } from '../src/engine.js';
import { runScenario, SCENARIOS } from './attacks.mjs';
import { ACCOUNTS } from '../src/labdata.js';

export { ACCOUNTS };

const ROOT = resolve(fileURLToPath(new URL('..', import.meta.url)));
const TYPES = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.mjs': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8', '.svg': 'image/svg+xml', '.json': 'application/json', '.png': 'image/png' };

export const DEFAULT_DECOYS = [
  { port: 2121, service: 'FTP', banner: '220 (vsFTPd 3.0.3)\r\n' },
  { port: 2222, service: 'SSH', banner: 'SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10\r\n' },
  { port: 2323, service: 'Telnet', banner: '\r\nUbuntu 22.04.4 LTS\r\nlogin: ' },
  { port: 5901, service: 'VNC', banner: 'RFB 003.008\n' },
  { port: 9201, service: 'Elasticsearch', banner: '' },
];

const isLoopback = (ip) => /^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(ip) || ip === '::1';
const clean = (ip) => String(ip || '').replace(/^::ffff:/, '');

export function createLab(opts = {}) {
  const host = opts.host || '127.0.0.1';
  const port = opts.port ?? 3000;
  const decoys = opts.decoys ?? DEFAULT_DECOYS;
  const quiet = !!opts.quiet;
  const log = (...a) => { if (!quiet) console.log(...a); };
  let detector = createDetector(opts.detector || {});
  const clients = new Set();
  const decoyServers = [];
  const decoysUp = [];
  let http;
  let running = null; // the scenario currently running from the dashboard

  function broadcast(kind, data) {
    const msg = `event: ${kind}\ndata: ${JSON.stringify(data)}\n\n`;
    for (const res of clients) res.write(msg);
    opts.onMessage?.(kind, data);
  }

  function handle(event) {
    const res = detector.ingest(event);
    broadcast('event', event);
    for (const a of res.alerts) {
      broadcast('alert', a);
      if (!a.updated) log(`[${a.severity.toUpperCase()}] ${a.title}: ${a.detail} (${a.mitre})`);
    }
    for (const act of res.actions) {
      broadcast('action', act);
      log(act.type === 'block' ? `  -> blocked ${act.ip} for ${Math.round((act.until - Date.now()) / 1000)}s` : `  -> locked account "${act.user}"`);
    }
    broadcast('stats', detector.snapshot(Date.now()).stats);
    return res;
  }

  // Lab-only source override: lets the attack simulator act as several attackers on systems that only
  // have 127.0.0.1 configured (macOS). Accepted only from loopback, and only as another loopback address.
  function sourceIp(req) {
    const real = clean(req.socket.remoteAddress);
    const claimed = String(req.headers['x-tripline-lab-source'] || '');
    if (claimed && isLoopback(real) && /^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(claimed)) return claimed;
    return real;
  }

  async function readBody(req, limit = 16 * 1024) {
    let size = 0;
    const chunks = [];
    for await (const c of req) { size += c.length; if (size > limit) throw new Error('body too large'); chunks.push(c); }
    const raw = Buffer.concat(chunks).toString('utf8');
    if (/json/.test(req.headers['content-type'] || '')) { try { return JSON.parse(raw || '{}'); } catch { return {}; } }
    return Object.fromEntries(new URLSearchParams(raw));
  }

  function send(res, status, body, type = 'text/html; charset=utf-8', extra = {}) {
    res.writeHead(status, {
      'Content-Type': type, 'X-Content-Type-Options': 'nosniff', 'Cache-Control': 'no-store', 'Referrer-Policy': 'no-referrer',
      'Content-Security-Policy': "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'none'",
      ...extra,
    });
    res.end(body);
  }
  const json = (res, status, data) => send(res, status, JSON.stringify(data), 'application/json');

  async function staticFile(res, urlPath) {
    let rel = urlPath === '/' ? '/web/index.html' : urlPath.startsWith('/src/') ? urlPath : '/web' + urlPath;
    if (urlPath === '/portal') rel = '/web/portal.html';
    const file = normalize(join(ROOT, rel));
    if (!file.startsWith(ROOT + sep)) return send(res, 403, 'Forbidden', 'text/plain');
    try {
      return send(res, 200, await readFile(file), TYPES[extname(file)] || 'application/octet-stream');
    } catch {
      return send(res, 404, 'Not found', 'text/plain');
    }
  }

  function portalPage(status, title, message, tone) {
    return `<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>${title} | Acme Staff Portal</title><link rel="stylesheet" href="/portal.css"></head><body><main class="portal"><h1>Acme Staff Portal</h1><p class="msg ${tone}">${message}</p><p><a href="/portal">Back to sign in</a></p></main></body></html>`;
  }

  async function login(req, res) {
    const ip = sourceIp(req);
    const now = Date.now();
    let body;
    try { body = await readBody(req); } catch { return send(res, 413, 'Too large', 'text/plain'); }
    const user = String(body.username ?? body.user ?? '').slice(0, 128);
    const pass = String(body.password ?? body.pass ?? '').slice(0, 256);
    const wantsJson = /json/.test(req.headers.accept || '') || /json/.test(req.headers['content-type'] || '');

    const blocked = detector.isBlocked(ip, now);
    if (blocked) {
      detector.noteBlockedAttempt(ip, now);
      broadcast('event', { type: 'auth', ts: now, ip, user, ok: false, blocked: true, source: 'portal' });
      const msg = `Access from ${ip} is blocked by Tripline (${blocked.reason}). Try again in ${Math.ceil((blocked.until - now) / 1000)}s.`;
      return wantsJson ? json(res, 403, { ok: false, blocked: true, message: msg }) : send(res, 403, portalPage(403, 'Blocked', msg, 'bad'));
    }
    const locked = detector.isLocked(user, now);
    if (locked) {
      broadcast('event', { type: 'auth', ts: now, ip, user, ok: false, locked: true, source: 'portal' });
      const msg = `The account "${escapeHtml(user)}" is temporarily locked. Contact IT.`;
      return wantsJson ? json(res, 423, { ok: false, locked: true, message: msg }) : send(res, 423, portalPage(423, 'Locked', msg, 'bad'));
    }

    // The password is checked and then dropped. Only the injection pattern name, if any, reaches the engine.
    const injection = detectInjection(user, pass);
    const ok = !injection && Object.hasOwn(ACCOUNTS, user) && ACCOUNTS[user] === pass;
    handle({ type: 'auth', ts: now, ip, user, ok, knownUser: Object.hasOwn(ACCOUNTS, user), injection, source: 'portal' });

    if (ok) return wantsJson ? json(res, 200, { ok: true, message: `Welcome, ${user}` }) : send(res, 200, portalPage(200, 'Welcome', `Welcome back, ${escapeHtml(user)}. You are signed in.`, 'good'));
    return wantsJson ? json(res, 401, { ok: false, message: 'Invalid username or password' }) : send(res, 401, portalPage(401, 'Sign in failed', 'Invalid username or password.', 'bad'));
  }

  function events(req, res) {
    res.writeHead(200, { 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-store', Connection: 'keep-alive', 'X-Accel-Buffering': 'no' });
    res.write(`retry: 2000\nevent: hello\ndata: ${JSON.stringify(hello())}\n\n`);
    res.write(`event: snapshot\ndata: ${JSON.stringify(detector.snapshot(Date.now()))}\n\n`);
    clients.add(res);
    const beat = setInterval(() => res.write(': ping\n\n'), 15000);
    req.on('close', () => { clearInterval(beat); clients.delete(res); });
  }

  function hello() {
    return {
      mode: 'live', version: VERSION, portal: '/portal', accounts: Object.keys(ACCOUNTS),
      decoys: decoysUp, autoBlock: detector.config.autoBlock, scenarios: Object.keys(SCENARIOS), running,
    };
  }

  async function api(req, res, path) {
    if (req.method === 'GET' && path === '/api/hello') return json(res, 200, hello());
    if (req.method === 'GET' && path === '/api/state') return json(res, 200, detector.snapshot(Date.now()));
    // Control endpoints change the lab, so they only answer to this machine.
    if (!isLoopback(clean(req.socket.remoteAddress))) return json(res, 403, { error: 'control API is loopback only' });
    let body = {};
    try { body = await readBody(req); } catch { return json(res, 413, { error: 'too large' }); }
    if (req.method === 'POST' && path === '/api/reset') {
      const autoBlock = detector.config.autoBlock;
      detector = createDetector({ ...(opts.detector || {}), autoBlock });
      broadcast('snapshot', detector.snapshot(Date.now()));
      return json(res, 200, { ok: true });
    }
    if (req.method === 'POST' && path === '/api/config') {
      if (typeof body.autoBlock === 'boolean') detector.config.autoBlock = body.autoBlock;
      broadcast('hello', hello());
      return json(res, 200, { ok: true, autoBlock: detector.config.autoBlock });
    }
    if (req.method === 'POST' && path === '/api/simulate') {
      const name = String(body.scenario || '');
      if (!SCENARIOS[name]) return json(res, 400, { error: 'unknown scenario', scenarios: Object.keys(SCENARIOS) });
      if (running) return json(res, 409, { error: `"${running}" is still running` });
      running = name;
      broadcast('hello', hello());
      runScenario(name, { port: http.address().port, decoyPorts: decoysUp.map((d) => d.port), quiet: true })
        .catch((e) => log('scenario failed:', e.message))
        .finally(() => { running = null; broadcast('hello', hello()); });
      return json(res, 202, { ok: true, scenario: name });
    }
    return json(res, 404, { error: 'not found' });
  }

  async function onRequest(req, res) {
    try {
      const path = new URL(req.url, 'http://x').pathname;
      if (path === '/login' && req.method === 'POST') return await login(req, res);
      if (path === '/events') return events(req, res);
      if (path.startsWith('/api/')) return await api(req, res, path);
      if (req.method === 'GET') return await staticFile(res, decodeURIComponent(path));
      return send(res, 405, 'Method not allowed', 'text/plain');
    } catch (e) {
      log('request error:', e.message);
      if (!res.headersSent) send(res, 500, 'Server error', 'text/plain');
    }
  }

  function startDecoy(d) {
    return new Promise((resolveP) => {
      const srv = createTcp((sock) => {
        const ip = clean(sock.remoteAddress);
        sock.on('error', () => {});
        // The port actually bound, not the configured one (which can be 0 for "any free port").
        handle({ type: 'conn', ts: Date.now(), ip, port: sock.localPort, service: d.service });
        if (d.banner) sock.write(d.banner);
        sock.setTimeout(3000, () => sock.destroy());
        sock.on('data', () => sock.destroy());
      });
      srv.on('error', (e) => { log(`  decoy ${d.service} on ${d.port} not started (${e.code})`); resolveP(); });
      srv.listen(d.port, host, () => { decoyServers.push(srv); decoysUp.push({ port: srv.address().port, service: d.service }); resolveP(); });
    });
  }

  async function start() {
    http = createHttp(onRequest);
    await new Promise((ok, fail) => { http.once('error', fail); http.listen(port, host, ok); });
    for (const d of decoys) await startDecoy(d);
    return { url: `http://${host === '0.0.0.0' ? '127.0.0.1' : host}:${http.address().port}`, port: http.address().port, decoys: decoysUp };
  }

  async function stop() {
    for (const c of clients) c.end();
    clients.clear();
    await Promise.all([http, ...decoyServers].filter(Boolean).map((s) => new Promise((r) => { s.close(() => r()); s.closeAllConnections?.(); })));
  }

  return { start, stop, handle, get detector() { return detector; } };
}

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}
