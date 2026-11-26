// Tripline dashboard. Talks to the live server over Server-Sent Events when it is running,
// otherwise runs the whole lab in the browser (demo mode, used on GitHub Pages).
// Everything that came from an attacker (usernames, payloads) is inserted with textContent, never as HTML.

import { SEVERITY_RANK } from './src/engine.js';
import { toMarkdown, describeEvent } from './src/report.js';

const $ = (s) => document.querySelector(s);
const SCENARIO_LABELS = {
  scan: ['Port scan', 'T1046'], brute: ['Brute force', 'T1110.001'], spray: ['Password spray', 'T1110.003'],
  distributed: ['Distributed', 'T1110'], injection: ['Login injection', 'T1190'], slow: ['Low and slow', 'T1110.001'], tour: ['Full tour', ''],
};

function el(tag, props = {}, ...kids) {
  const n = document.createElement(tag);
  for (const [k, v] of Object.entries(props)) {
    if (v == null || v === false) continue;
    if (k === 'class') n.className = v;
    else if (k === 'text') n.textContent = v;
    else if (k.startsWith('on')) n.addEventListener(k.slice(2), v);
    else n.setAttribute(k, v);
  }
  for (const c of kids.flat()) if (c != null && c !== false) n.append(c instanceof Node ? c : document.createTextNode(String(c)));
  return n;
}

const time = (ts) => new Date(ts).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
const mitreUrl = (id) => `https://attack.mitre.org/techniques/${id.replace('.', '/')}/`;

// ---------- state ----------
const state = { mode: null, hello: null, alerts: new Map(), stats: {}, snapshot: null };
const buckets = new Map(); // second -> { ok, fail, blk, conn }
let lab = null;            // demo lab, or null in live mode

function bucket(ts) {
  const s = Math.floor(ts / 1000);
  if (!buckets.has(s)) buckets.set(s, { ok: 0, fail: 0, blk: 0, conn: 0 });
  return buckets.get(s);
}

// ---------- message handling (same for live and demo) ----------
function onMessage(kind, data) {
  if (kind === 'hello') { state.hello = data; renderHello(); }
  else if (kind === 'snapshot') { state.alerts.clear(); data.alerts.forEach((a) => state.alerts.set(a.id, a)); state.stats = data.stats; state.snapshot = data; buckets.clear(); $('#feed').replaceChildren(); renderAll(); }
  else if (kind === 'alert') { state.alerts.set(data.id, data); renderAlerts(); if (!data.updated) flash(data); }
  else if (kind === 'stats') { state.stats = data; renderCounters(); }
  else if (kind === 'event') feed(data);
  else if (kind === 'action') feedAction(data);
}

function feed(e) {
  const b = bucket(e.ts || Date.now());
  const { kind, text } = describeEvent(e);
  if (kind in b) b[kind]++; // web requests are listed but not counted in the login chart
  pushFeed(el('li', { class: kind === 'http' ? '' : kind }, el('span', { class: 't', text: time(e.ts || Date.now()) }), ' ', el('span', { text })));
}

function feedAction(a) {
  const text = a.type === 'block' ? `BLOCKED ${a.ip} (${a.reason})` : `LOCKED account ${a.user} (${a.reason})`;
  pushFeed(el('li', { class: 'act' }, el('span', { class: 't', text: time(Date.now()) }), ' ', el('span', { text })));
}

function pushFeed(li) {
  const f = $('#feed');
  f.prepend(li);
  while (f.children.length > 120) f.lastChild.remove();
}

// ---------- rendering ----------
function renderHello() {
  const h = state.hello;
  $('#ver').textContent = 'v' + h.version;
  $('#mode').replaceChildren(
    el('span', { class: `pill ${h.mode}`, text: h.mode === 'live' ? 'Live' : 'Demo' }),
    ' ',
    h.mode === 'live' ? `server on ${location.host}` : 'running in your browser',
  );
  $('#accounts').textContent = h.accounts.join(', ');
  $('#autoblock').checked = h.autoBlock;
  $('#running').textContent = h.running ? `Running: ${SCENARIO_LABELS[h.running]?.[0] || h.running}...` : '';
  const box = $('#scenarios');
  box.replaceChildren(...h.scenarios.map((name) => {
    const [title, mitre] = SCENARIO_LABELS[name] || [name, ''];
    return el('button', { class: 'scenario', type: 'button', disabled: h.running ? '' : null, onclick: () => simulate(name) },
      el('b', { text: title }), mitre ? el('span', { text: mitre }) : null);
  }));
  renderHowto();
}

function renderHowto() {
  const live = state.hello.mode === 'live';
  const port = location.port || '80';
  const box = $('#howto');
  if (live) {
    box.replaceChildren(
      el('h2', { class: 'label', text: 'Attack it from a terminal' }),
      el('p', { class: 'note', text: 'Tripline sees real tools too. Run these on this machine:' }),
      el('pre', { class: 'cmd', text: `node cli/tripline.mjs attack tour\n\nhydra -l admin -P wordlist.txt -s ${port} 127.0.0.1 \\\n  http-post-form "/login:username=^USER^&password=^PASS^:F=Invalid"\n\nnmap -sT -p 2000-10000 127.0.0.1` }),
      el('p', { class: 'note' }, 'The full portal page is at ', el('a', { href: '/portal', text: '/portal' }), '.'),
    );
  } else {
    box.replaceChildren(
      el('h2', { class: 'label', text: 'Run it for real' }),
      el('p', { class: 'note', text: 'This page runs a simulated lab. The real one is a Node.js server you can attack with Hydra, curl and nmap, or point at a Linux server\'s SSH log:' }),
      el('pre', { class: 'cmd', text: 'git clone https://github.com/AbdulRasheed03/tripline\ncd tripline\nnode cli/tripline.mjs serve' }),
    );
  }
}

function renderCounters() {
  const s = state.stats;
  $('#c-attempts').textContent = (s.auth || 0) + (s.blockedAttempts || 0);
  $('#c-failed').textContent = s.failures || 0;
  $('#c-alerts').textContent = s.alerts || 0;
  $('#c-blocked').textContent = s.blockedAttempts || 0;
}

function renderAlerts() {
  const list = [...state.alerts.values()].sort((a, b) => b.lastSeen - a.lastSeen);
  $('#alert-count').textContent = list.length ? `(${list.length})` : '';
  const ol = $('#alerts');
  if (!list.length) { ol.replaceChildren(el('li', { class: 'empty', text: 'Quiet so far. Try a few wrong passwords.' })); return; }
  ol.replaceChildren(...list.map((a) => el('li', { class: `alert sev-${a.severity}`, 'data-id': a.id },
    el('div', { class: 'a-head' },
      el('span', { class: 'sev', text: a.severity }),
      el('b', { class: 'a-title', text: a.title }),
      el('a', { class: 'tag', href: mitreUrl(a.mitre), target: '_blank', rel: 'noopener noreferrer', title: `MITRE ATT&CK: ${a.tactic}`, text: a.mitre }),
      el('span', { class: 'a-time', text: `${time(a.lastSeen)}${a.hits > 1 ? `  x${a.hits}` : ''}` })),
    el('p', { class: 'a-detail', text: a.detail }),
    el('details', {}, el('summary', { text: 'Why this matters and what to do' }),
      el('p', { text: a.explain }), el('p', {}, el('b', { text: 'Response: ' }), a.respond)))));
}

function renderChart() {
  const now = Math.floor(Date.now() / 1000);
  for (const k of buckets.keys()) if (k < now - 70) buckets.delete(k);
  let max = 4;
  for (let s = now - 59; s <= now; s++) { const b = buckets.get(s); if (b) max = Math.max(max, b.ok + b.fail + b.blk + b.conn); }
  const cols = [];
  let total = 0;
  for (let s = now - 59; s <= now; s++) {
    const b = buckets.get(s) || { ok: 0, fail: 0, blk: 0, conn: 0 };
    total += b.ok + b.fail + b.blk + b.conn;
    const seg = (n, cls) => (n ? el('span', { class: `seg ${cls}` }) : null);
    const col = el('div', { class: 'col' }, seg(b.conn, 'conn'), seg(b.blk, 'blk'), seg(b.fail, 'fail'), seg(b.ok, 'ok'));
    [...col.children].forEach((c) => { const n = b[c.classList[1]]; c.style.setProperty('--h', `${(n / max) * 100}%`); });
    cols.push(col);
  }
  const chart = $('#chart');
  chart.replaceChildren(...cols);
  chart.setAttribute('aria-label', `${total} attempts and connections in the last 60 seconds`);
}

function renderAttackers() {
  const snap = state.snapshot;
  if (!snap) return;
  const now = Date.now();
  const rows = snap.attackers.slice(0, 12).map((a) => {
    const left = a.blockedUntil ? Math.max(0, Math.ceil((a.blockedUntil - now) / 1000)) : 0;
    return el('tr', { class: left ? 'is-blocked' : '' },
      el('td', { class: 'mono', text: a.ip }),
      el('td', { text: String(a.attempts) }),
      el('td', { text: String(a.failures) }),
      el('td', { text: a.ports ? `${a.users} + ${a.ports} ports` : String(a.users) }),
      el('td', {}, left ? el('span', { class: 'status blk', text: `blocked ${left}s` }) : a.successes ? el('span', { class: 'status ok', text: 'logged in' }) : el('span', { class: 'status', text: 'watching' })));
  });
  $('#attackers tbody').replaceChildren(...(rows.length ? rows : [el('tr', {}, el('td', { colspan: '5', class: 'empty', text: 'No traffic yet.' }))]));
}

function renderAll() { renderCounters(); renderAlerts(); renderAttackers(); renderChart(); }

function flash(a) {
  if (SEVERITY_RANK[a.severity] < SEVERITY_RANK.high) return;
  document.body.classList.remove('flash');
  void document.body.offsetWidth;
  document.body.classList.add('flash');
}

// ---------- actions ----------
async function post(path, body) {
  const r = await fetch(path, { method: 'POST', headers: { 'Content-Type': 'application/json', Accept: 'application/json' }, body: JSON.stringify(body || {}) });
  return { status: r.status, data: await r.json().catch(() => ({})) };
}

async function simulate(name) {
  if (lab) lab.simulate(name);
  else await post('/api/simulate', { scenario: name });
}

async function login(user, pass) {
  if (lab) return lab.login(user, pass);
  const r = await post('/login', { username: user, password: pass });
  return { status: r.status, message: r.data.message || `HTTP ${r.status}` };
}

function wire() {
  $('#login').addEventListener('submit', async (ev) => {
    ev.preventDefault();
    const res = await login($('#user').value, $('#pass').value);
    const out = $('#login-result');
    out.className = `result s${res.status}`;
    out.textContent = res.status === 403 || res.status === 423 ? `${res.message} Press "Reset lab" to start over.` : res.message;
    $('#pass').value = '';
    $('#pass').focus();
  });
  $('#autoblock').addEventListener('change', async (e) => {
    if (lab) lab.setAutoBlock(e.target.checked);
    else await post('/api/config', { autoBlock: e.target.checked });
  });
  $('#report').addEventListener('click', async () => {
    const snap = lab ? lab.snapshot() : await (await fetch('/api/state')).json();
    const md = toMarkdown(snap, { source: lab ? 'Tripline browser demo' : `Tripline lab on ${location.host}` });
    const url = URL.createObjectURL(new Blob([md], { type: 'text/markdown' }));
    const a = el('a', { href: url, download: `tripline-incident-${new Date().toISOString().slice(0, 19).replace(/[:T]/g, '-')}.md` });
    document.body.append(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  });
  $('#reset').addEventListener('click', async () => {
    $('#login-result').textContent = '';
    if (lab) lab.reset(); else await post('/api/reset');
  });
}

// ---------- start ----------
async function connectLive() {
  try {
    const ctl = new AbortController();
    const t = setTimeout(() => ctl.abort(), 1500);
    const r = await fetch('/api/hello', { signal: ctl.signal });
    clearTimeout(t);
    if (!r.ok) return false;
    const h = await r.json();
    if (h.mode !== 'live') return false;
  } catch { return false; }
  const es = new EventSource('/events');
  for (const kind of ['hello', 'snapshot', 'event', 'alert', 'action', 'stats']) {
    es.addEventListener(kind, (m) => onMessage(kind, JSON.parse(m.data)));
  }
  es.onerror = () => { $('#mode').textContent = 'Reconnecting to the server...'; };
  // The attackers table needs per-address detail, which the stream does not carry on every event.
  setInterval(async () => { try { state.snapshot = await (await fetch('/api/state')).json(); renderAttackers(); } catch { /* server gone */ } }, 1500);
  return true;
}

async function start() {
  wire();
  if (!(await connectLive())) {
    const { createDemoLab } = await import('./demo.js');
    lab = createDemoLab(onMessage);
    onMessage('hello', lab.hello());
    onMessage('snapshot', lab.snapshot());
    setInterval(() => { state.snapshot = lab.snapshot(); renderAttackers(); }, 1000);
  }
  setInterval(renderChart, 1000);
  renderChart();
}

start();
