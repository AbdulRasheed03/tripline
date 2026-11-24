#!/usr/bin/env node
// Tripline command line.
//   tripline serve   [--port 3000] [--no-block] [--watch /var/log/auth.log]   live lab + dashboard
//   tripline attack  <scenario> [--port 3000] [--speed 2]                       attack your own lab
//   tripline replay  <logfile> [--year 2026] [--json | --md]                    analyze a saved log (SSH or web)
//   tripline watch   <logfile>                                                  alert on a live log in the terminal

import { readFile, open, stat } from 'node:fs/promises';
import { watchFile } from 'node:fs';
import { createDetector, SEVERITY_RANK, fmtSpan } from '../src/engine.js';
import { parseLine, parseLog } from '../src/parsers.js';
import { toMarkdown } from '../src/report.js';
import { createLab } from '../server/lab.mjs';
import { runScenario, SCENARIOS } from '../server/attacks.mjs';

const argv = process.argv.slice(2);
const cmd = argv[0] && !argv[0].startsWith('-') ? argv.shift() : 'serve';
const flag = (name) => argv.includes(`--${name}`);
const opt = (name, def) => { const i = argv.indexOf(`--${name}`); return i >= 0 && argv[i + 1] ? argv[i + 1] : def; };
const VALUE_FLAGS = new Set(['port', 'host', 'watch', 'year', 'speed']);
const positional = [];
for (let i = 0; i < argv.length; i++) {
  if (argv[i].startsWith('--')) { if (VALUE_FLAGS.has(argv[i].slice(2))) i++; continue; }
  positional.push(argv[i]);
}

const useColor = process.stdout.isTTY && !flag('no-color');
const C = (code) => (s) => (useColor ? `\x1b[${code}m${s}\x1b[0m` : String(s));
const paint = { critical: C('41;97'), high: C('31;1'), medium: C('33'), low: C('36'), dim: C('2'), bold: C('1') };

function printAlert(a) {
  const when = new Date(a.lastSeen).toLocaleTimeString();
  console.log(`${paint.dim(when)} ${paint[a.severity](` ${a.severity.toUpperCase()} `)} ${paint.bold(a.title)}  ${paint.dim(a.mitre)}`);
  console.log(`           ${a.detail}`);
}

async function serve() {
  const port = Number(opt('port', process.env.PORT || 3000));
  const host = opt('host', '127.0.0.1');
  const lab = createLab({ port, host, detector: { autoBlock: !flag('no-block') } });
  const info = await lab.start();
  if (host !== '127.0.0.1' && host !== 'localhost') {
    console.log(paint.high(`\n  Warning: listening on ${host}. The portal has weak demo passwords on purpose. Only do this on an isolated lab network.\n`));
  }
  console.log(`
  ${paint.bold('Tripline')} is watching.

  Dashboard   ${info.url}
  Target      ${info.url}/portal   (accounts: admin, aina, farid, mei, raj, siti)
  Decoys      ${info.decoys.map((d) => `${d.service} ${d.port}`).join(', ') || 'none'}
  Auto-block  ${flag('no-block') ? 'off (attacks can succeed)' : 'on'}

  Attack it from another terminal:
    node cli/tripline.mjs attack brute            ${paint.dim('# or: scan, spray, distributed, injection, slow, tour')}
    hydra -l admin -P wordlist.txt -s ${info.port} 127.0.0.1 http-post-form "/login:username=^USER^&password=^PASS^:F=Invalid"
    nmap -sT -p 2000-10000 127.0.0.1
`);
  const logFile = opt('watch');
  if (logFile) tail(logFile, (e) => lab.handle(e));
  const shut = async () => { await lab.stop(); process.exit(0); };
  process.on('SIGINT', shut);
  process.on('SIGTERM', shut);
}

async function attack() {
  const name = positional[0];
  if (!name || !SCENARIOS[name]) {
    console.log('Scenarios:');
    for (const [k, s] of Object.entries(SCENARIOS)) console.log(`  ${k.padEnd(12)} ${s.title}${s.mitre ? ` (${s.mitre})` : ''}\n               ${paint.dim(s.about)}`);
    process.exit(name ? 1 : 0);
  }
  const port = Number(opt('port', 3000));
  console.log(`${paint.bold(SCENARIOS[name].title)} against 127.0.0.1:${port}\n${paint.dim(SCENARIOS[name].about)}\n`);
  try {
    await runScenario(name, { port, speed: Number(opt('speed', 1)) });
  } catch (e) {
    console.error(paint.high(e.code === 'ECONNREFUSED' ? `Nothing is listening on port ${port}. Start the lab first: node cli/tripline.mjs serve` : e.message));
    process.exit(1);
  }
}

async function replay() {
  const file = positional[0];
  if (!file) { console.error('Usage: tripline replay <logfile> [--year 2026] [--json]'); process.exit(1); }
  const events = parseLog(await readFile(file, 'utf8'), { year: Number(opt('year', new Date().getFullYear())) }).sort((a, b) => a.ts - b.ts);
  const det = createDetector({ autoBlock: !flag('no-block') });
  const raised = new Set();
  for (const e of events) for (const a of det.ingest(e).alerts) raised.add(a);
  const alerts = [...raised];
  if (flag('json')) {
    console.log(JSON.stringify({ events: events.length, alerts }, null, 2));
  } else if (flag('md')) {
    console.log(toMarkdown(det.snapshot(events.at(-1)?.ts || 0), { source: file }));
  } else {
    const span = events.length ? fmtSpan(events.at(-1).ts - events[0].ts) : '0s';
    const kinds = [['auth', 'login'], ['http', 'web request'], ['conn', 'connection']]
      .map(([t, label]) => [events.filter((e) => e.type === t).length, label]).filter(([n]) => n).map(([n, l]) => `${n} ${l}${n === 1 ? '' : 's'}`).join(', ');
    console.log(`${paint.bold(file)}: ${kinds || '0 events'} over ${span}, ${alerts.length} alert(s)\n`);
    alerts.forEach(printAlert);
    const snap = det.snapshot(events.at(-1)?.ts || 0);
    const flagged = snap.attackers.filter((a) => a.alerts > 0);
    if (flagged.length) {
      console.log(`\n${paint.bold('Sources that raised alerts')}`);
      for (const a of flagged.slice(0, 10)) {
        const web = a.requests ? `  ${String(a.requests).padStart(5)} web requests` : '';
        console.log(`  ${a.ip.padEnd(16)} ${String(a.failures).padStart(5)} failed  ${String(a.successes).padStart(3)} ok  ${String(a.users).padStart(3)} accounts${web}`);
      }
    }
  }
  // Exit code 2 when anything high or critical was found, so scripts and cron jobs can react.
  process.exit(alerts.some((a) => SEVERITY_RANK[a.severity] >= SEVERITY_RANK.high) ? 2 : 0);
}

function tail(file, onEvent) {
  let pos = 0;
  let buf = '';
  let busy = false;
  const year = Number(opt('year', new Date().getFullYear()));
  const pump = async () => {
    if (busy) return;
    busy = true;
    try {
      const { size } = await stat(file);
      if (size < pos) pos = 0; // rotated or truncated
      if (size > pos) {
        const fh = await open(file, 'r');
        const chunk = Buffer.alloc(size - pos);
        await fh.read(chunk, 0, chunk.length, pos);
        await fh.close();
        pos = size;
        buf += chunk.toString('utf8');
        const lines = buf.split(/\r?\n/);
        buf = lines.pop();
        for (const l of lines) { const e = parseLine(l, { year }); if (e) onEvent(e.source === 'ssh' ? { ...e, ts: Date.now() } : e); }
      }
    } catch (e) {
      if (e.code !== 'ENOENT') console.error(e.message);
    } finally { busy = false; }
  };
  // Start at the end of the file: only new lines matter in live mode.
  stat(file).then((s) => { pos = s.size; }).catch(() => {}).finally(() => watchFile(file, { interval: 1000 }, pump));
  console.log(`Watching ${file} for SSH logins...`);
}

async function watch() {
  const file = positional[0];
  if (!file) { console.error('Usage: tripline watch <logfile>'); process.exit(1); }
  const det = createDetector({ autoBlock: false });
  tail(file, (e) => { for (const a of det.ingest(e).alerts) if (!a.updated) printAlert(a); });
}

const COMMANDS = { serve, attack, replay, watch };
if (!COMMANDS[cmd]) { console.error(`Unknown command "${cmd}". Use: serve, attack, replay, watch`); process.exit(1); }
COMMANDS[cmd]();
