// Attack simulator for the Tripline lab. It only ever targets this machine.
// Each scenario plays a real attack pattern against the local portal or decoy ports,
// using separate loopback source addresses (127.0.0.x) so it looks like separate attackers.

import { request } from 'node:http';
import { connect } from 'node:net';
import { WORDLIST, SPRAY_USERS, SPRAY_PASSWORDS, INJECTIONS } from '../src/labdata.js';

export { WORDLIST };
const LOOPBACK = /^(localhost|127\.\d{1,3}\.\d{1,3}\.\d{1,3}|::1|\[::1\])$/i;

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
let headerFallback = false; // set when the OS cannot bind 127.0.0.x (macOS)

export function assertLoopback(host) {
  if (!LOOPBACK.test(String(host))) {
    throw new Error(`Refusing to attack "${host}". The simulator only targets this machine (localhost / 127.0.0.x). Attack only systems you own or are allowed to test.`);
  }
}

function attempt(ctx, user, pass, src) {
  const body = JSON.stringify({ username: user, password: pass });
  const options = {
    host: ctx.host, port: ctx.port, path: '/login', method: 'POST',
    headers: { 'Content-Type': 'application/json', Accept: 'application/json', 'Content-Length': Buffer.byteLength(body), 'User-Agent': 'tripline-attack-sim/1.0' },
  };
  if (src && headerFallback) options.headers['X-Tripline-Lab-Source'] = src;
  else if (src) options.localAddress = src;
  return new Promise((resolveP, reject) => {
    const req = request(options, (res) => { res.resume(); res.on('end', () => resolveP(res.statusCode)); });
    req.on('error', (e) => {
      if (e.code === 'EADDRNOTAVAIL' && src && !headerFallback) { headerFallback = true; attempt(ctx, user, pass, src).then(resolveP, reject); return; }
      reject(e);
    });
    req.end(body);
  });
}

function knock(ctx, port, src) {
  return new Promise((resolveP) => {
    const opts = { host: ctx.host, port };
    if (src && !headerFallback) opts.localAddress = src;
    const s = connect(opts);
    const done = (open) => { s.destroy(); resolveP(open); };
    s.setTimeout(800, () => done(false));
    s.on('connect', () => setTimeout(() => done(true), 50));
    s.on('error', () => done(false));
  });
}

const label = { 200: 'SUCCESS', 401: 'fail', 403: 'BLOCKED', 423: 'LOCKED', 429: 'throttled' };

async function guessLoop(ctx, tries, delay) {
  let blockedInARow = 0;
  for (const [user, pass, src] of tries) {
    const code = await attempt(ctx, user, pass, src);
    ctx.say(`  ${src.padEnd(12)} ${user.padEnd(12)} ${pass.padEnd(16)} -> ${code} ${label[code] || ''}`);
    if (code === 200) { ctx.say(`  !! "${user}" cracked from ${src}. Check the dashboard for the critical alert.`); return 'cracked'; }
    if (code === 403 || code === 423) { if (++blockedInARow >= 3) { ctx.say('  Stopped: Tripline is blocking this attacker.'); return 'blocked'; } }
    else blockedInARow = 0;
    await sleep(delay / ctx.speed);
  }
  return 'finished';
}

export const SCENARIOS = {
  scan: {
    title: 'Port scan', mitre: 'T1046',
    about: 'Connects to a range of ports, including the decoys, from 127.0.0.88.',
    async run(ctx) {
      const ports = [...new Set([2020, 2100, ...ctx.decoyPorts, 3333, 4444, 8888])].sort((a, b) => a - b);
      for (const p of ports) {
        const open = await knock(ctx, p, '127.0.0.88');
        ctx.say(`  127.0.0.88   port ${String(p).padEnd(6)} ${open ? 'open' : 'closed'}`);
        await sleep(80 / ctx.speed);
      }
    },
  },
  brute: {
    title: 'Brute force on "admin"', mitre: 'T1110.001',
    about: 'Tries the top 20 leaked passwords against admin from 127.0.0.66. Turn auto-block off to watch it win.',
    run: (ctx) => guessLoop(ctx, WORDLIST.map((p) => ['admin', p, '127.0.0.66']), 150),
  },
  spray: {
    title: 'Password spray', mitre: 'T1110.003',
    about: 'Tries three seasonal passwords against ten accounts from 127.0.0.77.',
    run: (ctx) => guessLoop(ctx, SPRAY_PASSWORDS.flatMap((p) => SPRAY_USERS.map((u) => [u, p, '127.0.0.77'])), 150),
  },
  distributed: {
    title: 'Distributed brute force on "aina"', mitre: 'T1110',
    about: 'Six addresses (127.0.0.101 to .106) take turns guessing one account, three tries each.',
    run: (ctx) => guessLoop(ctx, WORDLIST.slice(0, 18).map((p, i) => ['aina', p, `127.0.0.${101 + (i % 6)}`]), 150),
  },
  injection: {
    title: 'SQL and script injection in the login form', mitre: 'T1190',
    about: 'Sends classic login-bypass payloads from 127.0.0.99.',
    run: (ctx) => guessLoop(ctx, INJECTIONS.map(([u, p]) => [u, p, '127.0.0.99']), 300),
  },
  slow: {
    title: 'Low and slow brute force', mitre: 'T1110.001',
    about: 'One guess every 9 seconds from 127.0.0.44, staying under the per-minute rule. Takes about 3 minutes.',
    run: (ctx) => guessLoop(ctx, [...WORDLIST.slice(0, 15), ...WORDLIST.slice(0, 6)].map((p) => ['mei', p, '127.0.0.44']), 9000),
  },
  tour: {
    title: 'Full tour', mitre: '',
    about: 'Scan, injection, brute force, spray and distributed attack, one after another.',
    async run(ctx) {
      for (const name of ['scan', 'injection', 'brute', 'spray', 'distributed']) {
        ctx.say(`\n== ${SCENARIOS[name].title} ==`);
        await SCENARIOS[name].run(ctx);
        await sleep(1200 / ctx.speed);
      }
    },
  },
};

export async function runScenario(name, opts = {}) {
  const sc = SCENARIOS[name];
  if (!sc) throw new Error(`Unknown scenario "${name}". Try: ${Object.keys(SCENARIOS).join(', ')}`);
  const ctx = {
    host: opts.host || '127.0.0.1', port: opts.port || 3000, decoyPorts: opts.decoyPorts || [2121, 2222, 2323, 5901, 9201],
    speed: opts.speed || 1, say: opts.quiet ? () => {} : (opts.say || console.log),
  };
  assertLoopback(ctx.host);
  return sc.run(ctx);
}
