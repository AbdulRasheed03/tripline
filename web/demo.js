// Browser demo lab. Used when the dashboard is opened without the Node server (for example on GitHub Pages).
// Same detection engine, same accounts, same scenarios. It emits the same messages as the live server's
// event stream, so the dashboard code does not care which one it is talking to.

import { createDetector, detectInjection, VERSION } from './src/engine.js';
import { ACCOUNTS, WORDLIST, SPRAY_USERS, SPRAY_PASSWORDS, INJECTIONS } from './src/labdata.js';

const DECOYS = [
  { port: 21, service: 'FTP' }, { port: 22, service: 'SSH' }, { port: 23, service: 'Telnet' },
  { port: 3389, service: 'RDP' }, { port: 5900, service: 'VNC' },
];

// Attackers in the demo use the address ranges reserved for documentation (RFC 5737).
const SCENARIOS = {
  scan: { title: 'Port scan', steps: () => [20, 21, 22, 23, 25, 80, 443, 3389, 5900, 8080].map((port) => ({ conn: port, ip: '203.0.113.88', wait: 120 })) },
  brute: { title: 'Brute force on admin', steps: () => WORDLIST.map((p) => ({ user: 'admin', pass: p, ip: '203.0.113.66', wait: 220 })) },
  spray: { title: 'Password spray', steps: () => SPRAY_PASSWORDS.flatMap((p) => SPRAY_USERS.map((u) => ({ user: u, pass: p, ip: '198.51.100.77', wait: 200 }))) },
  distributed: { title: 'Distributed brute force on aina', steps: () => WORDLIST.slice(0, 18).map((p, i) => ({ user: 'aina', pass: p, ip: `192.0.2.${101 + (i % 6)}`, wait: 200 })) },
  injection: { title: 'Login injection', steps: () => INJECTIONS.map(([u, p]) => ({ user: u, pass: p, ip: '203.0.113.99', wait: 450 })) },
  tour: { title: 'Full tour', steps: () => ['scan', 'injection', 'brute', 'spray', 'distributed'].flatMap((n) => [...SCENARIOS[n].steps(), { pause: 1200 }]) },
};

export function createDemoLab(emit) {
  let detector = createDetector();
  let running = null;
  let timer = null;

  const hello = () => ({
    mode: 'demo', version: VERSION, accounts: Object.keys(ACCOUNTS), decoys: DECOYS,
    autoBlock: detector.config.autoBlock, scenarios: Object.keys(SCENARIOS), running,
  });

  function handle(event) {
    const res = detector.ingest(event);
    emit('event', event);
    res.alerts.forEach((a) => emit('alert', a));
    res.actions.forEach((a) => emit('action', a));
    emit('stats', detector.snapshot(Date.now()).stats);
  }

  // Mirrors the server's /login handler: blocked, then locked, then check. The password is never stored.
  function login(ip, user, pass) {
    const now = Date.now();
    const blocked = detector.isBlocked(ip, now);
    if (blocked) {
      detector.noteBlockedAttempt(ip, now);
      emit('event', { type: 'auth', ts: now, ip, user, ok: false, blocked: true, source: 'demo' });
      return { status: 403, message: `Blocked by Tripline (${blocked.reason}). Unblocks in ${Math.ceil((blocked.until - now) / 1000)}s.` };
    }
    if (detector.isLocked(user, now)) {
      emit('event', { type: 'auth', ts: now, ip, user, ok: false, locked: true, source: 'demo' });
      return { status: 423, message: `The account "${user}" is temporarily locked.` };
    }
    const injection = detectInjection(user, pass);
    const ok = !injection && Object.hasOwn(ACCOUNTS, user) && ACCOUNTS[user] === pass;
    handle({ type: 'auth', ts: now, ip, user, ok, knownUser: Object.hasOwn(ACCOUNTS, user), injection, source: 'demo' });
    return ok ? { status: 200, message: `Welcome, ${user}. You are in.` } : { status: 401, message: 'Invalid username or password.' };
  }

  function simulate(name) {
    if (!SCENARIOS[name] || running) return false;
    running = name;
    emit('hello', hello());
    const steps = SCENARIOS[name].steps();
    let i = 0;
    let blockedInARow = 0;
    const next = () => {
      if (i >= steps.length) return finish();
      const s = steps[i++];
      if (s.pause) { timer = setTimeout(next, s.pause); return; }
      if (s.conn) {
        if (!detector.isBlocked(s.ip, Date.now())) {
          const d = DECOYS.find((x) => x.port === s.conn);
          if (d) handle({ type: 'conn', ts: Date.now(), ip: s.ip, port: d.port, service: d.service });
        }
      } else {
        const r = login(s.ip, s.user, s.pass);
        if (r.status === 200 && name !== 'tour') return finish();
        blockedInARow = r.status === 403 || r.status === 423 ? blockedInARow + 1 : 0;
        // Like a real attacker, give up after being turned away a few times (skip to the next stage in the tour).
        if (blockedInARow >= 3) {
          blockedInARow = 0;
          if (name !== 'tour') return finish();
          while (i < steps.length && !steps[i].pause) i++;
        }
      }
      timer = setTimeout(next, s.wait);
    };
    next();
    return true;
  }

  function finish() {
    clearTimeout(timer);
    running = null;
    emit('hello', hello());
  }

  return {
    hello,
    snapshot: () => detector.snapshot(Date.now()),
    login: (user, pass) => login('you', user, pass),
    simulate,
    stop: finish,
    reset() {
      finish();
      detector = createDetector({ autoBlock: detector.config.autoBlock });
      emit('snapshot', detector.snapshot(Date.now()));
    },
    setAutoBlock(v) { detector.config.autoBlock = !!v; emit('hello', hello()); },
  };
}
