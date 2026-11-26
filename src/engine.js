// Tripline detection engine.
// Pure logic: events go in, alerts and response actions come out. No timers, no I/O, no Node APIs,
// so the exact same code runs in the live server, the log watcher, the browser demo and the tests.
// Time always comes from event.ts (milliseconds), which makes every rule replayable and testable.
//
// Event shapes:
//   { type: 'auth', ts, ip, user, ok, knownUser?, injection?, source? }
//   { type: 'conn', ts, ip, port, service? }
//   { type: 'http', ts, ip, method, path, status, ua? }        (web server access logs)
//   { type: 'lockout', ts, user, host? }                       (Windows event 4740: the OS locked an account)
// Passwords are never part of an event. Callers only pass the *name* of an injection pattern if one was seen.

export const VERSION = '1.3.0';

export const DEFAULTS = {
  bruteForce: { failures: 8, windowMs: 60_000 },          // one IP, one account, fast
  spray: { users: 5, maxPerUser: 3, windowMs: 300_000 },  // one IP, many accounts, few tries each
  distributed: { failures: 12, ips: 4, windowMs: 300_000 }, // many IPs, one account
  slow: { failures: 20, windowMs: 3_600_000 },             // one IP, under the fast threshold, over an hour
  compromise: { failures: 5, windowMs: 600_000 },          // a success right after many failures
  scan: { ports: 4, windowMs: 60_000 },                    // one IP touching several decoy ports
  web: { notFound: 20, windowMs: 60_000 },                 // one IP collecting 404s: guessing paths
  webLogin: { posts: 10, windowMs: 60_000 },               // one IP posting to a login page again and again
  autoBlock: true,
  blockMs: 300_000,
  lockMs: 300_000,
  cooldownMs: 60_000, // repeat hits of the same alert inside this time update it instead of creating a new one
};

export const RULES = {
  'brute-force': {
    title: 'Brute force against one account', severity: 'high', mitre: 'T1110.001', tactic: 'Credential Access',
    explain: 'One address is guessing passwords for the same account, fast. Real users mistype a few times, not dozens.',
    respond: 'Block the address, check whether any attempt succeeded, and make sure the account has MFA.',
  },
  'password-spray': {
    title: 'Password spraying across many accounts', severity: 'high', mitre: 'T1110.003', tactic: 'Credential Access',
    explain: 'One address is trying a few common passwords against many different accounts, staying under per-account lockout limits.',
    respond: 'Block the address, find every account it tried, and force a password reset on any that later logged in.',
  },
  'distributed-brute-force': {
    title: 'Distributed brute force on one account', severity: 'high', mitre: 'T1110', tactic: 'Credential Access',
    explain: 'Several addresses are guessing the same account. Blocking one address does not help, so the account is locked instead.',
    respond: 'Keep the temporary lock, contact the account owner, and look for the same addresses in other logs.',
  },
  'slow-brute-force': {
    title: 'Low and slow brute force', severity: 'medium', mitre: 'T1110.001', tactic: 'Credential Access',
    explain: 'Failures are spread out to stay under the per-minute threshold, but over an hour they add up.',
    respond: 'Treat it like a normal brute force. Slow attacks are deliberate, not accidents.',
  },
  'compromise-suspected': {
    title: 'Successful login after many failures', severity: 'critical', mitre: 'T1078', tactic: 'Initial Access',
    explain: 'An address that failed many times just logged in. The attacker probably found the password.',
    respond: 'Disable the session and the account now, reset the password, and review everything the account did.',
  },
  'login-injection': {
    title: 'Injection attempt in the login form', severity: 'high', mitre: 'T1190', tactic: 'Initial Access',
    explain: 'The username or password field contained SQL or script syntax. Someone is testing the form for a bypass.',
    respond: 'Block the address and confirm the login code uses parameterised queries and output encoding.',
  },
  'port-scan': {
    title: 'Port scan hit the decoy services', severity: 'medium', mitre: 'T1046', tactic: 'Discovery',
    explain: 'One address connected to several decoy ports that no real user has any reason to touch.',
    respond: 'Block the address and expect follow-up attacks on whatever real services it found.',
  },
  'web-scanner': {
    title: 'Vulnerability scanner hitting the web server', severity: 'medium', mitre: 'T1595.002', tactic: 'Reconnaissance',
    explain: 'The User-Agent belongs to an automated attack or scanning tool (for example sqlmap, Nikto or Nuclei). Someone is mapping weaknesses.',
    respond: 'Block the address and check what the scanner found: look for 200 responses to unusual paths in the same window.',
  },
  'web-dir-bruteforce': {
    title: 'Directory brute forcing', severity: 'medium', mitre: 'T1595.003', tactic: 'Reconnaissance',
    explain: 'One address is requesting many pages that do not exist. That is a wordlist tool guessing hidden admin panels, backups and APIs.',
    respond: 'Block the address and review any paths in the burst that returned 200, 301 or 403. Those are the ones it found.',
  },
  'web-login-bruteforce': {
    title: 'Brute force against a web login page', severity: 'high', mitre: 'T1110', tactic: 'Credential Access',
    explain: 'One address is submitting a login form over and over. A person who forgot their password tries a few times, not ten in a minute. Access logs do not show the username, so this could be one account or many (spraying or credential stuffing).',
    respond: 'Block the address and check the application log for the accounts it tried. Any 302 or 303 answer in the burst may be a login that worked, so look at that session first.',
  },
  'web-injection': {
    title: 'Injection or traversal attempt in a URL', severity: 'high', mitre: 'T1190', tactic: 'Initial Access',
    explain: 'The request path or query string contains SQL, script, template or path traversal syntax. Someone is trying to break the application.',
    respond: 'Block the address, then check the application log for the same request. A 200 or 500 response deserves a closer look.',
  },
  'web-sensitive-probe': {
    title: 'Probe for secrets or admin files', severity: 'medium', mitre: 'T1083', tactic: 'Discovery',
    explain: 'The address asked for files that should never be public, such as .env, .git/config or database dumps. These leak passwords and keys when they exist.',
    respond: 'Make sure none of the probed files returned 200. If one did, rotate every secret it contained.',
  },
  'web-secret-exposed': {
    title: 'Secret or admin file was served', severity: 'critical', mitre: 'T1552.001', tactic: 'Credential Access',
    explain: 'A file that should never be public (such as .env or .git/config) was returned with a success status. Anything inside it is now in the attacker\'s hands.',
    respond: 'Remove the file from the web root now, rotate every password, key and token it contained, and check the logs for other addresses that fetched it.',
  },
  'account-lockout': {
    title: 'Windows locked an account', severity: 'medium', mitre: 'T1110', tactic: 'Credential Access',
    explain: 'Windows locked the account after too many wrong passwords (event 4740). One lockout can be a user who forgot a changed password. Several, or one right after a burst of failures, is someone guessing.',
    respond: 'Check the caller computer and the failed logons (4625) just before it. Unlock only after you know who was guessing, or the attacker gets a fresh set of tries.',
  },
  'honeypot-touch': {
    title: 'Connection to a decoy service', severity: 'low', mitre: 'T1046', tactic: 'Discovery',
    explain: 'Nothing legitimate runs on this port, so any connection is reconnaissance or a mistake.',
    respond: 'Note the address. On its own it is weak, but it often comes right before an attack.',
  },
};

export const SEVERITY_RANK = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };

// Injection patterns checked on the raw form fields by the caller. Returns a label or null.
const INJECTION = [
  // A quote has to close the string first. That keeps ordinary passwords such as "Kopi2026#" out of it.
  [/['"]\s*(or|and)\b\s*['"]?\w*['"]?\s*(=|like\b)\s*['"]?\w*/i, 'SQL tautology'],
  // Whitespace or an inline comment between the words, so a slug like /blog/union-select-guide is not flagged.
  [/\bunion(\s|\/\*.*?\*\/)+(all(\s|\/\*.*?\*\/)+)?select\b/i, 'SQL UNION'],
  [/['"]\s*(--|#|\/\*)/, 'SQL comment terminator'],
  [/;\s*(drop|delete|insert|update|exec|shutdown)\b/i, 'Stacked SQL query'],
  [/\b(sleep|benchmark|pg_sleep|waitfor\s+delay)\s*\(/i, 'Time-based SQL'],
  [/<\s*script|on(error|load|mouseover)\s*=|javascript:/i, 'Script injection'],
  [/\$\{jndi:|\{\{.*\}\}|\$\{.*\}/i, 'Template or JNDI injection'],
  [/\$where|\{\s*"\$(ne|gt|regex)"/i, 'NoSQL operator'],
  [/(\.\.\/){2,}|\.\.\\|\/etc\/(passwd|shadow)\b|\bwin\.ini\b/i, 'Path traversal'],
  [/[;|`]\s*(cat|id|whoami|wget|curl|nc|bash|sh|powershell)\b|\$\((id|whoami|cat)\b/i, 'Command injection'],
];

const SCANNER_UA = /\b(sqlmap|nikto|nmap|masscan|nuclei|zgrab|gobuster|dirbuster|dirb|ffuf|feroxbuster|wpscan|acunetix|nessus|openvas|wfuzz|hydra|whatweb|jaeles|xray|commix|arachni|w3af|skipfish|zmeu)\b/i;
// Login endpoints, matched on the whole last path segment so /blog/how-to-login-safely is not one.
// /oauth/token is left out on purpose: service clients refresh tokens there all day.
const LOGIN_PATH = /(^|\/)(wp-login\.php|xmlrpc\.php|login|log-in|logon|signin|sign-in|sign_in|auth|authenticate|session|sessions|j_security_check|login\.(php|aspx?|jsp|html?|do|action)|administrator\/index\.php)\/?$/i;
const SENSITIVE_PATH = /(^|\/)(\.env(\.\w+)?|\.git\/(config|HEAD)|\.svn\/|\.aws\/credentials|\.ssh\/|id_rsa|wp-config\.php(\.bak|~|\.old)?|config\.php\.bak|database\.sql|dump\.sql|backup\.(zip|tar\.gz|sql)|\.htpasswd|server-status|phpinfo\.php|phpmyadmin\/?|actuator\/(env|heapdump)|web\.config)$/i;

function decodeSafe(s) {
  let out = String(s ?? '');
  for (let i = 0; i < 2; i++) { try { const d = decodeURIComponent(out.replace(/\+/g, ' ')); if (d === out) break; out = d; } catch { break; } }
  return out;
}

export function detectInjection(...fields) {
  for (const f of fields) {
    const s = String(f ?? '');
    if (!s) continue;
    for (const [re, label] of INJECTION) if (re.test(s)) return label;
  }
  return null;
}

export function createDetector(options = {}) {
  const cfg = mergeConfig(DEFAULTS, options);
  const failsByIp = new Map();   // ip -> [{ ts, user }]
  const failsByUser = new Map(); // user -> [{ ts, ip }]
  const portsByIp = new Map();   // ip -> [{ ts, port }]
  const missesByIp = new Map();  // ip -> [{ ts, path }]  (404s)
  const loginPostsByIp = new Map(); // ip -> [{ ts, path, status }]  (POSTs to login pages)
  const blocked = new Map();     // ip -> { until, reason }
  const locked = new Map();      // user -> { until, reason }
  const open = new Map();        // dedupe key -> alert
  const alerts = [];             // every alert, oldest first
  const stats = { events: 0, auth: 0, failures: 0, successes: 0, conns: 0, alerts: 0, blockedAttempts: 0 };
  const ipStats = new Map();     // ip -> { attempts, failures, successes, users:Set, ports:Set, firstSeen, lastSeen }
  let seq = 0;
  let lastTs = 0;

  const longest = Math.max(cfg.bruteForce.windowMs, cfg.spray.windowMs, cfg.distributed.windowMs, cfg.slow.windowMs, cfg.compromise.windowMs, cfg.scan.windowMs, cfg.web.windowMs, cfg.webLogin.windowMs);

  function push(map, key, item, now) {
    let arr = map.get(key);
    if (!arr) { arr = []; map.set(key, arr); }
    arr.push(item);
    while (arr.length && arr[0].ts < now - longest) arr.shift();
    return arr;
  }
  const within = (arr, now, windowMs) => (arr || []).filter((x) => x.ts >= now - windowMs);

  function touchIp(ip, now) {
    let s = ipStats.get(ip);
    if (!s) { s = { ip, attempts: 0, failures: 0, successes: 0, users: new Set(), ports: new Set(), firstSeen: now, lastSeen: now, alerts: 0 }; ipStats.set(ip, s); }
    s.lastSeen = now;
    return s;
  }

  // How long an alert stays open and absorbs repeat hits. Slow rules need their whole window,
  // otherwise a guess every few minutes would raise a fresh alert each time (alert fatigue).
  const openFor = (rule) => ({
    'slow-brute-force': cfg.slow.windowMs,
    'distributed-brute-force': cfg.distributed.windowMs,
    'password-spray': cfg.spray.windowMs,
  }[rule] ?? cfg.cooldownMs);

  function raise(rule, key, now, fields) {
    const meta = RULES[rule];
    const dedupe = `${rule}|${key}`;
    const prev = open.get(dedupe);
    if (prev && now - prev.lastSeen <= openFor(rule)) {
      prev.lastSeen = now;
      prev.hits++;
      Object.assign(prev, fields, { updated: true });
      return { alert: prev, isNew: false };
    }
    const alert = {
      id: `A${String(++seq).padStart(4, '0')}`,
      rule, key, ...meta, firstSeen: now, lastSeen: now, hits: 1, updated: false, ...fields,
    };
    open.set(dedupe, alert);
    alerts.push(alert);
    stats.alerts++;
    if (fields.ip && ipStats.has(fields.ip)) ipStats.get(fields.ip).alerts++;
    return { alert, isNew: true };
  }

  function block(ip, now, reason, actions) {
    if (!cfg.autoBlock || !ip) return;
    const cur = blocked.get(ip);
    if (cur && cur.until > now) return;
    const until = now + cfg.blockMs;
    blocked.set(ip, { until, reason });
    actions.push({ type: 'block', ip, until, reason });
  }

  function lock(user, now, reason, actions) {
    if (!cfg.autoBlock || !user) return;
    const cur = locked.get(user);
    if (cur && cur.until > now) return;
    const until = now + cfg.lockMs;
    locked.set(user, { until, reason });
    actions.push({ type: 'lock', user, until, reason });
  }

  function ingest(event) {
    const now = Number(event.ts) || lastTs || 0;
    lastTs = Math.max(lastTs, now);
    stats.events++;
    const out = { alerts: [], actions: [] };
    const emit = (r) => { if (r) out.alerts.push(r.alert); };

    if (event.type === 'auth') ingestAuth(event, now, out, emit);
    else if (event.type === 'conn') ingestConn(event, now, out, emit);
    else if (event.type === 'http') ingestHttp(event, now, out, emit);
    else if (event.type === 'lockout') ingestLockout(event, now, out, emit);
    return out;
  }

  function ingestHttp(e, now, out, emit) {
    const ip = e.ip || 'unknown';
    const s = touchIp(ip, now);
    stats.http = (stats.http || 0) + 1;
    s.requests = (s.requests || 0) + 1;
    const path = String(e.path || '/').slice(0, 2048);
    const decoded = decodeSafe(path);
    const status = Number(e.status) || 0;
    const shown = `${e.method || 'GET'} ${path.length > 120 ? path.slice(0, 120) + '...' : path} -> ${status}`;

    if (e.ua && SCANNER_UA.test(e.ua)) {
      const tool = SCANNER_UA.exec(e.ua)[1];
      emit(raise('web-scanner', ip, now, { ip, count: s.requests, tool, detail: `${ip} is using ${tool} (User-Agent: ${String(e.ua).slice(0, 80)})`, evidence: shown }));
      block(ip, now, 'web-scanner', out.actions);
    }

    const injection = detectInjection(decoded);
    if (injection) {
      emit(raise('web-injection', ip, now, { ip, count: s.requests, pattern: injection, status, detail: `${injection} in a request from ${ip} (answered ${status})`, evidence: shown }));
      block(ip, now, 'web-injection', out.actions);
    }

    const bare = decoded.split(/[?#]/)[0];
    if (SENSITIVE_PATH.test(bare)) {
      // A probe is reconnaissance. A probe that got a 2xx answer is a leak, and gets its own critical alert
      // per file, so a later 404 from the same address can never overwrite it.
      if (status >= 200 && status < 300) {
        emit(raise('web-secret-exposed', `${ip}|${bare}`, now, { ip, status, path: bare, count: 1, detail: `${bare} was served to ${ip} (status ${status}). Treat its contents as leaked.`, evidence: shown }));
      }
      const probe = raise('web-sensitive-probe', ip, now, { ip, count: s.requests, detail: `${ip} probed for secret or admin files, latest ${bare} (status ${status})`, evidence: shown });
      probe.alert.paths = [...new Set([...(probe.alert.paths || []), bare])].slice(-12);
      probe.alert.detail = `${ip} probed ${probe.alert.paths.length} secret or admin file(s): ${probe.alert.paths.join(', ')}`;
      emit(probe);
    }

    // Web login brute force. Counted on every status: WordPress answers a wrong password with 200,
    // other apps with 401, 403, 429 or a redirect back to the form. Ten submissions a minute is not a typo.
    if (String(e.method || '').toUpperCase() === 'POST' && LOGIN_PATH.test(bare)) {
      const arr = push(loginPostsByIp, ip, { ts: now, path: bare, status }, now);
      const burst = within(arr, now, cfg.webLogin.windowMs);
      if (burst.length >= cfg.webLogin.posts) {
        const byStatus = new Map();
        burst.forEach((b) => byStatus.set(b.status, (byStatus.get(b.status) || 0) + 1));
        const statuses = [...byStatus.entries()].sort((a, b) => b[1] - a[1]).map(([st, n]) => `${st} x${n}`).join(', ');
        // Some apps redirect every failure back to the form. A redirect only stands out when the other answers were not redirects.
        const redirects = burst.filter((b) => b.status === 302 || b.status === 303).length;
        const oddRedirects = redirects > 0 && redirects < burst.length ? redirects : 0;
        const paths = [...new Set(burst.map((b) => b.path))];
        emit(raise('web-login-bruteforce', ip, now, {
          ip, count: burst.length, paths: paths.slice(0, 8),
          detail: `${burst.length} login submissions to ${paths.slice(0, 3).join(', ')}${paths.length > 3 ? ', ...' : ''} from ${ip} in ${fmtSpan(now - burst[0].ts)}${oddRedirects ? `. ${oddRedirects} answered with a redirect, which may be a login that worked` : ''}`,
          evidence: `answers: ${statuses}`,
        }));
        block(ip, now, 'web-login-bruteforce', out.actions);
      }
    }

    if (status === 404) {
      const arr = push(missesByIp, ip, { ts: now, path: bare }, now);
      const burst = within(arr, now, cfg.web.windowMs);
      if (burst.length >= cfg.web.notFound) {
        emit(raise('web-dir-bruteforce', ip, now, {
          ip, count: burst.length, detail: `${burst.length} requests for missing pages from ${ip} in ${fmtSpan(now - burst[0].ts)}`,
          evidence: `e.g. ${[...new Set(burst.slice(-5).map((b) => b.path))].join(', ')}`,
        }));
        block(ip, now, 'web-dir-bruteforce', out.actions);
      }
    }
  }

  function ingestAuth(e, now, out, emit) {
    const ip = e.ip || 'unknown';
    const user = String(e.user ?? '').slice(0, 128);
    const s = touchIp(ip, now);
    stats.auth++;
    s.attempts++;
    if (user) s.users.add(user);

    if (e.injection) {
      emit(raise('login-injection', ip, now, { ip, user, count: s.attempts, detail: `${e.injection} pattern in the login form from ${ip}`, evidence: `user="${user}" pattern=${e.injection}` }));
      block(ip, now, 'login-injection', out.actions);
    }

    if (e.ok) {
      stats.successes++;
      s.successes++;
      const ipFails = within(failsByIp.get(ip), now, cfg.compromise.windowMs);
      const userFails = within(failsByUser.get(user), now, cfg.compromise.windowMs);
      if (ipFails.length >= cfg.compromise.failures || userFails.length >= cfg.compromise.failures * 2) {
        const fromIps = new Set(userFails.map((f) => f.ip)).size;
        emit(raise('compromise-suspected', `${ip}|${user}`, now, {
          ip, user, count: Math.max(ipFails.length, userFails.length),
          detail: `"${user}" logged in from ${ip} after ${ipFails.length} failures from that address${fromIps > 1 ? ` and ${userFails.length} failures from ${fromIps} addresses` : ''}`,
          evidence: `success for ${user} from ${ip}`,
        }));
        block(ip, now, 'compromise-suspected', out.actions);
        lock(user, now, 'compromise-suspected', out.actions);
      }
      return;
    }

    stats.failures++;
    s.failures++;
    const ipArr = push(failsByIp, ip, { ts: now, user }, now);
    const userArr = push(failsByUser, user, { ts: now, ip }, now);

    // Brute force: same IP, same account, fast.
    const burst = within(ipArr, now, cfg.bruteForce.windowMs).filter((f) => f.user === user);
    let fastFired = false;
    if (burst.length >= cfg.bruteForce.failures) {
      fastFired = true;
      emit(raise('brute-force', `${ip}|${user}`, now, {
        ip, user, count: burst.length,
        detail: `${burst.length} failed logins for "${user}" from ${ip} in ${Math.round(cfg.bruteForce.windowMs / 1000)}s`,
        evidence: `${burst.length} failures in ${fmtSpan(now - burst[0].ts)}`,
      }));
      block(ip, now, 'brute-force', out.actions);
    }

    // Password spraying: same IP, many accounts, few tries each.
    const sprayWin = within(ipArr, now, cfg.spray.windowMs);
    const perUser = new Map();
    sprayWin.forEach((f) => perUser.set(f.user, (perUser.get(f.user) || 0) + 1));
    const maxPerUser = Math.max(0, ...perUser.values());
    if (perUser.size >= cfg.spray.users && maxPerUser <= cfg.spray.maxPerUser) {
      fastFired = true;
      const users = [...perUser.keys()];
      emit(raise('password-spray', ip, now, {
        ip, user: users.slice(-1)[0], count: sprayWin.length, users: users.length,
        detail: `${ip} tried ${users.length} different accounts (${maxPerUser} or fewer attempts each)`,
        evidence: `accounts: ${users.slice(0, 8).join(', ')}${users.length > 8 ? ', ...' : ''}`,
      }));
      block(ip, now, 'password-spray', out.actions);
    }

    // Distributed brute force: same account, many IPs.
    const distWin = within(userArr, now, cfg.distributed.windowMs);
    const ips = new Set(distWin.map((f) => f.ip));
    if (user && distWin.length >= cfg.distributed.failures && ips.size >= cfg.distributed.ips) {
      emit(raise('distributed-brute-force', user, now, {
        ip: [...ips].slice(-1)[0], user, count: distWin.length, ips: ips.size,
        detail: `${distWin.length} failed logins for "${user}" from ${ips.size} addresses`,
        evidence: `addresses: ${[...ips].slice(0, 8).join(', ')}${ips.size > 8 ? ', ...' : ''}`,
      }));
      lock(user, now, 'distributed-brute-force', out.actions);
    }

    // Low and slow: lots of failures over an hour, without ever tripping the fast rules.
    const slowWin = within(ipArr, now, cfg.slow.windowMs);
    const everFast = open.has(`brute-force|${ip}|${user}`) || open.has(`password-spray|${ip}`);
    if (!fastFired && !everFast && slowWin.length >= cfg.slow.failures) {
      emit(raise('slow-brute-force', ip, now, {
        ip, user, count: slowWin.length,
        detail: `${slowWin.length} failed logins from ${ip} over ${fmtSpan(now - slowWin[0].ts)}, never fast enough to trip the burst rule`,
        evidence: `average gap ${fmtSpan((now - slowWin[0].ts) / Math.max(1, slowWin.length - 1))}`,
      }));
      block(ip, now, 'slow-brute-force', out.actions);
    }
  }

  // The OS already locked the account, so there is nothing to block here. The value is the context:
  // the failures Tripline saw for that account just before, and from how many addresses.
  function ingestLockout(e, now, out, emit) {
    const user = String(e.user ?? '').slice(0, 128);
    if (!user) return;
    stats.lockouts = (stats.lockouts || 0) + 1;
    const fails = within(failsByUser.get(user), now, cfg.compromise.windowMs);
    const ips = [...new Set(fails.map((f) => f.ip))];
    const host = String(e.host || '').slice(0, 64);
    emit(raise('account-lockout', user, now, {
      ip: ips.length === 1 ? ips[0] : undefined, user, host, count: fails.length,
      detail: `Windows locked "${user}"${host ? ` (caller computer ${host})` : ''}${fails.length ? ` after ${fails.length} failed logons from ${ips.length} address${ips.length === 1 ? '' : 'es'}` : ''}`,
      evidence: ips.length ? `addresses: ${ips.slice(0, 8).join(', ')}${ips.length > 8 ? ', ...' : ''}` : 'event 4740, no failed logons for this account in the log',
    }));
  }

  function ingestConn(e, now, out, emit) {
    const ip = e.ip || 'unknown';
    const s = touchIp(ip, now);
    stats.conns++;
    s.ports.add(e.port);
    const arr = push(portsByIp, ip, { ts: now, port: e.port }, now);
    const ports = new Set(within(arr, now, cfg.scan.windowMs).map((p) => p.port));
    if (ports.size >= cfg.scan.ports) {
      emit(raise('port-scan', ip, now, {
        ip, count: ports.size, detail: `${ip} connected to ${ports.size} decoy ports: ${[...ports].sort((a, b) => a - b).join(', ')}`,
        evidence: `ports ${[...ports].join(', ')}`,
      }));
      block(ip, now, 'port-scan', out.actions);
    } else {
      // Long cooldown so a single curious connection does not flood the feed.
      const key = `honeypot-touch|${ip}`;
      const prev = open.get(key);
      if (!prev || now - prev.lastSeen > cfg.cooldownMs * 10) {
        emit(raise('honeypot-touch', ip, now, { ip, count: 1, detail: `${ip} connected to decoy ${e.service || 'service'} on port ${e.port}`, evidence: `port ${e.port}` }));
      }
    }
  }

  function isBlocked(ip, now) {
    const b = blocked.get(ip);
    if (!b) return null;
    if (b.until <= now) { blocked.delete(ip); return null; }
    return b;
  }
  function isLocked(user, now) {
    const l = locked.get(user);
    if (!l) return null;
    if (l.until <= now) { locked.delete(user); return null; }
    return l;
  }
  function noteBlockedAttempt(ip, now) {
    stats.blockedAttempts++;
    touchIp(ip, now).attempts++;
  }
  function unblock(ip) { return blocked.delete(ip); }

  function snapshot(now = lastTs) {
    const attackers = [...ipStats.values()]
      .map((s) => ({
        ip: s.ip, attempts: s.attempts, failures: s.failures, successes: s.successes, users: s.users.size, ports: s.ports.size, requests: s.requests || 0,
        alerts: s.alerts, firstSeen: s.firstSeen, lastSeen: s.lastSeen, blockedUntil: isBlocked(s.ip, now)?.until || null,
      }))
      .sort((a, b) => b.alerts - a.alerts || b.attempts - a.attempts)
      .slice(0, 50);
    return {
      stats: { ...stats },
      attackers,
      blocked: [...blocked.entries()].filter(([, b]) => b.until > now).map(([ip, b]) => ({ ip, ...b })),
      locked: [...locked.entries()].filter(([, l]) => l.until > now).map(([user, l]) => ({ user, ...l })),
      alerts: alerts.slice(-200),
      config: cfg,
    };
  }

  return { ingest, isBlocked, isLocked, noteBlockedAttempt, unblock, snapshot, config: cfg, alerts };
}

function mergeConfig(base, over) {
  const out = {};
  for (const [k, v] of Object.entries(base)) {
    out[k] = v && typeof v === 'object' ? { ...v, ...(over[k] || {}) } : (k in over ? over[k] : v);
  }
  return out;
}

export function fmtSpan(ms) {
  const s = Math.max(0, Math.round(ms / 1000));
  if (s < 60) return `${s}s`;
  if (s < 3600) return `${Math.floor(s / 60)}m ${String(s % 60).padStart(2, '0')}s`;
  return `${Math.floor(s / 3600)}h ${String(Math.floor((s % 3600) / 60)).padStart(2, '0')}m`;
}
