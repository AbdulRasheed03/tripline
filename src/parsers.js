// Turns log lines into Tripline events.
// Supported: OpenSSH lines from /var/log/auth.log or /var/log/secure (classic syslog or ISO timestamps),
// nginx and Apache access logs (combined or common format),
// and Tripline's own JSON lines ({"type":"auth",...}) for piping from other tools.

const MONTHS = { jan: 0, feb: 1, mar: 2, apr: 3, may: 4, jun: 5, jul: 6, aug: 7, sep: 8, oct: 9, nov: 10, dec: 11 };

// "Nov 24 06:55:23 host sshd[812]: ..."  or  "2026-11-24T06:55:23.123456+08:00 host sshd[812]: ..."
const SYSLOG = /^([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})\s+\S+\s+(\S+?)(?:\[\d+\])?:\s+(.*)$/;
const ISO = /^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s+\S+\s+(\S+?)(?:\[\d+\])?:\s+(.*)$/;

// nginx / Apache "combined" (and "common", without referrer and User-Agent):
// 203.0.113.9 - - [24/Nov/2026:02:10:01 +0800] "GET /wp-login.php HTTP/1.1" 404 153 "-" "Mozilla/5.0 ..."
const ACCESS = /^(\S+) \S+ \S+ \[(\d{2})\/([A-Za-z]{3})\/(\d{4}):(\d{2}:\d{2}:\d{2}) ([+-]\d{4})\] "([A-Z]+) (\S+)(?: [^"]*)?" (\d{3}) \S+(?: "[^"]*" "([^"]*)")?/;

function parseAccess(s) {
  const m = ACCESS.exec(s);
  if (!m) return null;
  const mon = MONTHS[m[3].toLowerCase()];
  if (mon === undefined) return null;
  const iso = `${m[4]}-${String(mon + 1).padStart(2, '0')}-${m[2]}T${m[5]}${m[6].slice(0, 3)}:${m[6].slice(3)}`;
  return { type: 'http', ts: Date.parse(iso), ip: m[1], method: m[7], path: m[8], status: Number(m[9]), ua: m[10] || '', source: 'web' };
}

const SSH_FAILED = /^Failed (?:password|publickey|keyboard-interactive\/pam|none) for (invalid user )?(.*?) from (\S+) port \d+/;
const SSH_ACCEPTED = /^Accepted (?:password|publickey|keyboard-interactive\/pam) for (.*?) from (\S+) port \d+/;

export function parseTimestamp(line, { year = new Date().getFullYear() } = {}) {
  let m = ISO.exec(line);
  if (m) return { ts: Date.parse(m[1]), program: m[2], message: m[3] };
  m = SYSLOG.exec(line);
  if (m) {
    const mon = MONTHS[m[1].toLowerCase()];
    if (mon === undefined) return null;
    // Syslog has no year or zone. Local time of the machine reading the log is the best guess.
    const ts = new Date(year, mon, Number(m[2]), Number(m[3]), Number(m[4]), Number(m[5])).getTime();
    return { ts, program: m[6], message: m[7] };
  }
  return null;
}

export function parseLine(line, opts = {}) {
  const s = String(line || '').trim();
  if (!s) return null;

  if (s.startsWith('{')) {
    try {
      const e = JSON.parse(s);
      if ((e.type === 'auth' || e.type === 'conn' || e.type === 'http') && e.ip) {
        return { ...e, ts: typeof e.ts === 'string' ? Date.parse(e.ts) : Number(e.ts) || Date.now(), source: e.source || 'json' };
      }
    } catch { /* not JSON after all */ }
    return null;
  }

  const web = parseAccess(s);
  if (web) return web;

  const head = parseTimestamp(s, opts);
  if (!head || !/^sshd/.test(head.program)) return null;
  let m = SSH_FAILED.exec(head.message);
  if (m) return { type: 'auth', ts: head.ts, ip: m[3], user: m[2], ok: false, knownUser: !m[1], source: 'ssh' };
  m = SSH_ACCEPTED.exec(head.message);
  if (m) return { type: 'auth', ts: head.ts, ip: m[2], user: m[1], ok: true, knownUser: true, source: 'ssh' };
  return null;
}

export function parseLog(text, opts = {}) {
  return String(text).split(/\r?\n/).map((l) => parseLine(l, opts)).filter(Boolean);
}
