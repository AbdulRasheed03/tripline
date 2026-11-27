// Turn Tripline's block decisions into firewall commands for a human to review and run.
// Pure: it only builds text. Tripline never runs these commands itself.
//
// Addresses come from logs, and logs are written by attackers. So every address is checked against a strict
// IPv4 or IPv6 grammar before it can appear in a command. Anything else ("unknown", "local", "1.2.3.4; rm -rf /")
// is left out and listed in a comment instead. Loopback and unspecified addresses are left out too: blocking
// 127.0.0.1 or ::1 would cut the machine off from itself, and the lab's own attackers all live there.

export const FIREWALL_FORMATS = ['nftables', 'ufw', 'fail2ban', 'iptables'];

const V4_OCTET = '(25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)';
const V4 = new RegExp(`^${V4_OCTET}(\\.${V4_OCTET}){3}$`);
const HEX = /^[0-9a-f]{1,4}$/i;

export function ipVersion(value) {
  const s = String(value ?? '');
  if (s.length > 45) return 0;
  if (V4.test(s)) return 4;
  if (!s.includes(':') || /[^0-9a-f:.]/i.test(s)) return 0;
  const halves = s.split('::');
  if (halves.length > 2) return 0;
  const groups = (h) => (h === '' ? [] : h.split(':'));
  const head = groups(halves[0]);
  const tail = halves.length === 2 ? groups(halves[1]) : [];
  const all = [...head, ...tail];
  // An embedded IPv4 address (::ffff:203.0.113.5) may only be the last part and counts as two groups.
  let size = all.length;
  const last = all.at(-1);
  if (last && last.includes('.')) {
    if (!V4.test(last)) return 0;
    all.pop();
    size++;
  }
  if (!all.every((g) => HEX.test(g))) return 0;
  if (halves.length === 2 ? size > 7 : size !== 8) return 0;
  return 6;
}

// Fold IPv4-mapped IPv6 into the plain address, so one attacker gives one rule.
function normalise(ip) {
  const s = String(ip).toLowerCase();
  const m = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/.exec(s);
  return m ? m[1] : s;
}

// Every group of a valid IPv6 address as a number, with :: filled in.
function groups6(ip) {
  const [a, b] = ip.split('::');
  const head = a ? a.split(':') : [];
  const tail = b !== undefined && b ? b.split(':') : [];
  const fill = b !== undefined ? Array(8 - head.length - tail.length).fill('0') : [];
  return [...head, ...fill, ...tail].map((g) => parseInt(g, 16));
}

function isSelf(ip, version) {
  if (version === 4) return ip.startsWith('127.') || ip === '0.0.0.0';
  if (ip.includes('.')) return false; // embedded IPv4 that was not ::ffff: mapped
  const g = groups6(ip);
  return g.slice(0, 7).every((n) => n === 0) && (g[7] === 0 || g[7] === 1); // :: and ::1, however they are written
}

// Rule ids are ours, but keep comments to a safe alphabet anyway.
const label = (reason) => String(reason || 'tripline').toLowerCase().replace(/[^a-z0-9-]/g, '').slice(0, 40) || 'tripline';

// entries: [{ ip, reason }], usually the 'block' actions the engine returned. Returns { v4, v6, skipped }.
export function blockList(entries) {
  const seen = new Map();
  const skipped = [];
  for (const e of entries || []) {
    const raw = e?.ip;
    const version = ipVersion(raw);
    if (!version) { skipped.push({ value: String(raw ?? ''), why: 'not an IP address' }); continue; }
    const ip = normalise(raw);
    const v = ipVersion(ip);
    if (isSelf(ip, v)) { skipped.push({ value: ip, why: 'loopback or unspecified' }); continue; }
    if (!seen.has(ip)) seen.set(ip, { ip, version: v, reason: label(e.reason) });
  }
  const list = [...seen.values()];
  return { v4: list.filter((x) => x.version === 4), v6: list.filter((x) => x.version === 6), skipped };
}

// Shown in comments only. Strip anything that could end the comment line.
const commentSafe = (s) => String(s).replace(/[^\x20-\x7e]/g, '?').slice(0, 60);

export function toFirewall(entries, format, opts = {}) {
  if (!FIREWALL_FORMATS.includes(format)) throw new Error(`Unknown firewall format "${format}". Use one of: ${FIREWALL_FORMATS.join(', ')}`);
  const { v4, v6, skipped } = blockList(entries);
  const all = [...v4, ...v6];
  const jail = /^[A-Za-z0-9_.-]{1,40}$/.test(opts.jail || '') ? opts.jail : 'sshd';
  const L = [];
  L.push(`# Tripline block list for ${format}: ${all.length} address(es)${opts.source ? ` from ${commentSafe(opts.source)}` : ''}.`);
  L.push('# Review every line before running it, as root. Tripline never runs these commands itself.');
  for (const s of skipped) L.push(`# skipped ${commentSafe(s.value) || '(empty)'}: ${s.why}`);
  if (!all.length) {
    L.push('# Nothing to block.');
    return L.join('\n') + '\n';
  }

  if (format === 'nftables') {
    L.push('# Undo with: nft delete table inet tripline');
    L.push('nft add table inet tripline');
    L.push("nft add chain inet tripline input '{ type filter hook input priority -10; policy accept; }'");
    if (v4.length) {
      L.push("nft add set inet tripline blocked4 '{ type ipv4_addr; }'");
      L.push('nft add rule inet tripline input ip saddr @blocked4 drop');
    }
    if (v6.length) {
      L.push("nft add set inet tripline blocked6 '{ type ipv6_addr; }'");
      L.push('nft add rule inet tripline input ip6 saddr @blocked6 drop');
    }
    for (const x of v4) L.push(`nft add element inet tripline blocked4 '{ ${x.ip} }'   # ${x.reason}`);
    for (const x of v6) L.push(`nft add element inet tripline blocked6 '{ ${x.ip} }'   # ${x.reason}`);
  } else if (format === 'ufw') {
    // prepend puts the deny above any earlier allow rule, and works for IPv4 and IPv6 alike.
    L.push('# Undo one with: ufw delete deny from <address>');
    for (const x of all) L.push(`ufw prepend deny from ${x.ip} comment 'tripline ${x.reason}'`);
  } else if (format === 'fail2ban') {
    L.push(`# Uses the "${jail}" jail, which must already exist (change it with --jail). Undo with: fail2ban-client set ${jail} unbanip <address>`);
    for (const x of all) L.push(`fail2ban-client set ${jail} banip ${x.ip}   # ${x.reason}`);
  } else if (format === 'iptables') {
    L.push('# Not saved across reboots. Undo one by running the same line with -D instead of -I.');
    for (const x of v4) L.push(`iptables -I INPUT -s ${x.ip} -m comment --comment 'tripline ${x.reason}' -j DROP`);
    for (const x of v6) L.push(`ip6tables -I INPUT -s ${x.ip} -m comment --comment 'tripline ${x.reason}' -j DROP`);
  }
  return L.join('\n') + '\n';
}
