// Windows Security log support.
// Turns logon events into the same Tripline events the SSH parser makes, so every existing rule
// (brute force, spraying, distributed, low and slow, success after failures) works on RDP, SMB and
// console logons without a single new detection rule.
//
//   4625  An account failed to log on       -> { type: 'auth', ok: false }
//   4624  An account was successfully logged on -> { type: 'auth', ok: true }
//   4740  A user account was locked out    -> { type: 'lockout' }
//
// Two export formats are read:
//   XML:  Get-WinEvent ... | ForEach-Object { $_.ToXml() }, wevtutil qe Security /f:xml,
//         or Event Viewer "Save All Events As..." XML. Fields are named (<Data Name='IpAddress'>).
//   JSON: Get-WinEvent ... | Select-Object TimeCreated, Id, Properties | ConvertTo-Json
//         Fields are positional (Properties[19].Value is the address in a 4625).
// Pure functions, no I/O.

export const WINDOWS_EVENT_IDS = [4624, 4625, 4740];

// Positions of the fields we need inside Properties, per event ID (from the event schema).
const POSITION = {
  4625: { TargetUserName: 5, TargetDomainName: 6, SubStatus: 9, LogonType: 10, WorkstationName: 13, IpAddress: 19 },
  4624: { TargetUserSid: 4, TargetUserName: 5, TargetDomainName: 6, LogonType: 8, WorkstationName: 11, IpAddress: 18 },
  4740: { TargetUserName: 0, TargetDomainName: 1 },
};

const NO_SUCH_USER = 0xc0000064;
// Logon types that are the machine talking to itself: 0 system, 4 batch (scheduled task), 5 service.
const NOISE_LOGON_TYPES = new Set([0, 4, 5]);
const SERVICE_SIDS = new Set(['S-1-5-18', 'S-1-5-19', 'S-1-5-20']); // SYSTEM, LOCAL SERVICE, NETWORK SERVICE
const VIRTUAL_DOMAINS = /^(window manager|font driver host|nt authority|nt service)$/i;

const ENTITIES = { amp: '&', lt: '<', gt: '>', quot: '"', apos: "'" };
const unxml = (s) => String(s).replace(/&(amp|lt|gt|quot|apos);/g, (_, n) => ENTITIES[n]);

function toNumber(v) {
  if (typeof v === 'number') return v;
  const s = String(v ?? '').trim();
  if (/^0x[0-9a-f]+$/i.test(s)) return parseInt(s, 16);
  return /^\d+$/.test(s) ? Number(s) : NaN;
}

function toTs(v) {
  if (v == null) return NaN;
  if (typeof v === 'number') return v;
  if (typeof v === 'object') return toTs(v.value ?? v.DateTime);
  const ms = /\/Date\((-?\d+)(?:[+-]\d{4})?\)\//.exec(v); // Windows PowerShell 5.1 writes "\/Date(1764000000000)\/"
  return ms ? Number(ms[1]) : Date.parse(v);
}

// "-" and empty mean "no address". Strip the IPv4-mapped prefix so ::ffff:203.0.113.5 and 203.0.113.5 are one source.
function cleanIp(v) {
  const s = String(v ?? '').trim();
  if (!s || s === '-') return null;
  return s.replace(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/i, '$1');
}

// Map one event (id, time, named fields) to a Tripline event, or null if it is not one we use.
export function fromWindowsFields(id, ts, f) {
  id = Number(id);
  if (!WINDOWS_EVENT_IDS.includes(id) || !Number.isFinite(ts)) return null;
  // Windows account names are case-insensitive: ADMINISTRATOR and administrator are the same target.
  const user = String(f.TargetUserName ?? '').trim().toLowerCase();
  const clean = user === '-' ? '' : user;

  if (id === 4740) {
    if (!clean) return null;
    return { type: 'lockout', ts, user: clean, host: String(f.TargetDomainName ?? '').trim().slice(0, 64), source: 'windows' };
  }

  const logonType = toNumber(f.LogonType);
  const ip = cleanIp(f.IpAddress) || 'local';
  if (id === 4625) {
    return { type: 'auth', ts, ip, user: clean, ok: false, knownUser: toNumber(f.SubStatus) !== NO_SUCH_USER, logonType, source: 'windows' };
  }
  // 4624: drop the thousands of logons Windows makes for itself, so only people (or attackers) remain.
  if (NOISE_LOGON_TYPES.has(logonType)) return null;
  if (!clean || clean.endsWith('$') || clean === 'anonymous logon') return null;
  if (SERVICE_SIDS.has(String(f.TargetUserSid ?? '').trim()) || VIRTUAL_DOMAINS.test(String(f.TargetDomainName ?? '').trim())) return null;
  return { type: 'auth', ts, ip, user: clean, ok: true, knownUser: true, logonType, source: 'windows' };
}

// One <Event>...</Event> element as XML text.
export function parseWindowsXmlEvent(xml) {
  const id = /<EventID[^>]*>\s*(\d+)\s*<\/EventID>/.exec(xml);
  if (!id) return null;
  const time = /<TimeCreated\s+SystemTime\s*=\s*['"]([^'"]+)['"]/.exec(xml);
  const fields = {};
  for (const m of xml.matchAll(/<Data\s+Name\s*=\s*['"](\w+)['"]\s*(?:\/>|>([^<]*)<\/Data>)/g)) fields[m[1]] = unxml(m[2] ?? '');
  return fromWindowsFields(id[1], toTs(time?.[1]), fields);
}

// One object from Get-WinEvent | Select-Object TimeCreated, Id, Properties | ConvertTo-Json.
export function parseWindowsJsonEvent(o) {
  if (!o || typeof o !== 'object' || !('Id' in o)) return null;
  const pos = POSITION[Number(o.Id)];
  if (!pos || !Array.isArray(o.Properties)) return null;
  const fields = {};
  for (const [name, i] of Object.entries(pos)) {
    const p = o.Properties[i];
    const v = p && typeof p === 'object' ? p.Value : p;
    fields[name] = v && typeof v === 'object' ? v.Value ?? '' : v; // a SID may serialize as { Value: 'S-1-5-18', ... }
  }
  return fromWindowsFields(o.Id, toTs(o.TimeCreated), fields);
}

// A whole exported file. Returns an array of events, or null when the text is not a Windows export.
export function parseWindowsDocument(text) {
  const s = String(text).replace(/^﻿/, '').trim();
  if (/<Event[\s>]/.test(s) && /<EventID/.test(s)) {
    return [...s.matchAll(/<Event[\s>][\s\S]*?<\/Event>/g)].map((m) => parseWindowsXmlEvent(m[0])).filter(Boolean);
  }
  if (s.startsWith('[') || s.startsWith('{')) {
    let data;
    try { data = JSON.parse(s); } catch { return null; }
    const list = Array.isArray(data) ? data : [data];
    if (!list.length || !list.every((o) => o && typeof o === 'object' && 'Id' in o)) return null;
    return list.map(parseWindowsJsonEvent).filter(Boolean);
  }
  return null;
}

// True when the export used plain ConvertTo-Json without Select-Object, which turns every field into a type name.
export function looksLikeFlattenedWinEvent(text) {
  return /System\.Diagnostics\.Eventing\.Reader\.EventProperty/.test(String(text));
}
