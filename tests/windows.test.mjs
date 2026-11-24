import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, writeFileSync, mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { parseLine, parseLog, decodeText } from '../src/parsers.js';
import { parseWindowsDocument, looksLikeFlattenedWinEvent } from '../src/windows.js';
import { createDetector } from '../src/engine.js';
import { toMarkdown } from '../src/report.js';

const run = (events) => {
  const det = createDetector();
  const alerts = new Map();
  for (const e of events.sort((a, b) => a.ts - b.ts)) for (const a of det.ingest(e).alerts) alerts.set(a.id, a);
  return { det, alerts: [...alerts.values()] };
};

// A 4625 as Get-WinEvent | Select-Object TimeCreated, Id, Properties | ConvertTo-Json writes it in Windows PowerShell 5.1.
const props = (values) => values.map((Value) => ({ Value }));
const json4625 = (ms, user, ip, subStatus = 3221225578) => ({
  TimeCreated: `/Date(${ms})/`, Id: 4625,
  Properties: props(['S-1-0-0', '-', '-', 0, 'S-1-0-0', user, 'CORP', 3221225581, '%%2313', subStatus, 10, 'User32', 'Negotiate', 'kali', '-', '-', 0, 0, '-', ip, 0]),
});
const json4624 = (ms, user, ip, { type = 10, sid = 'S-1-5-21-1-2-3-1104', domain = 'CORP' } = {}) => ({
  TimeCreated: new Date(ms).toISOString(), Id: 4624, // PowerShell 7 writes ISO dates
  Properties: props(['S-1-5-18', 'FS01$', 'CORP', 999, sid, user, domain, 1, type, 'User32', 'Negotiate', 'WS1', '{0}', '-', '-', 0, 1256, 'svchost.exe', ip, 50112]),
});

test('the sample security.xml: one alert per attacker, nothing for the user with a typo or for Windows itself', () => {
  const events = parseLog(readFileSync(new URL('../samples/security.xml', import.meta.url), 'utf8'));
  assert.equal(events.filter((e) => e.type === 'auth').length, 35, 'SYSTEM, DWM, machine and anonymous logons are dropped');
  assert.equal(events.filter((e) => e.type === 'lockout').length, 1);
  const { alerts } = run(events);
  const byRule = Object.fromEntries(alerts.map((a) => [a.rule, a.ip ?? a.user]));
  assert.deepEqual(byRule, {
    'brute-force': '203.0.113.77',
    'account-lockout': '203.0.113.77',
    'password-spray': '198.51.100.140',
    'compromise-suspected': '203.0.113.12',
  });
  const brute = alerts.find((a) => a.rule === 'brute-force');
  assert.equal(brute.user, 'administrator', 'Administrator, administrator and ADMINISTRATOR are one account');
  assert.equal(brute.count, 12);
  assert.ok(!alerts.some((a) => a.ip === '192.0.2.15'), 'aina mistyped once over RDP and is not flagged');
  assert.ok(!alerts.some((a) => String(a.ip).startsWith('::ffff:')), 'IPv4-mapped addresses fold into the plain address');
});

test('Get-WinEvent JSON: a whole array, one compressed object per line, numeric and hex SubStatus', () => {
  const t0 = Date.parse('2026-11-24T03:00:00Z');
  const arr = [json4625(t0, 'svc-sql', '203.0.113.50'), json4625(t0 + 1000, 'nobody', '203.0.113.50', 0xc0000064), json4624(t0 + 2000, 'svc-sql', '203.0.113.50'),
    { TimeCreated: `/Date(${t0 + 3000})/`, Id: 4740, Properties: props(['svc-sql', 'WS-FRONT', 'S-1-5-21-1-2-3-500', 'S-1-5-18', 'DC01$', 'CORP', 999]) }];
  const events = parseWindowsDocument(JSON.stringify(arr, null, 2));
  assert.equal(events.length, 4);
  assert.deepEqual(events[0], { type: 'auth', ts: t0, ip: '203.0.113.50', user: 'svc-sql', ok: false, knownUser: true, logonType: 10, source: 'windows' });
  assert.equal(events[1].knownUser, false, 'SubStatus 0xC0000064 means the account does not exist');
  assert.equal(events[2].ok, true);
  assert.deepEqual(events[3], { type: 'lockout', ts: t0 + 3000, user: 'svc-sql', host: 'WS-FRONT', source: 'windows' });
  // A single object (one event exported) and JSON lines work too.
  assert.equal(parseWindowsDocument(JSON.stringify(arr[0])).length, 1);
  assert.equal(parseLine(JSON.stringify(arr[2])).user, 'svc-sql');
  assert.equal(parseLog(arr.map((o) => JSON.stringify(o)).join('\n')).length, 4);
});

test('one XML event per line, as $_.ToXml() writes it, with entities and empty fields', () => {
  const xml = "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><EventID>4625</EventID><TimeCreated SystemTime='2026-11-24T03:00:00.1234567Z'/></System>"
    + "<EventData><Data Name='TargetUserName'>o&apos;brien&amp;co</Data><Data Name='SubStatus'>0xc000006a</Data><Data Name='LogonType'>3</Data><Data Name='WorkstationName'/><Data Name='IpAddress'>2001:db8::44</Data></EventData></Event>";
  const e = parseLine(xml);
  assert.equal(e.user, "o'brien&co");
  assert.equal(e.ip, '2001:db8::44');
  assert.equal(e.ts, Date.parse('2026-11-24T03:00:00.123Z'));
  assert.equal(parseLine(xml.replace('<Data Name=\'IpAddress\'>2001:db8::44</Data>', "<Data Name='IpAddress'>-</Data>")).ip, 'local', 'a console logon has no address');
});

test('false positive guards: logons Windows makes for itself and unrelated event IDs are ignored', () => {
  const t0 = Date.parse('2026-11-24T04:00:00Z');
  const noise = [
    json4624(t0, 'SYSTEM', '-', { type: 5, sid: 'S-1-5-18', domain: 'NT AUTHORITY' }),
    json4624(t0, 'backupjob', '-', { type: 4 }),
    json4624(t0, 'FS01$', '192.0.2.5', { type: 3 }),
    json4624(t0, 'ANONYMOUS LOGON', '192.0.2.6', { type: 3, sid: 'S-1-5-7' }),
    json4624(t0, 'DWM-2', '-', { type: 2, sid: 'S-1-5-90-0-2', domain: 'Window Manager' }),
    json4624(t0, 'UMFD-2', '-', { type: 2, sid: 'S-1-5-96-0-2', domain: 'Font Driver Host' }),
    json4624(t0, 'LocalSvc', '-', { type: 3, sid: 'S-1-5-19' }),
    { TimeCreated: `/Date(${t0})/`, Id: 4634, Properties: props(['S-1-5-21-1', 'aina', 'CORP', 1, 3]) }, // logoff
    { TimeCreated: `/Date(${t0})/`, Id: 4672, Properties: props(['S-1-5-21-1', 'aina', 'CORP', 1, 'SeDebugPrivilege']) },
  ];
  assert.deepEqual(parseWindowsDocument(JSON.stringify(noise)), []);
  // Plain Tripline JSON lines are not mistaken for Windows events.
  assert.equal(parseWindowsDocument('{"type":"auth","ip":"203.0.113.9","user":"x","ok":false}'), null);
});

test('a lone lockout is a medium alert that says it saw no failures, never high', () => {
  const { alerts } = run([{ type: 'lockout', ts: Date.parse('2026-11-24T05:00:00Z'), user: 'mei', host: 'MEI-PC', source: 'windows' }]);
  assert.equal(alerts.length, 1);
  assert.equal(alerts[0].rule, 'account-lockout');
  assert.equal(alerts[0].severity, 'medium');
  assert.equal(alerts[0].ip, undefined);
  assert.match(alerts[0].evidence, /no failed logons/);
});

test('Windows PowerShell 5.1 UTF-16 files are decoded, not silently read as zero events', () => {
  const xml = readFileSync(new URL('../samples/security.xml', import.meta.url), 'utf8');
  const utf16 = Buffer.concat([Buffer.from([0xff, 0xfe]), Buffer.from(xml, 'utf16le')]);
  assert.equal(parseLog(decodeText(utf16)).length, 36);
  const bomUtf8 = Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), Buffer.from(xml)]);
  assert.equal(parseLog(decodeText(bomUtf8)).length, 36);
});

test('plain ConvertTo-Json without Select-Object is recognised and the CLI explains how to export again', () => {
  const flat = JSON.stringify([{ Id: 4625, TimeCreated: '/Date(1795505081700)/', Properties: 'System.Diagnostics.Eventing.Reader.EventProperty System.Diagnostics.Eventing.Reader.EventProperty' }]);
  assert.ok(looksLikeFlattenedWinEvent(flat));
  assert.deepEqual(parseLog(flat), []);
  const file = join(mkdtempSync(join(tmpdir(), 'tripline-')), 'security.json');
  writeFileSync(file, flat);
  const r = spawnSync(process.execPath, [fileURLToPath(new URL('../cli/tripline.mjs', import.meta.url)), 'replay', file, '--no-color'], { encoding: 'utf8' });
  assert.equal(r.status, 1);
  assert.match(r.stderr, /Select-Object TimeCreated, Id, Properties/);
});

test('the incident report names the caller computer for a lockout and neutralises a hostile account name', () => {
  const t0 = Date.parse('2026-11-24T06:00:00Z');
  const hostile = 'x`](http://evil.example)|# fake';
  const events = [];
  for (let i = 0; i < 8; i++) events.push({ ...json4625(t0 + i * 1000, hostile, '203.0.113.66') });
  events.push({ TimeCreated: `/Date(${t0 + 9000})/`, Id: 4740, Properties: props([hostile, 'WS|FRONT', 'S', 'S', 'DC01$', 'CORP', 1]) });
  const { det } = run(parseWindowsDocument(JSON.stringify(events)));
  const md = toMarkdown(det.snapshot());
  assert.match(md, /Windows locked an account/);
  assert.match(md, /Windows account lockouts \| 1/);
  assert.ok(!md.includes('`](http'), 'a backtick in the account name cannot close the code span');
  assert.ok(!md.includes('WS|FRONT'), 'a pipe in the caller computer cannot break the table');
});
