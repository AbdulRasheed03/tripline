import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { createDetector } from '../src/engine.js';
import { parseLog } from '../src/parsers.js';
import { ipVersion, blockList, toFirewall, FIREWALL_FORMATS } from '../src/firewall.js';

const CLI = fileURLToPath(new URL('../cli/tripline.mjs', import.meta.url));
const commands = (out) => out.split('\n').filter((l) => l && !l.startsWith('#'));

test('only real IPv4 and IPv6 addresses pass the address check', () => {
  for (const ok of ['203.0.113.45', '0.0.0.0', '255.255.255.255', '2001:db8::7', '2001:0db8:0000:0000:0000:0000:0000:0001', '::ffff:198.51.100.9', '::', 'fe80::1'])
    assert.ok(ipVersion(ok), ok);
  for (const bad of ['', 'unknown', 'local', '256.1.1.1', '203.0.113', '203.0.113.045.1', '2001:db8:::1', '2001:db8::1::2', '1:2:3:4:5:6:7:8:9',
    'fe80::1%eth0', '203.0.113.7; rm -rf /', '$(id)', "203.0.113.7' ; nft flush ruleset; '", '203.0.113.7\nnft flush ruleset', '2001:db8::g', ' 203.0.113.7'])
    assert.equal(ipVersion(bad), 0, JSON.stringify(bad));
});

test('the block list drops loopback and junk, folds mapped IPv6 and removes duplicates', () => {
  const { v4, v6, skipped } = blockList([
    { ip: '203.0.113.45', reason: 'brute-force' },
    { ip: '::ffff:203.0.113.45', reason: 'port-scan' },
    { ip: '2001:DB8::7', reason: 'web-scanner' },
    { ip: '127.0.0.66', reason: 'brute-force' },
    { ip: '0:0:0:0:0:0:0:1', reason: 'brute-force' },
    { ip: 'local', reason: 'brute-force' },
    { ip: '203.0.113.9`; reboot', reason: 'x' },
  ]);
  assert.deepEqual(v4.map((x) => [x.ip, x.reason]), [['203.0.113.45', 'brute-force']]);
  assert.deepEqual(v6.map((x) => x.ip), ['2001:db8::7']);
  assert.equal(skipped.length, 4);
  assert.ok(skipped.some((s) => s.value === '127.0.0.66' && /loopback/.test(s.why)));
});

test('every format writes the right commands for IPv4 and IPv6', () => {
  const entries = [{ ip: '198.51.100.23', reason: 'password-spray' }, { ip: '2001:db8::5', reason: 'web-injection' }];
  const nft = toFirewall(entries, 'nftables');
  assert.match(nft, /^nft add element inet tripline blocked4 '\{ 198\.51\.100\.23 \}'/m);
  assert.match(nft, /^nft add element inet tripline blocked6 '\{ 2001:db8::5 \}'/m);
  assert.match(nft, /^nft add rule inet tripline input ip6 saddr @blocked6 drop$/m);
  assert.match(toFirewall(entries, 'ufw'), /^ufw prepend deny from 2001:db8::5 comment 'tripline web-injection'$/m);
  assert.match(toFirewall(entries, 'fail2ban', { jail: 'nginx-http-auth' }), /^fail2ban-client set nginx-http-auth banip 198\.51\.100\.23/m);
  assert.match(toFirewall(entries, 'fail2ban', { jail: 'sshd; reboot' }), /^fail2ban-client set sshd banip/m, 'a strange jail name falls back to sshd');
  const ipt = toFirewall(entries, 'iptables');
  assert.match(ipt, /^iptables -I INPUT -s 198\.51\.100\.23 .* -j DROP$/m);
  assert.match(ipt, /^ip6tables -I INPUT -s 2001:db8::5 .* -j DROP$/m);
  assert.throws(() => toFirewall(entries, 'pf'), /Unknown firewall format/);
});

test('hostile values from a log never reach a command line', () => {
  const evil = [{ ip: "203.0.113.7' ; nft flush ruleset ; '", reason: 'x' }, { ip: '203.0.113.8\nreboot', reason: 'x' }, { ip: '203.0.113.9', reason: "a'; halt #" }];
  for (const f of FIREWALL_FORMATS) {
    const out = toFirewall(evil, f, { source: 'log\nreboot' });
    const cmds = commands(out);
    assert.ok(cmds.every((l) => !/flush|reboot|';/.test(l)), `${f}: ${cmds.join(' / ')}`);
    assert.ok(out.split('\n').every((l) => l === '' || l.startsWith('#') || /^(nft|ufw|fail2ban-client|ip6?tables) /.test(l)), `${f} has only commands and comments`);
    assert.ok(cmds.some((l) => l.includes('203.0.113.9')), `${f} keeps the real address`);
  }
});

test('nothing to block gives comments only', () => {
  for (const f of FIREWALL_FORMATS) {
    const out = toFirewall([{ ip: '127.0.0.66', reason: 'brute-force' }], f);
    assert.equal(commands(out).length, 0, f);
    assert.match(out, /Nothing to block/);
  }
});

test('the SSH sample blocks its four attackers and never the admin who mistyped', () => {
  const det = createDetector();
  const blocks = [];
  for (const e of parseLog(readFileSync(new URL('../samples/auth.log', import.meta.url), 'utf8'), { year: 2026 }))
    blocks.push(...det.ingest(e).actions.filter((a) => a.type === 'block'));
  const ips = blockList(blocks).v4.map((x) => x.ip).sort();
  assert.deepEqual(ips, ['198.51.100.23', '198.51.100.61', '203.0.113.200', '203.0.113.45']);
  assert.ok(!toFirewall(blocks, 'ufw').includes('192.0.2.10'), 'the real admin is never blocked');
});

test('replay --firewall prints only a script and keeps exit code 2', () => {
  const r = spawnSync(process.execPath, [CLI, 'replay', fileURLToPath(new URL('../samples/access.log', import.meta.url)), '--firewall', 'iptables'], { encoding: 'utf8' });
  assert.equal(r.status, 2, r.stderr);
  const cmds = commands(r.stdout);
  assert.ok(cmds.length >= 3);
  assert.ok(cmds.every((l) => l.startsWith('iptables -I INPUT -s ')), r.stdout);
  const bad = spawnSync(process.execPath, [CLI, 'replay', 'samples/access.log', '--firewall', 'pf'], { encoding: 'utf8' });
  assert.equal(bad.status, 1);
  assert.match(bad.stderr, /nftables, ufw, fail2ban, iptables/);
});
