import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createDetector } from '../src/engine.js';
import { parseLog } from '../src/parsers.js';
import { toMarkdown } from '../src/report.js';

function replay(file, opts) {
  const det = createDetector();
  const events = parseLog(readFileSync(new URL(`../samples/${file}`, import.meta.url), 'utf8'), opts);
  for (const e of events) det.ingest(e);
  return det.snapshot(events.at(-1).ts);
}

test('report for the SSH sample: summary, critical first, MITRE links, indicators', () => {
  const md = toMarkdown(replay('auth.log', { year: 2026 }), { source: 'samples/auth.log', generatedAt: Date.UTC(2026, 10, 24) });
  assert.match(md, /^# Incident report: 4 alert\(s\), highest severity critical/);
  assert.match(md, /\| Alerts \| 1 critical, 2 high, 1 medium, 0 low \|/);
  assert.match(md, /\*\*Act first:\*\*/);
  const firstRow = md.split('\n').find((l) => l.startsWith('| 1 |'));
  assert.match(firstRow, /critical \| Successful login after many failures/);
  assert.match(md, /\[T1110\.003\]\(https:\/\/attack\.mitre\.org\/techniques\/T1110\/003\/\)/);
  assert.match(md, /```\n(203\.0\.113\.45|198\.51\.100\.\d+|203\.0\.113\.200)(\n[\d.]+)*\n```/);
  assert.ok(!md.includes('—'), 'no em dashes');
});

test('attacker-controlled text cannot inject Markdown into the ticket', () => {
  const det = createDetector();
  const evil = 'x`](https://evil.example)|\n## Fake section\n![img](https://evil.example/p.png)';
  for (let i = 0; i < 8; i++) det.ingest({ type: 'auth', ts: 1000 + i, ip: '203.0.113.7', user: evil, ok: false });
  det.ingest({ type: 'auth', ts: 2000, ip: '```\nrm -rf /', user: 'a', ok: false, injection: 'SQL tautology' });
  const md = toMarkdown(det.snapshot(3000));
  assert.ok(!md.includes('\n## Fake section'), 'no injected headings');
  assert.ok(!/`[^`\n]*`\]\(https:\/\/evil/.test(md), 'no link escaping its code span');
  for (const line of md.split('\n')) if (line.startsWith('|')) assert.ok(!line.includes('`](https://evil'), line);
  const fence = md.split('```')[1];
  assert.ok(!fence.includes('rm -rf'), 'a fake IP cannot break the indicator code fence');
  assert.match(fence, /203\.0\.113\.7/);
});

test('an empty lab still gives a valid report', () => {
  const md = toMarkdown(createDetector().snapshot(0));
  assert.match(md, /^# Incident report: no alerts/);
  assert.match(md, /\(none\)/);
});
