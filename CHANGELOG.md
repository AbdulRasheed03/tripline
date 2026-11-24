# Changelog

## 1.1.0 (2026-11-24)

### Added
* Web attack detection from nginx and Apache access logs (combined and common formats): vulnerability scanners by User-Agent (T1595.002), directory brute forcing (T1595.003), injection and path traversal in URLs with double URL decoding (T1190), probes for secret files (T1083), and a separate critical alert when a secret file is actually served (T1552.001).
* Command injection patterns (`; cat /etc/passwd`, `$(id)`) and `/etc/passwd` / `win.ini` traversal targets.
* Markdown incident report: `tripline replay <log> --md`, and an **Incident report** button on the dashboard. Attacker-controlled text is neutralised so it cannot inject Markdown into a ticket.
* `samples/access.log` with four web attackers and normal visitors whose URLs only look dangerous.
* 10 tests (37 in total). CI now replays the web log and builds a report.

### Fixed
* `UNION SELECT` detection no longer fires on slugs such as `/blog/union-select-guide`.
* `replay` lists only the sources that raised alerts.

## 1.0.0 (2026-11-24)

First release: live lab with an attackable portal and decoy ports, detection of brute force, password spraying, distributed and low-and-slow brute force, success after failures, login injection and port scans, auto-block and account lockout, attack simulator, SSH log watch and replay, and a browser demo.
