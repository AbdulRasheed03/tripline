# Changelog

## 1.2.0 (2026-11-24)

### Added
* Windows Security log support. Events 4625 (failed logon) and 4624 (successful logon) feed every existing login rule, so RDP, SMB and console attacks are caught the same way as SSH: brute force, spraying, distributed, low and slow, and success after failures.
* New rule **Windows locked an account** (event 4740, T1110). It adds the failed logons Tripline saw for that account just before the lockout, and from how many addresses.
* Reads `Get-WinEvent ... | ForEach-Object { $_.ToXml() }`, Event Viewer and `wevtutil` XML exports, and `Get-WinEvent | Select-Object TimeCreated, Id, Properties | ConvertTo-Json` from Windows PowerShell 5.1 and PowerShell 7. UTF-16 files are decoded instead of silently producing zero events.
* Noise filter for 4624: service, batch and system logons, SYSTEM and service SIDs, machine accounts, ANONYMOUS LOGON and the DWM / UMFD virtual accounts are dropped. Account names are compared without case, and IPv4-mapped IPv6 addresses fold into the plain address.
* `replay` explains how to export again when it gets `ConvertTo-Json` output that lost its fields.
* `samples/security.xml` with three Windows attackers, a user with one typo and background noise. CI replays it.
* 8 tests (45 in total).

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
