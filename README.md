# SOC- : Home SOC on AWS

A personal Security Operations Center (SOC) for a Windows laptop, built on
AWS-native services instead of a SIEM license. Sysmon, the Windows Security
log and the Windows System log are shipped to Amazon CloudWatch Logs, where
metric filters and alarms detect suspicious activity and email an alert.
Saved Logs Insights queries cover threat hunting where alarms cannot.
Everything is defined in Terraform and designed to run for about $0-5 a month.

```
Windows laptop                                   AWS (us-east-2)
+-------------------------+     HTTPS     +--------------------------------------+
| Sysmon (custom config)  |               | CloudWatch Logs (30-day retention)   |
| Windows Security log    | ------------> |   /hsoc/windows/sysmon               |
| Windows System log      |  least-priv.  |   /hsoc/windows/security             |
| CloudWatch Agent        |  IAM identity |   /hsoc/windows/system               |
|  (event ID filtering)   |               |        |                             |
+-------------------------+               |   metric filters -> alarms -> SNS ---+--> email
                                          | AWS Budgets ($5/month guardrail) ----+--> email
                                          +--------------------------------------+
```

## Detections

Eight detections, each mapped to MITRE ATT&CK and tagged with a severity in
its alarm description.

| ID   | Detects | Source / event | MITRE ATT&CK | Severity | Alert when |
|------|---------|----------------|--------------|----------|------------|
| H01  | Brute-force logon attempts | Security 4625 | T1110 | MEDIUM | 5+ in 5 min |
| H02  | New/enabled account, added to a local group, Security log cleared | Security 4720, 4722, 4732, 1102 | T1136, T1098, T1070.001 | HIGH | any |
| P01  | PowerShell run with an encoded command | Sysmon 1 | T1059.001 | HIGH | any |
| P02a | Office app (Word, Excel, PowerPoint, Outlook) launches cmd.exe | Sysmon 1 | T1204.002, T1566.001 | HIGH | any |
| P02b | Office app launches PowerShell | Sysmon 1 | T1204.002, T1566.001 | HIGH | any |
| P03  | certutil used to download a file | Sysmon 1 | T1105 | HIGH | any |
| P04  | New Windows service installed | System 7045 | T1543.003 | MEDIUM | any |
| P05  | Value written to a Run / RunOnce registry key | Sysmon 13 | T1547.001 | MEDIUM | any |

All detections live in one map in [terraform/alerts.tf](terraform/alerts.tf),
so adding a detection is one block of code.

## Validation results

Every detection was tested on the laptop with a harmless self-test that
produces the same telemetry as the real technique (similar to Atomic Red Team).

| ID   | Validation | Time to alert (MTTD) |
|------|------------|----------------------|
| H01, H02 | Live self-test (Phase 1) | see Phase 1 notes |
| P01  | Live self-test: base64-encoded `Write-Output` | ~60 s |
| P04  | Live self-test: dummy service created and deleted | ~72 s |
| P05  | Live self-test: Run value added and removed | ~71 s |
| P03  | Live attempt **blocked by Microsoft Defender in ~1 s** (no process was created); pattern validated with `aws logs test-metric-filter` | prevented |
| P02a/b | Pattern validated with `aws logs test-metric-filter` against real Office paths: 2 attack events matched, 2 benign events did not | - |

Evidence (redacted): [docs/screenshots/phase2](docs/screenshots/phase2)

## Threat hunting (Phase 3)

Alarms run every 5 minutes but metric filters are case-sensitive and cannot
mix AND with OR. Hunting queries run on demand with case-insensitive regular
expressions, so they cover what the alarms cannot. All seven are saved
Logs Insights query definitions in [terraform/queries.tf](terraform/queries.tf).

| ID | Hunts for | MITRE ATT&CK | Validation |
|----|-----------|--------------|------------|
| H-Q01 | Encoded PowerShell in any letter case or abbreviation (`-e`, `-enc`, `-EnCoDeDcOmMaNd`, `/ec`) | T1059.001, T1027 | Found all 3 P01 self-tests, no false positives |
| H-Q02 | certutil download / decode / encode, including a renamed copy | T1105, T1140 | 0 results; positive control returned the 2 known certutil runs |
| H-Q03 | netsh / route changing DNS, routes, firewall or port forwarding, minus verified VPN activity | T1562.004, T1090, T1565 | First run returned 6 VPN events the filter missed; fixed in code, redeployed, re-run: 1 deliberate result |
| H-Q04 | svchost.exe with an unusual parent or path | T1036.005 | Ready (only possible after Sysmon tuning removed the normal case) |
| H-Q05 | Remote-thread injection, with any lsass.exe target flagged | T1055, T1003.001 | Ready |
| T-Q01 | Sysmon volume by event type | - | Used for the before/after below |
| T-Q02 | Sysmon internal errors (Event 255) | - | Health check |

## Sysmon tuning (Phase 3)

One week of real data showed process creation (Event 1) was about 98% of
Sysmon volume. Every exclusion requires **both** the program and its expected
parent, so the same program started by anything else is still logged.

| Excluded | Why it is safe | Still logged |
|----------|----------------|--------------|
| svchost.exe started by services.exe | How Windows starts every service | svchost from any other parent (masquerading) |
| netsh / route started by the VPN service | Verified routing and DNS changes on connect and disconnect | netsh / route from cmd, PowerShell, scripts or an unknown parent |
| Remote threads from `C:\Windows\System32\csrss.exe` | Console Ctrl+C / close signal handling | Any other source, including a fake csrss.exe elsewhere |

**Result:** the excluded event types fell from up to 77 an hour to **zero**
the moment the new config was applied, while the laptop kept logging
everything else. In the measured window they were about 17% of all events.

At this volume (about 240 MB a month, roughly $0.12) tuning is about
**signal-to-noise for hunting**, not cost.

## Alert triage log

Every real alert and hunt finding is triaged with the same steps: what
happened, which program did it, is it signed and expected, verdict, action.

| ID | What | Verdict | Action |
|----|------|---------|--------|
| A-001 | P05 alarm: Copilot updater wrote a RunOnce cleanup value | Benign (signed Microsoft) | Closed |
| A-002, A-003 | P05 alarms: Edge "Startup boost" rewrote its own Run value | Benign (signed Microsoft) | **Fixed the cause:** the settings toggle did not hold, so the setting was enforced by browser policy; re-tested |
| H-001 | Hunt: 11 netsh commands launched from cmd.exe | Benign: read-only commands typed by the user; a local keyboard unlock (logon type 7) preceded each session, no remote logons | Closed |
| H-002 | Hunt: PowerShell creating remote threads in certutil.exe | Expected test activity: traces of the Phase 2 P03 test that Defender blocked, matched to Defender's detection time to the second | Closed |

## Lessons learned

- **Check the real log format before writing a pattern.** System-log events are
  written as `<EventID Qualifiers='16384'>7045</EventID>`, so the obvious pattern
  `<EventID>7045</EventID>` would never have matched. P04 matches the closing
  part only.
- **Prevention can beat detection.** Defender stopped the certutil download
  before the process started, so Sysmon had nothing to log. The detection is
  still deployed for systems where that block is missing.
- **Baseline before alerting.** Word legitimately starts a helper (`ai.exe`)
  when it opens, so P02 matches only shells, not every child process.
- **Your own tools are logged too.** Searching for `-EncodedCommand` with the
  AWS CLI would trigger P01, because Sysmon records that command line.
- **Metric filters are case-sensitive and cannot mix AND with OR.** P01 lists
  common spellings, and P02 is split into P02a and P02b. Case-insensitive checks
  move to Logs Insights hunting queries in Phase 3.
- **Least privilege holds under change.** When the new System log was added, the
  agent was denied until the IAM policy was updated, then retried and delivered
  the held events without loss.
- **A blocked attack can still leave evidence.** Defender stopped the P03 test
  before a process-start event was logged, but Sysmon still recorded remote
  threads into the dying process, which tied back to Defender's own log.
- **Validate hunts, including the empty ones.** H-Q03 failed its first run
  because the VPN's *disconnect* commands carry no VPN address. H-Q02 returned
  nothing, so a positive control proved the query could match at all.
- **Exclude by parent, never by name alone.** Every Sysmon exclusion pairs the
  program with its expected parent, so attackers reusing a trusted name are
  still logged.
- **A settings toggle is not proof of a fix.** Edge recreated its Run value
  after the toggle was turned off; re-testing caught it, and enforcing the
  setting by policy held.
- **Measure honestly.** Raw before/after volume mostly reflected the laptop
  sleeping, so the tuning was proven by counting only the excluded event
  types, which stopped exactly when the config changed.

## Layout

```
terraform/   AWS side: log groups, least-privilege IAM, SNS, detections (alerts.tf),
             hunting queries (queries.tf), budget
sysmon/      custom Sysmon configuration
agent/       CloudWatch Agent configuration (source of truth for the laptop)
docs/        setup walkthrough and redacted evidence screenshots
```

## Roadmap

- [x] Phase 0-1: log shipping, first detections (H01, H02), cost guardrail
- [x] Phase 2: System log shipping and five more host detections (P01-P05), validated
- [x] Phase 3: tune Sysmon with real data; hunting queries as code (case-insensitive coverage for P01/P03); alert triage log
- [ ] Phase 3+: ship successful logons (Security 4624) so logon-type checks do not depend on the laptop's local log
- [ ] Phase 4: replace the IAM access key with IAM Roles Anywhere (certificate auth)
- [ ] Phase 5: encrypted, versioned S3 backups with Object Lock
- [ ] Phase 6: weekly automated threat-hunt report (Lambda)

Setup: [docs/SETUP.md](docs/SETUP.md)
