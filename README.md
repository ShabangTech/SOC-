# SOC- : Home SOC on AWS

A personal Security Operations Center (SOC) for a Windows laptop, built on
AWS-native services instead of a SIEM license. Sysmon, the Windows Security
log and the Windows System log are shipped to Amazon CloudWatch Logs, where
metric filters and alarms detect suspicious activity and email an alert.
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

## Layout

```
terraform/   AWS side: log groups, least-privilege IAM, SNS, detections, budget
sysmon/      custom Sysmon configuration
agent/       CloudWatch Agent configuration (source of truth for the laptop)
docs/        setup walkthrough and redacted evidence screenshots
```

## Roadmap

- [x] Phase 0-1: log shipping, first detections (H01, H02), cost guardrail
- [x] Phase 2: System log shipping and five more host detections (P01-P05), validated
- [ ] Phase 3: tune Sysmon with real data; Logs Insights hunting queries (case-insensitive coverage for P01/P03)
- [ ] Phase 4: replace the IAM access key with IAM Roles Anywhere (certificate auth)
- [ ] Phase 5: encrypted, versioned S3 backups with Object Lock
- [ ] Phase 6: weekly automated threat-hunt report (Lambda)

Setup: [docs/SETUP.md](docs/SETUP.md)
