# SOC- : Home SOC on AWS

A personal Security Operations Center (SOC) for a Windows laptop, built on
AWS-native services instead of a SIEM license. Sysmon and the Windows Security
log are shipped to Amazon CloudWatch Logs, where metric filters and alarms
detect suspicious activity and email an alert. Everything is defined in
Terraform and designed to run for about $0-5 a month.

```
Windows laptop                                   AWS (us-east-2)
+-------------------------+     HTTPS     +--------------------------------------+
| Sysmon (custom config)  |               | CloudWatch Logs                      |
| Windows Security log    | ------------> |   /hsoc/windows/sysmon               |
| CloudWatch Agent        |  least-priv.  |   /hsoc/windows/security             |
|  (event ID filtering)   |  IAM identity |        |                             |
+-------------------------+               |   metric filters -> alarms -> SNS ---+--> email
                                          | AWS Budgets ($5/month guardrail) ----+--> email
                                          +--------------------------------------+
```

## Detections

| ID  | Detects | Windows events | MITRE ATT&CK | Alert when |
|-----|---------|----------------|--------------|------------|
| H01 | Brute-force logon attempts | 4625 | T1110 Brute Force | 5+ in 5 min |
| H02 | New/enabled account, added to a local group, Security log cleared | 4720, 4722, 4732, 1102 | T1136, T1098, T1070.001 | any |

Sysmon also records process creation, network connections from commonly
abused tools, and registry persistence locations for threat hunting
(see [sysmon/sysmon-homesoc.xml](sysmon/sysmon-homesoc.xml)).

## Layout

```
terraform/   AWS side: log groups, least-privilege IAM, SNS, detections, budget
sysmon/      custom Sysmon configuration
agent/       CloudWatch Agent configuration
docs/        setup walkthrough and results
```

## Roadmap

- [x] Phase 0-1: log shipping, first detections, cost guardrail
- [ ] Phase 2: more detections (encoded PowerShell, new services, Office spawning shells)
- [ ] Phase 3: tune Sysmon with real data; Logs Insights hunting queries
- [ ] Phase 4: replace the IAM access key with IAM Roles Anywhere (certificate auth)
- [ ] Phase 5: encrypted, versioned S3 backups with Object Lock
- [ ] Phase 6: weekly automated threat-hunt report (Lambda)

Setup: [docs/SETUP.md](docs/SETUP.md)
