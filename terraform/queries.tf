# ---------------------------------------------------------------------------
# Threat-hunting queries (Phase 3), saved as CloudWatch Logs Insights
# query definitions. They appear under "Saved queries" in the console,
# grouped in a folder named after var.name_prefix.
#
# Alarms (alerts.tf) use metric filters, which are case-sensitive and cannot
# mix AND with OR. Hunts run on demand and use case-insensitive regular
# expressions (?i), so they close the gaps the alarms cannot cover.
#
# Every exclusion below was verified with one week of real data
# (see the Alert Log in the Use Case Playbook: H-001, H-002).
# ---------------------------------------------------------------------------

locals {
  hunts = {

    # Case-insensitive version of alarm P01. PowerShell accepts any prefix
    # of -EncodedCommand (-e, -en, -enc ... -encodedcommand) and -ec, with
    # - or / and in any letter case. MITRE T1059.001, T1027.
    "H-Q01-encoded-powershell-any-case" = {
      log_groups = [aws_cloudwatch_log_group.sysmon.name]
      query      = <<-EOT
        parse @message "<EventID>*</EventID>" as eid
        | parse @message "<Data Name='Image'>*</Data>" as image
        | parse @message "<Data Name='ParentImage'>*</Data>" as parent
        | parse @message "<Data Name='CommandLine'>*</Data>" as cmd
        | filter eid = "1" and image like /(?i)(powershell|pwsh)\.exe/ and cmd like /(?i)\s[-\/]e(c|n[a-z]*)?\s/
        | display @timestamp, parent, cmd
        | sort @timestamp desc
      EOT
    }

    # Case-insensitive version of alarm P03, plus other certutil abuse:
    # download (-urlcache, -verifyctl) and decode/encode payloads (T1140).
    # Matches OriginalFileName too, so a renamed copy is still found.
    # Lenovo Vantage's normal certutil runs use none of these flags.
    # MITRE T1105, T1140.
    "H-Q02-certutil-abuse-any-case" = {
      log_groups = [aws_cloudwatch_log_group.sysmon.name]
      query      = <<-EOT
        parse @message "<EventID>*</EventID>" as eid
        | parse @message "<Data Name='Image'>*</Data>" as image
        | parse @message "<Data Name='OriginalFileName'>*</Data>" as original
        | parse @message "<Data Name='ParentImage'>*</Data>" as parent
        | parse @message "<Data Name='CommandLine'>*</Data>" as cmd
        | filter eid = "1" and (image like /(?i)certutil\.exe/ or original like /(?i)certutil\.exe/) and cmd like /(?i)[-\/](urlcache|verifyctl|decode|decodehex|encode)/
        | display @timestamp, image, parent, cmd
        | sort @timestamp desc
      EOT
    }

    # netsh / route changing DNS, routes, firewall or port forwarding.
    # Removed as verified NordVPN activity:
    #   - anything launched by the NordVPN service (connect AND disconnect
    #     commands; validation on 2026-11-17 found its disconnect commands,
    #     e.g. "set dnsservers ... address=none", carry no NordVPN address)
    #   - its connect fingerprints when the parent is missing ("-"):
    #     DNS servers 103.86.96.100 / 103.86.99.100, tunnel addresses
    #     10.3.0.x, 10.5.0.x, 100.64.0.1
    # Unverifiable "-" parent commands without those fingerprints stay
    # visible on purpose. Read-only "show" commands are ignored.
    # MITRE T1562.004, T1090, T1565.
    "H-Q03-network-changes-not-nordvpn" = {
      log_groups = [aws_cloudwatch_log_group.sysmon.name]
      query      = <<-EOT
        parse @message "<EventID>*</EventID>" as eid
        | parse @message "<Data Name='Image'>*</Data>" as image
        | parse @message "<Data Name='ParentImage'>*</Data>" as parent
        | parse @message "<Data Name='CommandLine'>*</Data>" as cmd
        | filter eid = "1" and image like /(?i)(netsh|route)\.exe/
        | filter cmd like /(?i)\b(add|set|delete|change|advfirewall|portproxy|dnsservers)\b/
        | filter parent not like /(?i)\\Program Files\\NordVPN\\nordvpn-service\.exe/
        | filter cmd not like /103\.86\.9[69]\.100|\b10\.[35]\.0\.\d{1,3}\b|\b100\.64\.0\.1\b/
        | display @timestamp, parent, cmd
        | sort @timestamp desc
      EOT
    }

    # Sysmon v2 drops svchost.exe started by services.exe, so ANY svchost
    # process start left in the log is unusual: wrong parent or wrong
    # folder. MITRE T1036.005 Masquerading: Match Legitimate Name.
    "H-Q04-svchost-unusual-parent-or-path" = {
      log_groups = [aws_cloudwatch_log_group.sysmon.name]
      query      = <<-EOT
        parse @message "<EventID>*</EventID>" as eid
        | parse @message "<Data Name='Image'>*</Data>" as image
        | parse @message "<Data Name='ParentImage'>*</Data>" as parent
        | filter eid = "1" and image like /(?i)svchost\.exe/
        | stats count(*) as events by image, parent
        | sort events desc
      EOT
    }

    # Sysmon v2 drops remote threads from the real csrss.exe, so what is
    # left is rare. Any target of lsass.exe (credential theft) is urgent.
    # MITRE T1055 Process Injection, T1003.001 LSASS Memory.
    "H-Q05-remote-thread-injection" = {
      log_groups = [aws_cloudwatch_log_group.sysmon.name]
      query      = <<-EOT
        parse @message "<EventID>*</EventID>" as eid
        | parse @message "<Data Name='SourceImage'>*</Data>" as src
        | parse @message "<Data Name='TargetImage'>*</Data>" as tgt
        | filter eid = "8"
        | stats count(*) as events, min(@timestamp) as first_seen, max(@timestamp) as last_seen by src, tgt
        | sort events desc
      EOT
    }

    # L-Q01 - investigative companion to alarm L01. Pulls the username and
    # source IP out of each failed SMB login so a brute-force burst shows
    # who, from where, and how many per 5-minute window. Loopback lab today;
    # generalises to real sources. MITRE T1110 Brute Force.
    "L-Q01-smb-brute-force-by-source" = {
      log_groups = [aws_cloudwatch_log_group.linux_samba.name]
      query      = <<-EOT
        filter @message like /NT_STATUS_WRONG_PASSWORD|NT_STATUS_NO_SUCH_USER/
        | parse @message /remote host \[ipv4:(?<src_ip>[0-9.]+):(?<src_port>[0-9]+)\]/
        | parse @message /\\\[(?<user>[^\]]+)\]/
        | stats count(*) as failures by user, src_ip, bin(5m)
        | sort failures desc
      EOT
    }

    # Tuning baseline: which event types and programs fill the Sysmon log.
    # Re-run after any Sysmon config change to measure the effect.
    "T-Q01-sysmon-volume-by-event" = {
      log_groups = [aws_cloudwatch_log_group.sysmon.name]
      query      = <<-EOT
        parse @message "<EventID>*</EventID>" as eid
        | stats count(*) as events, sum(strlen(@message)) as bytes by eid
        | sort bytes desc
      EOT
    }

    # Sysmon health: Event 255 is a Sysmon internal error.
    "T-Q02-sysmon-errors" = {
      log_groups = [aws_cloudwatch_log_group.sysmon.name]
      query      = <<-EOT
        parse @message "<EventID>*</EventID>" as eid
        | filter eid = "255"
        | display @timestamp, @message
        | sort @timestamp desc
      EOT
    }
  }
}

resource "aws_cloudwatch_query_definition" "hunt" {
  for_each = local.hunts

  name            = "${var.name_prefix}/${each.key}"
  log_group_names = each.value.log_groups
  query_string    = each.value.query
}
