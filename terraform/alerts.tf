# ---------------------------------------------------------------------------
# Detections: metric filters turn matching log lines into numbers,
# alarms watch those numbers, SNS emails you.
# The agent sends events as XML, so filters match on the EventID element.
# ---------------------------------------------------------------------------

resource "aws_sns_topic" "alerts" {
  name = "${var.name_prefix}-alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

locals {
  detections = {
    # H01 - brute force: many failed logons in a short window.
    # MITRE ATT&CK T1110 Brute Force
    "H01-failed-logon-burst" = {
      log_group   = aws_cloudwatch_log_group.security.name
      pattern     = "\"<EventID>4625</EventID>\""
      threshold   = var.failed_logon_threshold
      description = "[MEDIUM] ${var.failed_logon_threshold}+ failed logons (4625) in 5 min. MITRE T1110 Brute Force."
    }
    # H02 - persistence / privilege: new local account, account enabled,
    # user added to a local group (e.g. Administrators), or security log cleared.
    # MITRE T1136 Create Account, T1098 Account Manipulation, T1070.001 Clear Windows Event Logs
    "H02-account-or-log-tampering" = {
      log_group   = aws_cloudwatch_log_group.security.name
      pattern     = "?\"<EventID>4720</EventID>\" ?\"<EventID>4722</EventID>\" ?\"<EventID>4732</EventID>\" ?\"<EventID>1102</EventID>\""
      threshold   = 1
      description = "[HIGH] Account created/enabled (4720/4722), added to local group (4732) or Security log cleared (1102). MITRE T1136, T1098, T1070.001."
    }
    # P04 - persistence: a new Windows service was installed.
    # System-log events carry a Qualifiers attribute (<EventID Qualifiers='16384'>),
    # so this pattern matches only the closing part of the element.
    # MITRE ATT&CK T1543.003 Create or Modify System Process: Windows Service
    "P04-new-service-install" = {
      log_group   = aws_cloudwatch_log_group.system.name
      pattern     = "\"7045</EventID>\""
      threshold   = 1
      description = "[MEDIUM] New Windows service installed (7045). MITRE T1543.003 Windows Service."
    }
    # P01 - execution: PowerShell launched with an encoded (base64) command.
    # Metric filters are case-sensitive, so common spellings are listed;
    # the hunting phase will add a case-insensitive Logs Insights regex.
    # MITRE ATT&CK T1059.001 Command and Scripting Interpreter: PowerShell
    "P01-encoded-powershell" = {
      log_group   = aws_cloudwatch_log_group.sysmon.name
      pattern     = "?\"-EncodedCommand\" ?\"-encodedcommand\" ?\"-enc \" ?\"-Enc \" ?\"-ENC \""
      threshold   = 1
      description = "[HIGH] PowerShell run with an encoded command (-EncodedCommand / -enc). MITRE T1059.001."
    }
    # P05 - persistence: a value was written to a Run / RunOnce registry key.
    # Sysmon Event 13 = registry value set. Terms are ANDed; "Run" also
    # covers RunOnce. Known tuning item: legitimate installers add Run keys too.
    # MITRE ATT&CK T1547.001 Boot or Logon Autostart Execution: Registry Run Keys
    "P05-run-key-persistence" = {
      log_group   = aws_cloudwatch_log_group.sysmon.name
      pattern     = "\"<EventID>13</EventID>\" \"CurrentVersion\" \"Run\""
      threshold   = 1
      description = "[MEDIUM] Registry Run/RunOnce key value set (Sysmon 13). MITRE T1547.001 Registry Run Keys."
    }
  }
}

resource "aws_cloudwatch_log_metric_filter" "detection" {
  for_each       = local.detections
  name           = "${var.name_prefix}-${each.key}"
  log_group_name = each.value.log_group
  pattern        = each.value.pattern

  metric_transformation {
    name          = each.key
    namespace     = "HomeSOC"
    value         = "1"
    default_value = "0"
  }
}

resource "aws_cloudwatch_metric_alarm" "detection" {
  for_each            = local.detections
  alarm_name          = "${var.name_prefix}-${each.key}"
  alarm_description   = each.value.description
  namespace           = "HomeSOC"
  metric_name         = each.key
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = each.value.threshold
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.alerts.arn]

  depends_on = [aws_cloudwatch_log_metric_filter.detection]
}