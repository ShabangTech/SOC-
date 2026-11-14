output "shipper_user" {
  description = "IAM user the laptop agent signs in as (create its access key yourself)"
  value       = aws_iam_user.shipper.name
}

output "log_groups" {
  value = [
    aws_cloudwatch_log_group.security.name,
    aws_cloudwatch_log_group.sysmon.name,
    aws_cloudwatch_log_group.system.name,
  ]
}

output "alarms" {
  value = [for a in aws_cloudwatch_metric_alarm.detection : a.alarm_name]
}
