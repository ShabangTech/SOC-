# ---------------------------------------------------------------------------
# Log groups the CloudWatch Agent writes to. Terraform owns them so retention
# is enforced and the agent never needs permission to create log groups.
# ---------------------------------------------------------------------------

resource "aws_cloudwatch_log_group" "security" {
  name              = "/${var.name_prefix}/windows/security"
  retention_in_days = var.log_retention_days
}

resource "aws_cloudwatch_log_group" "sysmon" {
  name              = "/${var.name_prefix}/windows/sysmon"
  retention_in_days = var.log_retention_days
}

resource "aws_cloudwatch_log_group" "system" {
  name              = "/${var.name_prefix}/windows/system"
  retention_in_days = var.log_retention_days
}

resource "aws_cloudwatch_log_group" "linux_auth" {
  name              = "/${var.name_prefix}/linux/auth"
  retention_in_days = var.log_retention_days
}

resource "aws_cloudwatch_log_group" "linux_samba" {
  name              = "/${var.name_prefix}/linux/samba"
  retention_in_days = var.log_retention_days
}
