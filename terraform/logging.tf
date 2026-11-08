# ---------------------------------------------------------------------------
# Log groups the CloudWatch Agent on the laptop writes to.
# Terraform owns them so retention is enforced and the agent never needs
# permission to create log groups.
# ---------------------------------------------------------------------------

resource "aws_cloudwatch_log_group" "security" {
  name              = "/${var.name_prefix}/windows/security"
  retention_in_days = var.log_retention_days
}

resource "aws_cloudwatch_log_group" "sysmon" {
  name              = "/${var.name_prefix}/windows/sysmon"
  retention_in_days = var.log_retention_days
}
