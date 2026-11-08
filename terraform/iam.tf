# ---------------------------------------------------------------------------
# Least-privilege identity for the laptop's CloudWatch Agent.
# It can only write log streams/events into the /hsoc/* log groups - it
# cannot read logs, delete anything, or touch any other service.
#
# Phase 1 uses an IAM user. The access key is NOT created here (it would end
# up in Terraform state); create it yourself - see docs/SETUP.md.
# Phase 4 replaces this with IAM Roles Anywhere (certificate, no long-lived key).
# ---------------------------------------------------------------------------

resource "aws_iam_user" "shipper" {
  name = "${var.name_prefix}-laptop-shipper"
  path = "/${var.name_prefix}/"
}

data "aws_iam_policy_document" "ship_logs" {
  statement {
    sid = "WriteLaptopLogsOnly"
    actions = [
      "logs:CreateLogStream",
      "logs:PutLogEvents",
      "logs:DescribeLogStreams",
    ]
    resources = [
      "${aws_cloudwatch_log_group.security.arn}:*",
      "${aws_cloudwatch_log_group.sysmon.arn}:*",
    ]
  }
}

resource "aws_iam_user_policy" "ship_logs" {
  name   = "${var.name_prefix}-ship-logs"
  user   = aws_iam_user.shipper.name
  policy = data.aws_iam_policy_document.ship_logs.json
}
