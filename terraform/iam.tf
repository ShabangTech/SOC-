# ---------------------------------------------------------------------------
# Least-privilege identity for the laptop CloudWatch Agent. Writes into the
# /hsoc/* log groups only - cannot read logs, delete, or touch other services.
# Access key created by hand (not in state) - see docs/SETUP.md.
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
      "${aws_cloudwatch_log_group.system.arn}:*",
    ]
  }
}

resource "aws_iam_user_policy" "ship_logs" {
  name   = "${var.name_prefix}-ship-logs"
  user   = aws_iam_user.shipper.name
  policy = data.aws_iam_policy_document.ship_logs.json
}

# ---------------------------------------------------------------------------
# Separate identity for the Kali purple-team box. Scoped to /hsoc/linux/* only:
# if the attack box is compromised these creds cannot read or alter the Windows
# logs. Wildcard covers auth + samba + any future linux group, no IAM change.
# ---------------------------------------------------------------------------

resource "aws_iam_user" "kali_shipper" {
  name = "${var.name_prefix}-kali-shipper"
  path = "/${var.name_prefix}/"
}

data "aws_iam_policy_document" "ship_kali_logs" {
  statement {
    sid = "WriteKaliLogsOnly"
    actions = [
      "logs:CreateLogStream",
      "logs:PutLogEvents",
      "logs:DescribeLogStreams",
    ]
    resources = [
      "${replace(aws_cloudwatch_log_group.linux_auth.arn, "/linux/auth", "/linux/*")}:*",
    ]
  }
}

resource "aws_iam_user_policy" "ship_kali_logs" {
  name   = "${var.name_prefix}-ship-kali-logs"
  user   = aws_iam_user.kali_shipper.name
  policy = data.aws_iam_policy_document.ship_kali_logs.json
}
