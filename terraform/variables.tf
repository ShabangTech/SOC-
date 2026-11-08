variable "region" {
  description = "AWS region for all Home SOC resources"
  type        = string
  default     = "us-east-2"
}

variable "name_prefix" {
  description = "Prefix for every resource name"
  type        = string
  default     = "hsoc"
}

variable "alert_email" {
  description = "Email address that receives alarm and budget notifications"
  type        = string
}

variable "log_retention_days" {
  description = "How long CloudWatch keeps the laptop logs (shorter = cheaper)"
  type        = number
  default     = 30
}

variable "monthly_budget_usd" {
  description = "Monthly cost budget; you get an email at 80% and 100%"
  type        = number
  default     = 5
}

variable "failed_logon_threshold" {
  description = "Failed logons (Event ID 4625) within 5 minutes that count as a brute-force attempt"
  type        = number
  default     = 5
}
