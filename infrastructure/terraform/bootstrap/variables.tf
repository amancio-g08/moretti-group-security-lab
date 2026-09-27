variable "region" {
  description = "AWS region of the lab (Phase 4 decision: us-east-1, the cheapest)."
  type        = string
  default     = "us-east-1"
}

variable "project" {
  description = "Tag and name prefix for every lab resource."
  type        = string
  default     = "moretti-group-lab"
}

variable "alert_email" {
  description = "E-mail address that receives budget alerts. Set it in terraform.tfvars (not committed)."
  type        = string

  validation {
    condition     = can(regex("^[^@\\s]+@[^@\\s]+\\.[^@\\s]+$", var.alert_email))
    error_message = "alert_email must be an e-mail address."
  }
}

variable "monthly_budget_usd" {
  description = "Monthly cost budget. Alerts fire at one third, two thirds and all of it."
  type        = number
  default     = 30
}

variable "log_retention_days" {
  description = "Days before CloudTrail and VPC Flow Log objects are deleted."
  type        = number
  default     = 30
}

variable "allow_log_bucket_destroy" {
  description = "Allow terraform destroy to delete the log bucket with its contents (final teardown only)."
  type        = bool
  default     = false
}
