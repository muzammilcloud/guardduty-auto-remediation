variable "aws_region" {
  type    = string
  default = "us-east-1"
}

variable "name_prefix" {
  type    = string
  default = "gd-autoremediate"
}

variable "alert_email" {
  type        = string
  description = "Email address that receives remediation alerts"

  validation {
    condition     = can(regex("^[^@\\s]+@[^@\\s]+\\.[^@\\s]+$", var.alert_email))
    error_message = "alert_email must be a valid email address."
  }
}

variable "mode" {
  type        = string
  default     = "enforce"
  description = "enforce = take action, alert-only = notify without changing anything"

  validation {
    condition     = contains(["enforce", "alert-only"], var.mode)
    error_message = "mode must be \"enforce\" or \"alert-only\"."
  }
}

variable "min_severity" {
  type        = number
  default     = 7
  description = "Lowest GuardDuty severity that triggers the function (7 = High)"

  validation {
    condition     = var.min_severity >= 1 && var.min_severity <= 10
    error_message = "min_severity must be between 1 and 10."
  }
}

variable "create_detector" {
  type        = bool
  default     = true
  description = "Set to false if GuardDuty is already enabled in this Region"
}

variable "create_test_user" {
  type        = bool
  default     = true
  description = "Create a permissionless IAM user with an access key for safe testing"
}
