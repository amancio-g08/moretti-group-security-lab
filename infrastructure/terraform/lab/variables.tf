variable "region" {
  description = "AWS region of the lab (Phase 4 decision: us-east-1, the cheapest)."
  type        = string
  default     = "us-east-1"
}

variable "availability_zone" {
  description = "The single Availability Zone of the lab (ADR-003)."
  type        = string
  default     = "us-east-1a"
}

variable "project" {
  description = "Tag and name prefix; must match the bootstrap stack."
  type        = string
  default     = "moretti-group-lab"
}

variable "vpc_cidr" {
  description = "Address space of the lab. Segment subnets come from data/network-matrix.yaml."
  type        = string
  default     = "10.10.0.0/16"
}

variable "transit_cidr" {
  description = "Public subnet for the NAT instance, inside the matrix TRANSIT range."
  type        = string
  default     = "10.10.255.0/28"
}

variable "lab_phase" {
  description = "Roadmap phase: hosts whose aws_phase (data/assets.yaml) is <= this value are deployed."
  type        = number
  default     = 4

  validation {
    condition     = var.lab_phase >= 4 && var.lab_phase <= 9
    error_message = "lab_phase must be between 4 and 9."
  }
}

variable "enable_egress" {
  description = "Create the NAT instance (ADR-004). Without it hosts have no internet and no SSM access."
  type        = bool
  default     = true
}

variable "shutdown_schedule" {
  description = "EventBridge Scheduler expression that stops every lab instance."
  type        = string
  default     = "cron(0 23 * * ? *)"
}

variable "shutdown_timezone" {
  description = "Time zone of shutdown_schedule."
  type        = string
  default     = "America/Sao_Paulo"
}
