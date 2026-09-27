# Nightly stop of every lab instance (cost guardrail, ADR-009). Stopping is safe: disks are
# kept, and scripts/lab-up.sh starts everything again.

locals {
  instance_ids = concat([for i in aws_instance.host : i.id], [for i in aws_instance.nat : i.id])
}

data "aws_iam_policy_document" "scheduler_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["scheduler.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }
  }
}

data "aws_iam_policy_document" "stop_instances" {
  statement {
    actions   = ["ec2:StopInstances"]
    resources = ["arn:aws:ec2:${var.region}:${data.aws_caller_identity.current.account_id}:instance/*"]
    condition {
      test     = "StringEquals"
      variable = "aws:ResourceTag/Project"
      values   = [var.project]
    }
  }
}

resource "aws_iam_role" "scheduler" {
  name               = "${var.project}-nightly-stop"
  assume_role_policy = data.aws_iam_policy_document.scheduler_assume.json
}

resource "aws_iam_role_policy" "scheduler" {
  name   = "stop-lab-instances"
  role   = aws_iam_role.scheduler.id
  policy = data.aws_iam_policy_document.stop_instances.json
}

resource "aws_scheduler_schedule" "nightly_stop" {
  count = length(local.instance_ids) > 0 ? 1 : 0

  name                         = "${var.project}-nightly-stop"
  schedule_expression          = var.shutdown_schedule
  schedule_expression_timezone = var.shutdown_timezone

  flexible_time_window {
    mode = "OFF"
  }

  target {
    arn      = "arn:aws:scheduler:::aws-sdk:ec2:stopInstances"
    role_arn = aws_iam_role.scheduler.arn
    input    = jsonencode({ InstanceIds = local.instance_ids })
  }
}
