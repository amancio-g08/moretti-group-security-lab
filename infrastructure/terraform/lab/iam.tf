# Instance roles. Session Manager is the only way in (no SSH keys, no RDP from the internet, no
# public IPs), so every role has the SSM core policy. Anything more is granted per kind of host:
#
#   basic              GUEST01 and the NAT instance: SSM only
#   agent              Wazuh agents: read the agent enrollment password, nothing else
#   domain_controller  DC01: agent + store the AD passwords it generates (project-04-iam)
#   siem               SIEM01: store the Wazuh passwords, read CloudTrail and VPC Flow Logs
#
# GUEST01 is the untrusted host: it gets no secret at all, not even the enrollment password.

locals {
  parameter_arn = "arn:aws:ssm:${var.region}:${data.aws_caller_identity.current.account_id}:parameter/${var.project}"
  role_policies = {
    basic             = []
    agent             = ["wazuh_enrollment"]
    domain_controller = ["wazuh_enrollment", "ad_secrets"]
    siem              = ["wazuh_secrets", "siem_logs"]
  }
  role_policy_pairs = merge([
    for role, policies in local.role_policies : { for policy in policies : "${role}.${policy}" => { role = role, policy = policy } }
  ]...)
}

data "aws_iam_policy_document" "ec2_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

# SecureString parameters use the AWS managed key aws/ssm, only through Parameter Store.
data "aws_iam_policy_document" "secure_string" {
  statement {
    actions   = ["kms:Encrypt", "kms:Decrypt", "kms:GenerateDataKey"]
    resources = ["*"]
    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = ["ssm.${var.region}.amazonaws.com"]
    }
  }
}

data "aws_iam_policy_document" "wazuh_enrollment" {
  source_policy_documents = [data.aws_iam_policy_document.secure_string.json]
  statement {
    actions   = ["ssm:GetParameter"]
    resources = ["${local.parameter_arn}/wazuh/enrollment-password"]
  }
}

data "aws_iam_policy_document" "ad_secrets" {
  source_policy_documents = [data.aws_iam_policy_document.secure_string.json]
  statement {
    actions   = ["ssm:GetParameter", "ssm:PutParameter"]
    resources = ["${local.parameter_arn}/ad/*"]
  }
}

data "aws_iam_policy_document" "wazuh_secrets" {
  source_policy_documents = [data.aws_iam_policy_document.secure_string.json]
  statement {
    actions   = ["ssm:GetParameter", "ssm:PutParameter"]
    resources = ["${local.parameter_arn}/wazuh/*"]
  }
}

# Read-only access to the evidence, for the Wazuh AWS module (phase 6).
data "aws_iam_policy_document" "siem_logs" {
  statement {
    actions   = ["s3:ListBucket"]
    resources = [data.aws_s3_bucket.logs.arn]
  }
  statement {
    actions   = ["s3:GetObject"]
    resources = ["${data.aws_s3_bucket.logs.arn}/cloudtrail/*", "${data.aws_s3_bucket.logs.arn}/flowlogs/*"]
  }
  statement {
    # The module lists the VPC's flow logs to know which objects to read.
    actions   = ["ec2:DescribeFlowLogs"]
    resources = ["*"]
  }
}

locals {
  policy_json = {
    wazuh_enrollment = data.aws_iam_policy_document.wazuh_enrollment.json
    ad_secrets       = data.aws_iam_policy_document.ad_secrets.json
    wazuh_secrets    = data.aws_iam_policy_document.wazuh_secrets.json
    siem_logs        = data.aws_iam_policy_document.siem_logs.json
  }
}

resource "aws_iam_role" "role" {
  for_each = local.role_policies

  name               = "${var.project}-${replace(each.key, "_", "-")}"
  assume_role_policy = data.aws_iam_policy_document.ec2_assume.json
}

resource "aws_iam_role_policy_attachment" "ssm_core" {
  for_each = local.role_policies

  role       = aws_iam_role.role[each.key].name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_role_policy" "grant" {
  for_each = local.role_policy_pairs

  name   = replace(each.value.policy, "_", "-")
  role   = aws_iam_role.role[each.value.role].id
  policy = local.policy_json[each.value.policy]
}

resource "aws_iam_instance_profile" "role" {
  for_each = local.role_policies

  name = "${var.project}-${replace(each.key, "_", "-")}"
  role = aws_iam_role.role[each.key].name
}
