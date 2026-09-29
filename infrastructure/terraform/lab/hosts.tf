# Lab hosts. Which hosts exist, their addresses and their firewall rules come from data/ through
# the generated policy file; this file only decides how each one runs (ADR-009).

locals {
  # Instance size and purchase option per host. Spot everywhere except the domain controller:
  # an interruption in the middle of a session is acceptable for a lab host, not for AD.
  host_profiles = {
    "DC01"      = { instance_type = "t3.medium", spot = false, disk_gb = 30 }
    "WS-FIN01"  = { instance_type = "t3.medium", spot = true, disk_gb = 30 }
    "SIEM01"    = { instance_type = "t4g.large", spot = true, disk_gb = 30 }
    "WS-DEV01"  = { instance_type = "t4g.micro", spot = true, disk_gb = 8 }
    "GUEST01"   = { instance_type = "t4g.micro", spot = true, disk_gb = 8 }
    "APP-FIN01" = { instance_type = "t4g.small", spot = true, disk_gb = 10 }
  }

  hosts = {
    for name, host in local.policy.hosts : name => host if host.aws_phase <= var.lab_phase
  }

  ingress_rules = merge([
    for name, host in local.hosts : { for rule in host.ingress : "${name}|${rule.key}" => merge(rule, { host = name }) }
  ]...)
  egress_rules = merge([
    for name, host in local.hosts : { for rule in host.egress : "${name}|${rule.key}" => merge(rule, { host = name }) }
  ]...)
}

data "aws_ssm_parameter" "ubuntu_arm64" {
  name = "/aws/service/canonical/ubuntu/server/24.04/stable/current/arm64/hvm/ebs-gp3/ami-id"
}

data "aws_ssm_parameter" "windows_2022" {
  name = "/aws/service/ami-windows-latest/Windows_Server-2022-English-Full-Base"
}

# ------------------------------------------------------------------------------ security groups
resource "aws_security_group" "host" {
  for_each = local.hosts

  name        = "${var.project}-${lower(each.key)}"
  description = "${each.key}: rules generated from data/network-matrix.yaml"
  vpc_id      = aws_vpc.lab.id
  tags        = { Name = "${var.project}-${lower(each.key)}", AssetId = each.key }
}

resource "aws_vpc_security_group_ingress_rule" "host" {
  for_each = local.ingress_rules

  security_group_id = aws_security_group.host[each.value.host].id
  description       = join(", ", each.value.rules)
  cidr_ipv4         = each.value.cidr
  ip_protocol       = each.value.protocol
  from_port         = each.value.from_port
  to_port           = each.value.to_port
}

resource "aws_vpc_security_group_egress_rule" "host" {
  for_each = local.egress_rules

  security_group_id = aws_security_group.host[each.value.host].id
  description       = join(", ", each.value.rules)
  cidr_ipv4         = each.value.cidr
  ip_protocol       = each.value.protocol
  from_port         = each.value.from_port
  to_port           = each.value.to_port
}

# ------------------------------------------------------------------------------ SSM access
# Session Manager is the only way in: no SSH keys, no RDP from the internet, no public IPs.
data "aws_iam_policy_document" "ec2_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "ssm" {
  name               = "${var.project}-ssm-instance"
  assume_role_policy = data.aws_iam_policy_document.ec2_assume.json
}

resource "aws_iam_role_policy_attachment" "ssm" {
  role       = aws_iam_role.ssm.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_instance_profile" "ssm" {
  name = "${var.project}-ssm-instance"
  role = aws_iam_role.ssm.name
}

# DC01 only: the AD scripts (project-04-iam) store the passwords they generate under
# /<project>/ad/ in Parameter Store. No other host can read or write them.
data "aws_iam_policy_document" "ad_secrets" {
  statement {
    actions   = ["ssm:GetParameter", "ssm:PutParameter"]
    resources = ["arn:aws:ssm:${var.region}:${data.aws_caller_identity.current.account_id}:parameter/${var.project}/ad/*"]
  }
  statement {
    # SecureString parameters use the AWS managed key aws/ssm, only through Parameter Store.
    actions   = ["kms:Encrypt", "kms:Decrypt", "kms:GenerateDataKey"]
    resources = ["*"]
    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = ["ssm.${var.region}.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "domain_controller" {
  name               = "${var.project}-domain-controller"
  assume_role_policy = data.aws_iam_policy_document.ec2_assume.json
}

resource "aws_iam_role_policy_attachment" "domain_controller_ssm" {
  role       = aws_iam_role.domain_controller.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_role_policy" "domain_controller_secrets" {
  name   = "ad-secrets"
  role   = aws_iam_role.domain_controller.id
  policy = data.aws_iam_policy_document.ad_secrets.json
}

resource "aws_iam_instance_profile" "domain_controller" {
  name = "${var.project}-domain-controller"
  role = aws_iam_role.domain_controller.name
}

# ------------------------------------------------------------------------------ instances
resource "aws_instance" "host" {
  for_each = local.hosts

  ami                    = each.value.platform == "windows" ? data.aws_ssm_parameter.windows_2022.value : data.aws_ssm_parameter.ubuntu_arm64.value
  instance_type          = local.host_profiles[each.key].instance_type
  subnet_id              = aws_subnet.segment[each.value.segment].id
  private_ip             = each.value.ip
  vpc_security_group_ids = [aws_security_group.host[each.key].id]
  iam_instance_profile   = each.key == "DC01" ? aws_iam_instance_profile.domain_controller.name : aws_iam_instance_profile.ssm.name

  # Host names match the asset IDs so logs can be enriched from data/ (P05).
  user_data = each.value.platform == "windows" ? join("\n", [
    "<powershell>",
    "Rename-Computer -NewName '${each.key}' -Force -Restart",
    "</powershell>",
    ]) : join("\n", [
    "#cloud-config",
    "hostname: ${lower(each.key)}",
    "preserve_hostname: false",
  ])

  dynamic "instance_market_options" {
    for_each = local.host_profiles[each.key].spot ? [1] : []
    content {
      market_type = "spot"
      spot_options {
        spot_instance_type             = "persistent"
        instance_interruption_behavior = "stop"
      }
    }
  }

  metadata_options {
    http_tokens                 = "required"
    http_endpoint               = "enabled"
    http_put_response_hop_limit = 1
  }

  root_block_device {
    encrypted   = true
    volume_type = "gp3"
    volume_size = local.host_profiles[each.key].disk_gb
  }

  lifecycle {
    ignore_changes = [ami, user_data]
    precondition {
      condition     = contains(keys(local.host_profiles), each.key)
      error_message = "Add ${each.key} to host_profiles in hosts.tf."
    }
  }

  tags = {
    Name    = each.key
    AssetId = each.key
    Segment = each.value.segment
    Role    = "host"
  }
}
