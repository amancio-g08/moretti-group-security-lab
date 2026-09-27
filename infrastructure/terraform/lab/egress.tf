# Egress through a NAT instance (ADR-004, decided in ADR-009): a t4g.nano doing source NAT
# instead of a NAT Gateway, at a fraction of the hourly cost. It exists only while
# enable_egress = true.

locals {
  # Every port that some host may use towards the internet, per the matrix. The NAT instance
  # accepts and forwards only these.
  internet_ports = distinct(flatten([
    for host in values(local.policy.hosts) : [
      for rule in host.egress : {
        protocol  = rule.protocol
        from_port = rule.from_port
        to_port   = rule.to_port
      } if rule.cidr == "0.0.0.0/0"
    ]
  ]))
  internet_port_map = {
    for port in local.internet_ports : "${port.protocol}-${port.from_port}-${port.to_port}" => port
  }
}

data "aws_ssm_parameter" "al2023_arm64" {
  name = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-arm64"
}

resource "aws_security_group" "nat" {
  name        = "${var.project}-nat"
  description = "NAT instance: forwards only the internet ports allowed by the matrix"
  vpc_id      = aws_vpc.lab.id
  tags        = { Name = "${var.project}-nat" }
}

resource "aws_vpc_security_group_ingress_rule" "nat" {
  for_each = local.internet_port_map

  security_group_id = aws_security_group.nat.id
  description       = "From lab segments to the internet"
  cidr_ipv4         = var.vpc_cidr
  ip_protocol       = each.value.protocol
  from_port         = each.value.from_port
  to_port           = each.value.to_port
}

resource "aws_vpc_security_group_egress_rule" "nat" {
  for_each = local.internet_port_map

  security_group_id = aws_security_group.nat.id
  description       = "To the internet"
  cidr_ipv4         = "0.0.0.0/0"
  ip_protocol       = each.value.protocol
  from_port         = each.value.from_port
  to_port           = each.value.to_port
}

resource "aws_instance" "nat" {
  count = var.enable_egress ? 1 : 0

  ami                         = data.aws_ssm_parameter.al2023_arm64.value
  instance_type               = "t4g.nano"
  subnet_id                   = aws_subnet.transit.id
  vpc_security_group_ids      = [aws_security_group.nat.id]
  associate_public_ip_address = true
  source_dest_check           = false
  iam_instance_profile        = aws_iam_instance_profile.ssm.name

  user_data = <<-EOT
    #!/bin/bash
    set -euo pipefail
    dnf install -y nftables
    echo 'net.ipv4.ip_forward = 1' > /etc/sysctl.d/90-nat.conf
    sysctl --system
    iface=$(ip route show default | awk '{print $5; exit}')
    nft add table ip nat
    nft 'add chain ip nat postrouting { type nat hook postrouting priority 100 ; }'
    nft add rule ip nat postrouting oifname "$iface" ip saddr ${var.vpc_cidr} masquerade
    nft list ruleset > /etc/sysconfig/nftables.conf
    systemctl enable --now nftables
  EOT

  metadata_options {
    http_tokens                 = "required"
    http_endpoint               = "enabled"
    http_put_response_hop_limit = 1
  }

  root_block_device {
    encrypted   = true
    volume_type = "gp3"
  }

  lifecycle {
    ignore_changes = [ami] # a newer AMI must not replace the instance on every plan
  }

  tags = { Name = "${var.project}-nat", Role = "nat" }
}

resource "aws_route" "private_default" {
  count = var.enable_egress ? 1 : 0

  route_table_id         = aws_route_table.private.id
  destination_cidr_block = "0.0.0.0/0"
  network_interface_id   = aws_instance.nat[0].primary_network_interface_id
}
