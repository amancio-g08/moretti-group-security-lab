# Segments and their addresses come from the matrix through the generated policy file, so the
# AWS subnets can never drift from data/network-matrix.yaml (ADR-001).

locals {
  policy = jsondecode(file("${path.module}/generated/security-groups.json"))
}

resource "aws_vpc" "lab" {
  cidr_block           = var.vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = { Name = var.project }
}

# The default security group allows traffic between its members; strip every rule so nothing
# can use it by accident.
resource "aws_default_security_group" "default" {
  vpc_id = aws_vpc.lab.id
  tags   = { Name = "${var.project}-default-unused" }
}

resource "aws_subnet" "segment" {
  for_each = local.policy.segments

  vpc_id            = aws_vpc.lab.id
  cidr_block        = each.value.cidr
  availability_zone = var.availability_zone

  tags = { Name = "${var.project}-${each.key}", Segment = each.value.name }
}

resource "aws_route_table" "private" {
  vpc_id = aws_vpc.lab.id
  tags   = { Name = "${var.project}-private" }
}

resource "aws_route_table_association" "segment" {
  for_each = aws_subnet.segment

  subnet_id      = each.value.id
  route_table_id = aws_route_table.private.id
}

# ------------------------------------------------------------------------------ transit (public)
resource "aws_internet_gateway" "lab" {
  vpc_id = aws_vpc.lab.id
  tags   = { Name = var.project }
}

resource "aws_subnet" "transit" {
  vpc_id            = aws_vpc.lab.id
  cidr_block        = var.transit_cidr
  availability_zone = var.availability_zone

  tags = { Name = "${var.project}-transit", Segment = "TRANSIT" }
}

resource "aws_route_table" "transit" {
  vpc_id = aws_vpc.lab.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.lab.id
  }

  tags = { Name = "${var.project}-transit" }
}

resource "aws_route_table_association" "transit" {
  subnet_id      = aws_subnet.transit.id
  route_table_id = aws_route_table.transit.id
}

# ------------------------------------------------------------------------------ flow logs
data "aws_caller_identity" "current" {}

data "aws_s3_bucket" "logs" {
  # Created by the bootstrap stack; this lookup fails early if bootstrap was not applied.
  bucket = "${var.project}-logs-${data.aws_caller_identity.current.account_id}"
}

resource "aws_flow_log" "vpc" {
  vpc_id                   = aws_vpc.lab.id
  traffic_type             = "ALL"
  log_destination_type     = "s3"
  log_destination          = "${data.aws_s3_bucket.logs.arn}/flowlogs"
  max_aggregation_interval = 60

  tags = { Name = "${var.project}-flow-logs" }
}
