# Offline plan tests: the AWS provider is mocked, so no account or credentials are needed.
# Run: terraform init -backend=false && terraform test

mock_provider "aws" {
  mock_data "aws_caller_identity" {
    defaults = { account_id = "123456789012" }
  }
  mock_data "aws_ssm_parameter" {
    defaults = { value = "ami-0123456789abcdef0" }
  }
  mock_data "aws_s3_bucket" {
    defaults = { arn = "arn:aws:s3:::moretti-group-lab-logs-123456789012" }
  }
  mock_data "aws_iam_policy_document" {
    defaults = { json = "{}" }
  }
}

run "phase_4_deploys_only_the_two_linux_hosts" {
  command = plan

  assert {
    condition     = toset(keys(aws_instance.host)) == toset(["WS-DEV01", "GUEST01"])
    error_message = "Phase 4 must deploy exactly WS-DEV01 and GUEST01."
  }
  assert {
    condition     = length(aws_instance.nat) == 1 && length(aws_route.private_default) == 1
    error_message = "Egress is enabled by default."
  }
  assert {
    condition     = aws_instance.host["GUEST01"].private_ip == "10.10.90.10"
    error_message = "Hosts must keep the addresses from data/assets.yaml."
  }
  assert {
    condition     = length(aws_subnet.segment) == 5
    error_message = "One subnet per AWS segment of the matrix."
  }
}

run "no_host_accepts_traffic_from_the_internet" {
  command = plan

  variables {
    lab_phase = 9
  }

  assert {
    condition     = alltrue([for rule in aws_vpc_security_group_ingress_rule.host : rule.cidr_ipv4 != "0.0.0.0/0"])
    error_message = "No Security Group may accept traffic from 0.0.0.0/0 (NM-002)."
  }
  assert {
    condition     = alltrue([for rule in aws_vpc_security_group_ingress_rule.nat : rule.cidr_ipv4 == "10.10.0.0/16"])
    error_message = "The NAT instance accepts traffic from the lab only."
  }
}

run "workstations_accept_no_inbound_traffic" {
  command = plan

  variables {
    lab_phase = 9
  }

  assert {
    condition = length([
      for key, rule in aws_vpc_security_group_ingress_rule.host : key
      if contains(["WS-DEV01", "WS-FIN01", "GUEST01"], split("|", key)[0])
    ]) == 0
    error_message = "Workstations and the guest host accept no inbound traffic (NM-004, NM-060)."
  }
  assert {
    condition     = length(aws_instance.host) == 6
    error_message = "Phase 9 deploys every AWS host."
  }
  assert {
    condition     = length(aws_instance.host["DC01"].instance_market_options) == 0 && length(aws_instance.host["GUEST01"].instance_market_options) == 1
    error_message = "Every host runs on Spot except the domain controller (ADR-009)."
  }
  assert {
    condition     = aws_instance.host["DC01"].iam_instance_profile == "moretti-group-lab-domain-controller" && aws_instance.host["WS-FIN01"].iam_instance_profile == "moretti-group-lab-ssm-instance"
    error_message = "Only DC01 may store the AD passwords in Parameter Store."
  }
}

run "egress_disabled_removes_the_nat_instance" {
  command = plan

  variables {
    enable_egress = false
  }

  assert {
    condition     = length(aws_instance.nat) == 0 && length(aws_route.private_default) == 0
    error_message = "enable_egress = false must remove the NAT instance and the default route."
  }
}
