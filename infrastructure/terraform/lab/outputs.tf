output "hosts" {
  description = "Deployed hosts: instance ID and private address."
  value       = { for name, instance in aws_instance.host : name => { id = instance.id, ip = instance.private_ip } }
}

output "nat_instance_id" {
  value = one(aws_instance.nat[*].id)
}

output "ssm_session_commands" {
  description = "Open a shell on a host through Session Manager (no open ports)."
  value = {
    for name, instance in aws_instance.host :
    name => "aws ssm start-session --region ${var.region} --target ${instance.id}"
  }
}
