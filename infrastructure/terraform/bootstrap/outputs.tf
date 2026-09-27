output "log_bucket" {
  description = "Bucket that receives CloudTrail and VPC Flow Logs (read by the lab stack by name)."
  value       = aws_s3_bucket.logs.id
}

output "trail_name" {
  value = aws_cloudtrail.main.name
}

output "budget_name" {
  value = aws_budgets_budget.monthly.name
}
