output "cloudtrail_name" {
  description = "The name of the Cloudtrail."
  value       = aws_cloudtrail.this.id
}

output "cloudtrail_arn" {
  description = "The Amazon Resource Name of the Cloudtrail."
  value       = aws_cloudtrail.this.arn
}

output "cloudwatch_logs_role_arn" {
  description = "The IAM role ARN for the CloudWatch Logs endpoint to assume to write to a log group."
  value       = var.enable_cloudwatch_logs ? aws_iam_role.cloudtrail_cloudwatch_role[0].arn : null
}

output "cloudwatch_logs_group_arn" {
  description = "The log group ARN to which CloudTrail logs are delivered"
  value       = var.enable_cloudwatch_logs ? "${aws_cloudwatch_log_group.cloudtrail[0].arn}:*" : null
}

output "cloudwatch_logs_group_name" {
  description = "The log group NAME to which CloudTrail logs are delivered"
  value       = var.enable_cloudwatch_logs ? "${aws_cloudwatch_log_group.cloudtrail[0].name}" : null
}


