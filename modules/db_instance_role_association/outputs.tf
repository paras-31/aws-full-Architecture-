output "db_instance_role_association_id" {
  description = "DB Instance Identifier and IAM Role ARN separated by a comma"
  value       = try(aws_db_instance_role_association.this[0].id, "")
}

output "rds_secret_access_role_arn" {
  description = "The ARN of the IAM role created for RDS secret access."
  value       = aws_iam_role.rds_secret_access_role.arn
}