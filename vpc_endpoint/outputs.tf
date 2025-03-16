output "endpoints" {
  description = "Array containing the full resource object and attributes for all endpoints created"
  value       = aws_vpc_endpoint.this
}

output "vpc_endpoint_id" {
  description = "The ID of the VPC endpoint."
  value       = aws_vpc_endpoint.this.id
}

output "vpc_endpoint_arn" {
  description = "The ARN of the VPC endpoint."
  value       = aws_vpc_endpoint.this.arn
}

output "vpc_endpoint_dns_entry" {
  description = "The DNS entries for the VPC endpoint."
  value       = aws_vpc_endpoint.this.dns_entry
}
################################################################################
# Security Group
################################################################################

# output "security_group_arn" {
#   description = "Amazon Resource Name (ARN) of the security group"
#   value       = try(aws_security_group.this[0].arn, null)
# }

# output "security_group_id" {
#   description = "ID of the security group"
#   value       = try(aws_security_group.this[0].id, null)
# }
