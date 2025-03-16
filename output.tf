# output "sg_rules" {
#   value = var.Ec2["instance1"].ingress_rules
# }

# output "sg_rules-2" {
#   value = flatten(var.Ec2["instance1"].ingress_rules)
# }

# output "key_name" {
#   value = module.key_pair.aws_key_pair_name
# }


# output "key_id" {
#   value = module.kms.key_id
  
# }

# output "key_arn" {
#   value = module.kms.key_arn
  
# }


# output "s3_bucket_names" {
#   description = "Names of the created S3 buckets"
#   value       = { for k, v in module.s3 : k => v.bucket_name }
# }

# output "s3_bucket_arns" {
#   description = "ARNs of the created S3 buckets"
#   value       = { for k, v in module.s3 : k => v.bucket_arn }
# }

# output "s3_bucket_regions" {
#   description = "Regions where the S3 buckets are created"
#   value       = { for k, v in module.s3 : k => v.bucket_region }
# }



# output "lambda_function_last_modified" {
#   value = { for k, v in module.lambda_function : k => v.lambda_function_last_modified }
# }

# output "lambda_function_kms_key_arn" {
#   value = { for k, v in module.lambda_function : k => v.lambda_function_kms_key_arn }
# }

# output "lambda_function_source_code_hash" {
#   value = { for k, v in module.lambda_function : k => v.lambda_function_source_code_hash }
# }

# output "lambda_function_source_code_size" {
#   value = { for k, v in module.lambda_function : k => v.lambda_function_source_code_size }
# }

# output "lambda_role_arn" {
#   value = { for k, v in module.lambda_function : k => v.lambda_role_arn }
# }

# output "lambda_role_name" {
#   value = { for k, v in module.lambda_function : k => v.lambda_role_name }
# }

# output "lambda_cloudwatch_log_group_arn" {
#   value = { for k, v in module.lambda_function : k => v.lambda_cloudwatch_log_group_arn }
# }

# output "lambda_allowed_triggers" {
#   value = {
#     for key, value in var.lambda_functions : key => value.allowed_triggers
#   }
# }

# output "lambda_s3_bucket_notifications" {
#   value = {
#     for key, value in var.lambda_functions : key => value.s3_bucket_notification
#   }
# }