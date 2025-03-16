variable "create" {
  description = "Determines whether to create a DB instance role association"
  type        = bool
  default     = true
}

variable "feature_name" {
  description = "Name of the feature for association"
  type        = string
  default     = null
}

variable "role_arn" {
  description = "Amazon Resource Name (ARN) of the IAM Role to associate with the DB Instance"
  type        = string
  default     = null
}

variable "db_instance_identifier" {
  description = "The database instance identifier to associate the role"
  type        = string
  default     = null
}

variable "role_name" {
  type = string
}

variable "iam_policy_name" {
  description = "The name of the IAM policy to create for RDS secret access."
  type        = string
  default     = "rds-secret-access-policy"  # Default value, can be overridden
}

variable "policy_resource" {
  description = "The ARN of the secret in AWS Secrets Manager that the policy will grant access to."
  type        = string
}