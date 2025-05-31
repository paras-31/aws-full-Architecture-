variable "rds_username" {
  description = "RDS username stored in AWS Secrets Manager"
  type        = string
  sensitive   = true
}

variable "rds_password" {
  description = "RDS password stored in AWS Secrets Manager"
  type        = string
  sensitive   = true
}

variable "secret_name" {
  type = string
}