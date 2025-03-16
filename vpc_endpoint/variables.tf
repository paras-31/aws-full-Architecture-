variable "vpc_id" {
  description = "The ID of the VPC where the endpoint will be created."
  type        = string
}

variable "service" {
  description = "The service name (e.g., 's3', 'dynamodb')."
  type        = string
}

variable "service_name" {
  description = "The full service name (e.g., 'com.amazonaws.us-east-1.s3'). If not provided, it will be fetched using the `service` argument."
  type        = string
  default     = null
}

variable "service_type" {
  description = "The type of VPC endpoint (e.g., 'Interface' or 'Gateway')."
  type        = string
  default     = "Interface"
}

variable "auto_accept" {
  description = "Whether to automatically accept VPC endpoint connection requests."
  type        = bool
  default     = null
}

variable "security_group_ids" {
  description = "List of security group IDs for Interface endpoints."
  type        = list(string)
  default     = []
}

variable "subnet_ids" {
  description = "List of subnet IDs for Interface endpoints."
  type        = list(string)
  default     = []
}

variable "route_table_ids" {
  description = "List of route table IDs for Gateway endpoints."
  type        = list(string)
  default     = []
}

variable "policy" {
  description = "A policy to attach to the endpoint."
  type        = string
  default     = null
}

variable "private_dns_enabled" {
  description = "Whether to enable private DNS for Interface endpoints."
  type        = bool
  default     = null
}

variable "tags" {
  description = "A map of tags to assign to the endpoint."
  type        = map(string)
  default     = {}
}

variable "timeouts" {
  description = "Timeout configuration for the VPC endpoint."
  type = object({
    create = string
    update = string
    delete = string
  })
  default = {
    create = "10m"
    update = "10m"
    delete = "10m"
  }
}