## RULE GROUP VARIABLES
variable "rule_group_name" {
  type = string
  description = "Enter Rule group name: "
}

variable "rule_group_description" {
  type = string
  description = "Enter Rule group description: "
}

variable "rule_group_scope" {
  type = string
  description = "Enter Rule group scope: "
}

variable "rule_group_capacity" {
  type = number
  description = "Enter Rule group capacity: "
}

variable "rule_group_rules" {
  type = any
  description = "Enter Rule group rules: "
}

variable "ip_set_arn" {
  type = string
  description = "Enter IP set arn: "
}

variable "regex_set_arn" {
  type = string
  description = "Enter Regex set arn: "
}

variable "rule_group_visibility_config" {
  type = object({
    cloudwatch_metrics_enabled = bool
    metric_name                = string
    sampled_requests_enabled   = bool
  })
}


variable "rule_group_resource_tag" {
  type = map(any)
  description = "Enter the tags: "
}