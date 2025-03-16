# Setup Variables

variable "alarm_namespace" {
  description = "Namespace for generated Cloudwatch alarms"
  type        = string
  default     = "CISBenchmark"
}

variable "alarm_prefix" {
  description = "Prefix for the alarm name"
  type        = string
  default     = ""
}

variable "alarm_sns_topic_arn" {
  description = "SNS topic ARN for generated alarms"
  type        = string
}

variable "cloudtrail_log_group_name" {
  description = "Cloudwatch log group name for Cloudtrail logs"
  type        = string
 
}

variable "root_usage" {
  description = "Toggle root usage alarm"
  type        = bool
  default     = true
}

variable "tags" {
    type = map(any)
    description = "value"
  
}

variable "alarm_description" {
    type = string
    description = "The description for the alarm."
    default = "Monitoring for root account logins will provide visibility into the use of a fully privileged account and an opportunity to reduce the use of it."
  
}

variable "threshold" {
    type = number
    description = "This parameter is required for alarms based on static thresholds, but should not be used for alarms based on anomaly detection models."
    default = 1
  
}

variable "statistic" {
    type = string
    description = "The statistic to apply to the alarm's associated metric. Either of the following is supported: SampleCount, Average, Sum, Minimum, Maximum"
    default = "Sum"

}

variable "period" {
    type = number
    description = " The period in seconds over which the specified statistic is applied. Valid values are 10, 30, or any multiple of"
    default = "300"
  
}

variable "comparison_operator" {
    type = string
    description = "The arithmetic operation to use when comparing the specified Statistic and Threshold. The specified Statistic value is used as the first operand. Either of the following is supported: GreaterThanOrEqualToThreshold, GreaterThanThreshold, LessThanThreshold, LessThanOrEqualToThreshold. Additionally, the values LessThanLowerOrGreaterThanUpperThreshold, LessThanLowerThreshold, and GreaterThanUpperThreshold are used only for alarms based on anomaly detection models"
    default = "GreaterThanOrEqualToThreshold"
  
}

variable "evaluation_periods" {
    type = number
    description = "The number of periods over which data is compared to the specified threshold."
    default = 1
  
}

variable "metric_name" {
    type = string
    description = "name of metric"
    default = "RootUsage"
  
}

variable "pattern" {
    type = string
    description = "describe the pattern for alarm"
    default = "{ $.userIdentity.type = \"Root\" && $.userIdentity.invokedBy NOT EXISTS && $.eventType != \"AwsServiceEvent\" }"
  
}
