# ################################################################################
# # VPC
# ################################################################################

variable "create_vpc" {
  description = "Controls if VPC should be created (it affects almost all resources)"
  type        = bool
  default     = true
}
variable "name" {
  description = "Namespace to be used on all resources"
  type        = string
}

######### VPC endpoints ####
# variable "create" {
#   type = bool
#   default = true
  
# }

variable "private_subnet" {
  type = list(any)
  description = "list of private subnet cidr"
}


variable "public_subnet" {
  type = list(any)
  description = "list of public subnet cidr"
}


variable "endpoints" {
  description = "Configuration for multiple VPC endpoints."
  type = map(object({
    service             = string
    service_name        = optional(string)
    service_type        = optional(string, "Interface")
    auto_accept         = optional(bool)
    security_group_ids  = optional(list(string), [])
    subnet_ids          = optional(list(string), [])
    route_table_ids     = optional(list(string), [])
    policy              = optional(string)
    private_dns_enabled = optional(bool)
    tags                = optional(map(string), {})
  }))
}

# variable "root_cloudtrail_name" {
#  description = "Name to be used on all the resources as identifier"
#   type        = string
#   default     = ""
# }

# variable "ec2" {
#   description = "list of ec2"
#   type        = map(any)
# }

variable "cidr" {
  description = "(Optional) The IPv4 CIDR block for the VPC. CIDR can be explicitly set or it can be derived from IPAM using `ipv4_netmask_length` & `ipv4_ipam_pool_id`"
  type        = string
  default     = "10.0.0.0/16"
}

# # variable "secondary_cidr_blocks" {
# #   description = "List of secondary CIDR blocks to associate with the VPC to extend the IP Address pool"
# #   type        = list(string)
# #   default     = []
# # }

# # variable "instance_tenancy" {
# #   description = "A tenancy option for instances launched into the VPC"
# #   type        = string
# #   default     = "default"
# # }

variable "azs" {
  description = "A list of availability zones names or ids in the region"
  type        = list(string)
  default     = []
}

variable "enable_dns_hostnames" {
  description = "Should be true to enable DNS hostnames in the VPC"
  type        = bool
  default     = true
}

variable "enable_dns_support" {
  description = "Should be true to enable DNS support in the VPC"
  type        = bool
  default     = true
}

############ asg###############

variable "multipe_asg" {
  type = map(any)
  
}
# ################### ec2 creation variables #################

 variable "instance_type" {
   description = "instance_type"
   type        = any
   default     = null
 }

#  variable "associate_public_ip_address" {
#    description = "associate_public_ip_address"
#    type        = any
#    default     = true
#  }

 variable "ami" {
  description = "ID of AMI to use for the instance"
  type        = list(any)
  default     = []
}

variable "volume_tags" {
  description = "A mapping of tags to assign to the devices created by the instance at launch time"
  type        = map(string)
  default     = {}
}

variable "albs" {
  description = "A mapping of tags to assign to the devices created by the instance at launch time"
  type        = map(any)
  default     = {}
}

# variable "albs" {
#   type = map(object({
#     listeners = map(object({
#       port            = number
#       certificate_arn = optional(string)
#       protocol        = string
#       target_group_key = string
#       order           = number
#       rules = map(object({
#         priority = number
#         conditions = list(object({
#           http_header = object({
#             http_header_name = string
#             values           = list(string)
#           })
#         }))
#         actions = list(object({
#           type             = string
#           order            = number
#           target_group_key = string
#         }))
#       }))
#     }))
#     target_groups = map(object({
#       name              = string
#       port              = number
#       protocol          = string
#       target_type       = string
#       create_attachment = bool
#     }))
#   }))
# }

variable "secret_name" {
  type = string
  default = "secretidpareas"
}


# variable "Ec2" {
#   description = "A mapping of tags to assign to the devices created by the instance at launch time"
#   type        = map(any)
#   default     = {}
# }

variable "SecurityGroups" {
  type = map(any)
}

variable "SecurityGroups_RDS" {
  type = map(any)
}

variable "rds_username" {
  description = "RDS username"
  type        = string
  sensitive   = true
}

variable "rds_password" {
  description = "RDS password"
  type        = string
  sensitive   = true
}


################# waf ###########

variable "rule_group" {
  type = map(any)
}

variable "waf_creation" {
  type = map(any)
}

variable "regex" {
  type = map(any)
}

variable "ip_set" {
  type = map(any)
}

# variable "web_acl_association" {
#   type = map(any)
# }
############# cloudtrail root #############

# variable "name" {
#   description = "Namespace to be used on all resources"
#   type        = string
# }

variable "root_cloudtrail_name" {
 description = "Name to be used on all the resources as identifier"
  type        = string
  default     = ""
}

# variable "s3_bucket_name" {
#   description = "Specifies the name of the S3 bucket designated for publishing log files."
#   type        = string
# }

variable "tags" {
  description = "A map of tags to assign to resources."
  type        = map(string)
  default     = {}
}

variable "s3_key_prefix" {
  description = "Specifies the S3 key prefix that follows the name of the bucket you have designated for log file delivery."
  type        = string
  default     = null
}

variable "enable_cloudwatch_logs" {
  description = "Enables Cloudtrail logs to write to ceated log group."
  type        = bool
  default     = false
}

variable "cloudwatch_logs_retention_in_days" {
  description = "Specifies the number of days you want to retain log events in the specified log group. Possible values are: 1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365, 400, 545, 731, 1827, 3653, and 0. If you select 0, the events in the log group are always retained and never expire."
  type        = number
  default     = 365
}

variable "enable_logging" {
  description = "Enables logging for the trail. Defaults to true. Setting this to false will pause logging."
  type        = bool
  default     = false
}

variable "enable_log_file_validation" {
  description = "Specifies whether log file integrity validation is enabled."
  type        = bool
  default     = false
}

variable "include_global_service_events" {
  description = "Specifies whether the trail is publishing events from global services such as IAM to the log files."
  type        = bool
  default     = false
}

variable "is_multi_region_trail" {
  description = "Specifies whether the trail is created in the current region or in all regions."
  type        = bool
  default     = false
}

variable "is_organization_trail" {
  description = "Specifies whether the trail is an AWS Organizations trail. Organization trails log events for the master account and all member accounts. Can only be created in the organization master account."
  type        = bool
  default     = false
}

variable "enable_sns_notifications" {
 description = "Specifies whether to create SNS topic and send notification of log file delivery."
  type        = string
  default     = ""
}

variable "create_kms_key" {
  description = "Specifies whether to create kms key for cloudtrail and SNS. If 'kms_key_id' is set, need to set to 'false'."
  type        = string
  default     = ""
}

variable "event_selectors" {
  description = "Specifies a list of event selectors for enabling data event logging. See: https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudtrail#event_selector."

  type = list(object({
    read_write_type           = string
    include_management_events = bool

    data_resource = object({
      type   = string
      values = list(string)
    })
  }))

  default = []
}

variable "insight_selectors" {
  description = "Specifies a list of insight selectors for identifying unusual operational activity. See: https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudtrail#insight_selector."

  type = list(object({
    insight_type = string
  }))

  default = []
}
###### SNS #####
variable "sns_variable" {
  type = map(any)
  description = "Create multiple SNS"

  
}

# variable "sns_variable" {
#    type        = map(object({
#     sns_topic_name =  string
#     subscriptions = map(object({
#       protocol = string
#       endpoint  = string 
#     }))
#   }))
#   description = "Can create multiple SNS"
# }

########### aletrs on root account#######
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

# variable "alarm_sns_topic_arn" {
#   description = "SNS topic ARN for generated alarms"
#   type        = string
# }

# variable "cloudtrail_log_group_name" {
#   description = "Cloudwatch log group name for Cloudtrail logs"
#   type        = string
 
# }

variable "root_usage" {
  description = "Toggle root usage alarm"
  type        = bool
  default     = true
}

# variable "tags" {
#    type = map(any)
#    description = "value"
  
# }

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


# variable "iam_role_tags" {
#   description = "A map of additional tags to add to the IAM role/profile created"
#   type        = map(string)
#   default     = {}
# }


# # variable "enable_network_address_usage_metrics" {
# #   description = "Determines whether network address usage metrics are enabled for the VPC"
# #   type        = bool
# #   default     = null
# # }

# # variable "use_ipam_pool" {
# #   description = "Determines whether IPAM pool is used for CIDR allocation"
# #   type        = bool
# #   default     = false
# # }

# # variable "ipv4_ipam_pool_id" {
# #   description = "(Optional) The ID of an IPv4 IPAM pool you want to use for allocating this VPC's CIDR"
# #   type        = string
# #   default     = null
# # }

# # variable "ipv4_netmask_length" {
# #   description = "(Optional) The netmask length of the IPv4 CIDR you want to allocate to this VPC. Requires specifying a ipv4_ipam_pool_id"
# #   type        = number
# #   default     = null
# # }

# # variable "enable_ipv6" {
# #   description = "Requests an Amazon-provided IPv6 CIDR block with a /56 prefix length for the VPC. You cannot specify the range of IP addresses, or the size of the CIDR block"
# #   type        = bool
# #   default     = false
# # }

# # variable "ipv6_cidr" {
# #   description = "(Optional) IPv6 CIDR block to request from an IPAM Pool. Can be set explicitly or derived from IPAM using `ipv6_netmask_length`"
# #   type        = string
# #   default     = null
# # }

# # variable "ipv6_ipam_pool_id" {
# #   description = "(Optional) IPAM Pool ID for a IPv6 pool. Conflicts with `assign_generated_ipv6_cidr_block`"
# #   type        = string
# #   default     = null
# # }

# # variable "ipv6_netmask_length" {
# #   description = "(Optional) Netmask length to request from IPAM Pool. Conflicts with `ipv6_cidr_block`. This can be omitted if IPAM pool as a `allocation_default_netmask_length` set. Valid values: `56`"
# #   type        = number
# #   default     = null
# # }

# # variable "ipv6_cidr_block_network_border_group" {
# #   description = "By default when an IPv6 CIDR is assigned to a VPC a default ipv6_cidr_block_network_border_group will be set to the region of the VPC. This can be changed to restrict advertisement of public addresses to specific Network Border Groups such as LocalZones"
# #   type        = string
# #   default     = null
# # }

# # variable "vpc_tags" {
# #   description = "Additional tags for the VPC"
# #   type        = map(string)
# #   default     = {}
# # }

#variable "tags" {
 # description = "A map of tags to add to all resources"
  #type        = map(string)
  #default     = {}
#}

# ################################################################################
# # DHCP Options Set
# ################################################################################

# variable "enable_dhcp_options" {
#   description = "Should be true if you want to specify a DHCP options set with a custom domain name, DNS servers, NTP servers, netbios servers, and/or netbios server type"
#   type        = bool
#   default     = false
# }

# variable "dhcp_options_domain_name" {
#   description = "Specifies DNS name for DHCP options set (requires enable_dhcp_options set to true)"
#   type        = string
#   default     = ""
# }

# variable "dhcp_options_domain_name_servers" {
#   description = "Specify a list of DNS server addresses for DHCP options set, default to AWS provided (requires enable_dhcp_options set to true)"
#   type        = list(string)
#   default     = ["AmazonProvidedDNS"]
# }

# variable "dhcp_options_ntp_servers" {
#   description = "Specify a list of NTP servers for DHCP options set (requires enable_dhcp_options set to true)"
#   type        = list(string)
#   default     = []
# }

# variable "dhcp_options_netbios_name_servers" {
#   description = "Specify a list of netbios servers for DHCP options set (requires enable_dhcp_options set to true)"
#   type        = list(string)
#   default     = []
# }

# variable "dhcp_options_netbios_node_type" {
#   description = "Specify netbios node_type for DHCP options set (requires enable_dhcp_options set to true)"
#   type        = string
#   default     = ""
# }

# variable "dhcp_options_tags" {
#   description = "Additional tags for the DHCP option set (requires enable_dhcp_options set to true)"
#   type        = map(string)
#   default     = {}
# }

# ################################################################################
# # Publiс Subnets
# ################################################################################

# variable "public_subnets" {
#   description = "A list of public subnets inside the VPC"
#   type        = list(string)
#   default     = []
# }

# variable "public_subnet_assign_ipv6_address_on_creation" {
#   description = "Specify true to indicate that network interfaces created in the specified subnet should be assigned an IPv6 address. Default is `false`"
#   type        = bool
#   default     = false
# }

# variable "public_subnet_enable_dns64" {
#   description = "Indicates whether DNS queries made to the Amazon-provided DNS Resolver in this subnet should return synthetic IPv6 addresses for IPv4-only destinations. Default: `true`"
#   type        = bool
#   default     = true
# }

# variable "public_subnet_enable_resource_name_dns_aaaa_record_on_launch" {
#   description = "Indicates whether to respond to DNS queries for instance hostnames with DNS AAAA records. Default: `true`"
#   type        = bool
#   default     = true
# }

# variable "public_subnet_enable_resource_name_dns_a_record_on_launch" {
#   description = "Indicates whether to respond to DNS queries for instance hostnames with DNS A records. Default: `false`"
#   type        = bool
#   default     = false
# }

# variable "create_multiple_public_route_tables" {
#   description = "Indicates whether to create a separate route table for each public subnet. Default: `false`"
#   type        = bool
#   default     = false
# }

# variable "public_subnet_ipv6_prefixes" {
#   description = "Assigns IPv6 public subnet id based on the Amazon provided /56 prefix base 10 integer (0-256). Must be of equal length to the corresponding IPv4 subnet list"
#   type        = list(string)
#   default     = []
# }

# variable "public_subnet_ipv6_native" {
#   description = "Indicates whether to create an IPv6-only subnet. Default: `false`"
#   type        = bool
#   default     = false
# }

# variable "map_public_ip_on_launch" {
#   description = "Specify true to indicate that instances launched into the subnet should be assigned a public IP address. Default is `false`"
#   type        = bool
#   default     = false
# }

# variable "public_subnet_private_dns_hostname_type_on_launch" {
#   description = "The type of hostnames to assign to instances in the subnet at launch. For IPv6-only subnets, an instance DNS name must be based on the instance ID. For dual-stack and IPv4-only subnets, you can specify whether DNS names use the instance IPv4 address or the instance ID. Valid values: `ip-name`, `resource-name`"
#   type        = string
#   default     = null
# }

variable "public_subnet_names" {
  description = "Explicit values to use in the Name tag on public subnets. If empty, Name tags are generated"
  type        = list(string)
  default     = []
}

# variable "public_subnet_suffix" {
#   description = "Suffix to append to public subnets name"
#   type        = string
#   default     = "public"
# }

# variable "public_subnet_tags" {
#   description = "Additional tags for the public subnets"
#   type        = map(string)
#   default     = {}
# }

# variable "public_subnet_tags_per_az" {
#   description = "Additional tags for the public subnets where the primary key is the AZ"
#   type        = map(map(string))
#   default     = {}
# }

# variable "public_route_table_tags" {
#   description = "Additional tags for the public route tables"
#   type        = map(string)
#   default     = {}
# }

# ################################################################################
# # Public Network ACLs
# ################################################################################

variable "public_dedicated_network_acl" {
  description = "Whether to use dedicated network ACL (not default) and custom rules for public subnets"
  type        = bool

}

variable "public_inbound_acl_rules" {
  description = "Public subnets inbound network ACLs"
  type        = list(map(string))
  default = [
    {
      rule_number = 100
      rule_action = "allow"
      from_port   = 0
      to_port     = 0
      protocol    = "-1"
      cidr_block  = "0.0.0.0/0"
    },
  ]
}

variable "public_outbound_acl_rules" {
  description = "Public subnets outbound network ACLs"
  type        = list(map(string))
  default = [
    {
      rule_number = 100
      rule_action = "allow"
      from_port   = 0
      to_port     = 0
      protocol    = "-1"
      cidr_block  = "0.0.0.0/0"
    },
  ]
}

variable "public_acl_tags" {
  description = "Additional tags for the public subnets network ACL"
  type        = map(string)
  default     = {}
}

# ################################################################################
# # Private Subnets
# ################################################################################

# variable "private_subnets" {
#   description = "A list of private subnets inside the VPC"
#   type        = list(string)
#   default     = []
# }

# variable "private_subnet_assign_ipv6_address_on_creation" {
#   description = "Specify true to indicate that network interfaces created in the specified subnet should be assigned an IPv6 address. Default is `false`"
#   type        = bool
#   default     = false
# }

# variable "private_subnet_enable_dns64" {
#   description = "Indicates whether DNS queries made to the Amazon-provided DNS Resolver in this subnet should return synthetic IPv6 addresses for IPv4-only destinations. Default: `true`"
#   type        = bool
#   default     = true
# }

# variable "private_subnet_enable_resource_name_dns_aaaa_record_on_launch" {
#   description = "Indicates whether to respond to DNS queries for instance hostnames with DNS AAAA records. Default: `true`"
#   type        = bool
#   default     = true
# }

# variable "private_subnet_enable_resource_name_dns_a_record_on_launch" {
#   description = "Indicates whether to respond to DNS queries for instance hostnames with DNS A records. Default: `false`"
#   type        = bool
#   default     = false
# }

# variable "private_subnet_ipv6_prefixes" {
#   description = "Assigns IPv6 private subnet id based on the Amazon provided /56 prefix base 10 integer (0-256). Must be of equal length to the corresponding IPv4 subnet list"
#   type        = list(string)
#   default     = []
# }

# variable "private_subnet_ipv6_native" {
#   description = "Indicates whether to create an IPv6-only subnet. Default: `false`"
#   type        = bool
#   default     = false
# }

# variable "private_subnet_private_dns_hostname_type_on_launch" {
#   description = "The type of hostnames to assign to instances in the subnet at launch. For IPv6-only subnets, an instance DNS name must be based on the instance ID. For dual-stack and IPv4-only subnets, you can specify whether DNS names use the instance IPv4 address or the instance ID. Valid values: `ip-name`, `resource-name`"
#   type        = string
#   default     = null
# }

variable "private_subnet_names" {
  description = "Explicit values to use in the Name tag on private subnets. If empty, Name tags are generated"
  type        = list(string)
  default     = []
}

# variable "private_subnet_suffix" {
#   description = "Suffix to append to private subnets name"
#   type        = string
#   default     = "private"
# }

# variable "private_subnet_tags" {
#   description = "Additional tags for the private subnets"
#   type        = map(string)
#   default     = {}
# }

# variable "private_subnet_tags_per_az" {
#   description = "Additional tags for the private subnets where the primary key is the AZ"
#   type        = map(map(string))
#   default     = {}
# }

# variable "private_route_table_tags" {
#   description = "Additional tags for the private route tables"
#   type        = map(string)
#   default     = {}
# }

# ################################################################################
# # Private Network ACLs
# ################################################################################

# variable "private_dedicated_network_acl" {
#   description = "Whether to use dedicated network ACL (not default) and custom rules for private subnets"
#   type        = bool
#   default     = false
# }

# variable "private_inbound_acl_rules" {
#   description = "Private subnets inbound network ACLs"
#   type        = list(map(string))
#   default = [
#     {
#       rule_number = 100
#       rule_action = "allow"
#       from_port   = 0
#       to_port     = 0
#       protocol    = "-1"
#       cidr_block  = "0.0.0.0/0"
#     },
#   ]
# }

# variable "private_outbound_acl_rules" {
#   description = "Private subnets outbound network ACLs"
#   type        = list(map(string))
#   default = [
#     {
#       rule_number = 100
#       rule_action = "allow"
#       from_port   = 0
#       to_port     = 0
#       protocol    = "-1"
#       cidr_block  = "0.0.0.0/0"
#     },
#   ]
# }

# variable "private_acl_tags" {
#   description = "Additional tags for the private subnets network ACL"
#   type        = map(string)
#   default     = {}
# }

# ################################################################################
# # Database Subnets
# ################################################################################

# variable "database_subnets" {
#   description = "A list of database subnets inside the VPC"
#   type        = list(string)
#   default     = []
# }

# variable "database_subnet_assign_ipv6_address_on_creation" {
#   description = "Specify true to indicate that network interfaces created in the specified subnet should be assigned an IPv6 address. Default is `false`"
#   type        = bool
#   default     = false
# }

# variable "database_subnet_enable_dns64" {
#   description = "Indicates whether DNS queries made to the Amazon-provided DNS Resolver in this subnet should return synthetic IPv6 addresses for IPv4-only destinations. Default: `true`"
#   type        = bool
#   default     = true
# }

# variable "database_subnet_enable_resource_name_dns_aaaa_record_on_launch" {
#   description = "Indicates whether to respond to DNS queries for instance hostnames with DNS AAAA records. Default: `true`"
#   type        = bool
#   default     = true
# }

# variable "database_subnet_enable_resource_name_dns_a_record_on_launch" {
#   description = "Indicates whether to respond to DNS queries for instance hostnames with DNS A records. Default: `false`"
#   type        = bool
#   default     = false
# }

# variable "database_subnet_ipv6_prefixes" {
#   description = "Assigns IPv6 database subnet id based on the Amazon provided /56 prefix base 10 integer (0-256). Must be of equal length to the corresponding IPv4 subnet list"
#   type        = list(string)
#   default     = []
# }

# variable "database_subnet_ipv6_native" {
#   description = "Indicates whether to create an IPv6-only subnet. Default: `false`"
#   type        = bool
#   default     = false
# }

# variable "database_subnet_private_dns_hostname_type_on_launch" {
#   description = "The type of hostnames to assign to instances in the subnet at launch. For IPv6-only subnets, an instance DNS name must be based on the instance ID. For dual-stack and IPv4-only subnets, you can specify whether DNS names use the instance IPv4 address or the instance ID. Valid values: `ip-name`, `resource-name`"
#   type        = string
#   default     = null
# }

# variable "database_subnet_names" {
#   description = "Explicit values to use in the Name tag on database subnets. If empty, Name tags are generated"
#   type        = list(string)
#   default     = []
# }

# variable "database_subnet_suffix" {
#   description = "Suffix to append to database subnets name"
#   type        = string
#   default     = "db"
# }

# variable "create_database_subnet_route_table" {
#   description = "Controls if separate route table for database should be created"
#   type        = bool
#   default     = false
# }

# variable "create_database_internet_gateway_route" {
#   description = "Controls if an internet gateway route for public database access should be created"
#   type        = bool
#   default     = false
# }

# variable "create_database_nat_gateway_route" {
#   description = "Controls if a nat gateway route should be created to give internet access to the database subnets"
#   type        = bool
#   default     = false
# }

# variable "database_route_table_tags" {
#   description = "Additional tags for the database route tables"
#   type        = map(string)
#   default     = {}
# }

# variable "database_subnet_tags" {
#   description = "Additional tags for the database subnets"
#   type        = map(string)
#   default     = {}
# }

# variable "create_database_subnet_group" {
#   description = "Controls if database subnet group should be created (n.b. database_subnets must also be set)"
#   type        = bool
#   default     = true
# }

# variable "database_subnet_group_name" {
#   description = "Name of database subnet group"
#   type        = string
#   default     = null
# }

# variable "database_subnet_group_tags" {
#   description = "Additional tags for the database subnet group"
#   type        = map(string)
#   default     = {}
# }

# ################################################################################
# # Database Network ACLs
# ################################################################################

# variable "database_dedicated_network_acl" {
#   description = "Whether to use dedicated network ACL (not default) and custom rules for database subnets"
#   type        = bool
#   default     = false
# }

# variable "database_inbound_acl_rules" {
#   description = "Database subnets inbound network ACL rules"
#   type        = list(map(string))
#   default = [
#     {
#       rule_number = 100
#       rule_action = "allow"
#       from_port   = 0
#       to_port     = 0
#       protocol    = "-1"
#       cidr_block  = "0.0.0.0/0"
#     },
#   ]
# }

# variable "database_outbound_acl_rules" {
#   description = "Database subnets outbound network ACL rules"
#   type        = list(map(string))
#   default = [
#     {
#       rule_number = 100
#       rule_action = "allow"
#       from_port   = 0
#       to_port     = 0
#       protocol    = "-1"
#       cidr_block  = "0.0.0.0/0"
#     },
#   ]
# }

# variable "database_acl_tags" {
#   description = "Additional tags for the database subnets network ACL"
#   type        = map(string)
#   default     = {}
# }

# ################################################################################
# # Redshift Subnets
# ################################################################################

# variable "redshift_subnets" {
#   description = "A list of redshift subnets inside the VPC"
#   type        = list(string)
#   default     = []
# }

# variable "redshift_subnet_assign_ipv6_address_on_creation" {
#   description = "Specify true to indicate that network interfaces created in the specified subnet should be assigned an IPv6 address. Default is `false`"
#   type        = bool
#   default     = false
# }

# variable "redshift_subnet_enable_dns64" {
#   description = "Indicates whether DNS queries made to the Amazon-provided DNS Resolver in this subnet should return synthetic IPv6 addresses for IPv4-only destinations. Default: `true`"
#   type        = bool
#   default     = true
# }

# variable "redshift_subnet_enable_resource_name_dns_aaaa_record_on_launch" {
#   description = "Indicates whether to respond to DNS queries for instance hostnames with DNS AAAA records. Default: `true`"
#   type        = bool
#   default     = true
# }

# variable "redshift_subnet_enable_resource_name_dns_a_record_on_launch" {
#   description = "Indicates whether to respond to DNS queries for instance hostnames with DNS A records. Default: `false`"
#   type        = bool
#   default     = false
# }

# variable "redshift_subnet_ipv6_prefixes" {
#   description = "Assigns IPv6 redshift subnet id based on the Amazon provided /56 prefix base 10 integer (0-256). Must be of equal length to the corresponding IPv4 subnet list"
#   type        = list(string)
#   default     = []
# }

# variable "redshift_subnet_ipv6_native" {
#   description = "Indicates whether to create an IPv6-only subnet. Default: `false`"
#   type        = bool
#   default     = false
# }

# variable "redshift_subnet_private_dns_hostname_type_on_launch" {
#   description = "The type of hostnames to assign to instances in the subnet at launch. For IPv6-only subnets, an instance DNS name must be based on the instance ID. For dual-stack and IPv4-only subnets, you can specify whether DNS names use the instance IPv4 address or the instance ID. Valid values: `ip-name`, `resource-name`"
#   type        = string
#   default     = null
# }

# variable "redshift_subnet_names" {
#   description = "Explicit values to use in the Name tag on redshift subnets. If empty, Name tags are generated"
#   type        = list(string)
#   default     = []
# }

# variable "redshift_subnet_suffix" {
#   description = "Suffix to append to redshift subnets name"
#   type        = string
#   default     = "redshift"
# }

# variable "enable_public_redshift" {
#   description = "Controls if redshift should have public routing table"
#   type        = bool
#   default     = false
# }

# variable "create_redshift_subnet_route_table" {
#   description = "Controls if separate route table for redshift should be created"
#   type        = bool
#   default     = false
# }

# variable "redshift_route_table_tags" {
#   description = "Additional tags for the redshift route tables"
#   type        = map(string)
#   default     = {}
# }

# variable "redshift_subnet_tags" {
#   description = "Additional tags for the redshift subnets"
#   type        = map(string)
#   default     = {}
# }

# variable "create_redshift_subnet_group" {
#   description = "Controls if redshift subnet group should be created"
#   type        = bool
#   default     = true
# }

# variable "redshift_subnet_group_name" {
#   description = "Name of redshift subnet group"
#   type        = string
#   default     = null
# }

# variable "redshift_subnet_group_tags" {
#   description = "Additional tags for the redshift subnet group"
#   type        = map(string)
#   default     = {}
# }

# ################################################################################
# # Redshift Network ACLs
# ################################################################################

# variable "redshift_dedicated_network_acl" {
#   description = "Whether to use dedicated network ACL (not default) and custom rules for redshift subnets"
#   type        = bool
#   default     = false
# }

# variable "redshift_inbound_acl_rules" {
#   description = "Redshift subnets inbound network ACL rules"
#   type        = list(map(string))
#   default = [
#     {
#       rule_number = 100
#       rule_action = "allow"
#       from_port   = 0
#       to_port     = 0
#       protocol    = "-1"
#       cidr_block  = "0.0.0.0/0"
#     },
#   ]
# }

# variable "redshift_outbound_acl_rules" {
#   description = "Redshift subnets outbound network ACL rules"
#   type        = list(map(string))
#   default = [
#     {
#       rule_number = 100
#       rule_action = "allow"
#       from_port   = 0
#       to_port     = 0
#       protocol    = "-1"
#       cidr_block  = "0.0.0.0/0"
#     },
#   ]
# }

# variable "redshift_acl_tags" {
#   description = "Additional tags for the redshift subnets network ACL"
#   type        = map(string)
#   default     = {}
# }

# ################################################################################
# # Elasticache Subnets
# ################################################################################

# variable "elasticache_subnets" {
#   description = "A list of elasticache subnets inside the VPC"
#   type        = list(string)
#   default     = []
# }

# variable "elasticache_subnet_assign_ipv6_address_on_creation" {
#   description = "Specify true to indicate that network interfaces created in the specified subnet should be assigned an IPv6 address. Default is `false`"
#   type        = bool
#   default     = false
# }

# variable "elasticache_subnet_enable_dns64" {
#   description = "Indicates whether DNS queries made to the Amazon-provided DNS Resolver in this subnet should return synthetic IPv6 addresses for IPv4-only destinations. Default: `true`"
#   type        = bool
#   default     = true
# }

# variable "elasticache_subnet_enable_resource_name_dns_aaaa_record_on_launch" {
#   description = "Indicates whether to respond to DNS queries for instance hostnames with DNS AAAA records. Default: `true`"
#   type        = bool
#   default     = true
# }

# variable "elasticache_subnet_enable_resource_name_dns_a_record_on_launch" {
#   description = "Indicates whether to respond to DNS queries for instance hostnames with DNS A records. Default: `false`"
#   type        = bool
#   default     = false
# }

# variable "elasticache_subnet_ipv6_prefixes" {
#   description = "Assigns IPv6 elasticache subnet id based on the Amazon provided /56 prefix base 10 integer (0-256). Must be of equal length to the corresponding IPv4 subnet list"
#   type        = list(string)
#   default     = []
# }

# variable "elasticache_subnet_ipv6_native" {
#   description = "Indicates whether to create an IPv6-only subnet. Default: `false`"
#   type        = bool
#   default     = false
# }

# variable "elasticache_subnet_private_dns_hostname_type_on_launch" {
#   description = "The type of hostnames to assign to instances in the subnet at launch. For IPv6-only subnets, an instance DNS name must be based on the instance ID. For dual-stack and IPv4-only subnets, you can specify whether DNS names use the instance IPv4 address or the instance ID. Valid values: `ip-name`, `resource-name`"
#   type        = string
#   default     = null
# }

# variable "elasticache_subnet_names" {
#   description = "Explicit values to use in the Name tag on elasticache subnets. If empty, Name tags are generated"
#   type        = list(string)
#   default     = []
# }

# variable "elasticache_subnet_suffix" {
#   description = "Suffix to append to elasticache subnets name"
#   type        = string
#   default     = "elasticache"
# }

# variable "elasticache_subnet_tags" {
#   description = "Additional tags for the elasticache subnets"
#   type        = map(string)
#   default     = {}
# }

# variable "create_elasticache_subnet_route_table" {
#   description = "Controls if separate route table for elasticache should be created"
#   type        = bool
#   default     = false
# }

# variable "elasticache_route_table_tags" {
#   description = "Additional tags for the elasticache route tables"
#   type        = map(string)
#   default     = {}
# }

# variable "create_elasticache_subnet_group" {
#   description = "Controls if elasticache subnet group should be created"
#   type        = bool
#   default     = true
# }

# variable "elasticache_subnet_group_name" {
#   description = "Name of elasticache subnet group"
#   type        = string
#   default     = null
# }

# variable "elasticache_subnet_group_tags" {
#   description = "Additional tags for the elasticache subnet group"
#   type        = map(string)
#   default     = {}
# }

# ################################################################################
# # Elasticache Network ACLs
# ################################################################################

# variable "elasticache_dedicated_network_acl" {
#   description = "Whether to use dedicated network ACL (not default) and custom rules for elasticache subnets"
#   type        = bool
#   default     = false
# }

# variable "elasticache_inbound_acl_rules" {
#   description = "Elasticache subnets inbound network ACL rules"
#   type        = list(map(string))
#   default = [
#     {
#       rule_number = 100
#       rule_action = "allow"
#       from_port   = 0
#       to_port     = 0
#       protocol    = "-1"
#       cidr_block  = "0.0.0.0/0"
#     },
#   ]
# }

# variable "elasticache_outbound_acl_rules" {
#   description = "Elasticache subnets outbound network ACL rules"
#   type        = list(map(string))
#   default = [
#     {
#       rule_number = 100
#       rule_action = "allow"
#       from_port   = 0
#       to_port     = 0
#       protocol    = "-1"
#       cidr_block  = "0.0.0.0/0"
#     },
#   ]
# }

# variable "elasticache_acl_tags" {
#   description = "Additional tags for the elasticache subnets network ACL"
#   type        = map(string)
#   default     = {}
# }

# ################################################################################
# # Intra Subnets
# ################################################################################

# variable "intra_subnets" {
#   description = "A list of intra subnets inside the VPC"
#   type        = list(string)
#   default     = []
# }

# variable "intra_subnet_assign_ipv6_address_on_creation" {
#   description = "Specify true to indicate that network interfaces created in the specified subnet should be assigned an IPv6 address. Default is `false`"
#   type        = bool
#   default     = false
# }

# variable "intra_subnet_enable_dns64" {
#   description = "Indicates whether DNS queries made to the Amazon-provided DNS Resolver in this subnet should return synthetic IPv6 addresses for IPv4-only destinations. Default: `true`"
#   type        = bool
#   default     = true
# }

# variable "intra_subnet_enable_resource_name_dns_aaaa_record_on_launch" {
#   description = "Indicates whether to respond to DNS queries for instance hostnames with DNS AAAA records. Default: `true`"
#   type        = bool
#   default     = true
# }

# variable "intra_subnet_enable_resource_name_dns_a_record_on_launch" {
#   description = "Indicates whether to respond to DNS queries for instance hostnames with DNS A records. Default: `false`"
#   type        = bool
#   default     = false
# }

# variable "create_multiple_intra_route_tables" {
#   description = "Indicates whether to create a separate route table for each intra subnet. Default: `false`"
#   type        = bool
#   default     = false
# }

# variable "intra_subnet_ipv6_prefixes" {
#   description = "Assigns IPv6 intra subnet id based on the Amazon provided /56 prefix base 10 integer (0-256). Must be of equal length to the corresponding IPv4 subnet list"
#   type        = list(string)
#   default     = []
# }

# variable "intra_subnet_ipv6_native" {
#   description = "Indicates whether to create an IPv6-only subnet. Default: `false`"
#   type        = bool
#   default     = false
# }

# variable "intra_subnet_private_dns_hostname_type_on_launch" {
#   description = "The type of hostnames to assign to instances in the subnet at launch. For IPv6-only subnets, an instance DNS name must be based on the instance ID. For dual-stack and IPv4-only subnets, you can specify whether DNS names use the instance IPv4 address or the instance ID. Valid values: `ip-name`, `resource-name`"
#   type        = string
#   default     = null
# }

# variable "intra_subnet_names" {
#   description = "Explicit values to use in the Name tag on intra subnets. If empty, Name tags are generated"
#   type        = list(string)
#   default     = []
# }

# variable "intra_subnet_suffix" {
#   description = "Suffix to append to intra subnets name"
#   type        = string
#   default     = "intra"
# }

# variable "intra_subnet_tags" {
#   description = "Additional tags for the intra subnets"
#   type        = map(string)
#   default     = {}
# }

# variable "intra_route_table_tags" {
#   description = "Additional tags for the intra route tables"
#   type        = map(string)
#   default     = {}
# }

# ################################################################################
# # Intra Network ACLs
# ################################################################################

# variable "intra_dedicated_network_acl" {
#   description = "Whether to use dedicated network ACL (not default) and custom rules for intra subnets"
#   type        = bool
#   default     = false
# }

# variable "intra_inbound_acl_rules" {
#   description = "Intra subnets inbound network ACLs"
#   type        = list(map(string))
#   default = [
#     {
#       rule_number = 100
#       rule_action = "allow"
#       from_port   = 0
#       to_port     = 0
#       protocol    = "-1"
#       cidr_block  = "0.0.0.0/0"
#     },
#   ]
# }

# variable "intra_outbound_acl_rules" {
#   description = "Intra subnets outbound network ACLs"
#   type        = list(map(string))
#   default = [
#     {
#       rule_number = 100
#       rule_action = "allow"
#       from_port   = 0
#       to_port     = 0
#       protocol    = "-1"
#       cidr_block  = "0.0.0.0/0"
#     },
#   ]
# }

# variable "intra_acl_tags" {
#   description = "Additional tags for the intra subnets network ACL"
#   type        = map(string)
#   default     = {}
# }

# ################################################################################
# # Outpost Subnets
# ################################################################################

# variable "outpost_subnets" {
#   description = "A list of outpost subnets inside the VPC"
#   type        = list(string)
#   default     = []
# }

# variable "outpost_subnet_assign_ipv6_address_on_creation" {
#   description = "Specify true to indicate that network interfaces created in the specified subnet should be assigned an IPv6 address. Default is `false`"
#   type        = bool
#   default     = false
# }

# variable "outpost_az" {
#   description = "AZ where Outpost is anchored"
#   type        = string
#   default     = null
# }

# variable "customer_owned_ipv4_pool" {
#   description = "The customer owned IPv4 address pool. Typically used with the `map_customer_owned_ip_on_launch` argument. The `outpost_arn` argument must be specified when configured"
#   type        = string
#   default     = null
# }

# variable "outpost_subnet_enable_dns64" {
#   description = "Indicates whether DNS queries made to the Amazon-provided DNS Resolver in this subnet should return synthetic IPv6 addresses for IPv4-only destinations. Default: `true`"
#   type        = bool
#   default     = true
# }

# variable "outpost_subnet_enable_resource_name_dns_aaaa_record_on_launch" {
#   description = "Indicates whether to respond to DNS queries for instance hostnames with DNS AAAA records. Default: `true`"
#   type        = bool
#   default     = true
# }

# variable "outpost_subnet_enable_resource_name_dns_a_record_on_launch" {
#   description = "Indicates whether to respond to DNS queries for instance hostnames with DNS A records. Default: `false`"
#   type        = bool
#   default     = false
# }

# variable "outpost_subnet_ipv6_prefixes" {
#   description = "Assigns IPv6 outpost subnet id based on the Amazon provided /56 prefix base 10 integer (0-256). Must be of equal length to the corresponding IPv4 subnet list"
#   type        = list(string)
#   default     = []
# }

# variable "outpost_subnet_ipv6_native" {
#   description = "Indicates whether to create an IPv6-only subnet. Default: `false`"
#   type        = bool
#   default     = false
# }

# variable "map_customer_owned_ip_on_launch" {
#   description = "Specify true to indicate that network interfaces created in the subnet should be assigned a customer owned IP address. The `customer_owned_ipv4_pool` and `outpost_arn` arguments must be specified when set to `true`. Default is `false`"
#   type        = bool
#   default     = false
# }

# variable "outpost_arn" {
#   description = "ARN of Outpost you want to create a subnet in"
#   type        = string
#   default     = null
# }

# variable "outpost_subnet_private_dns_hostname_type_on_launch" {
#   description = "The type of hostnames to assign to instances in the subnet at launch. For IPv6-only subnets, an instance DNS name must be based on the instance ID. For dual-stack and IPv4-only subnets, you can specify whether DNS names use the instance IPv4 address or the instance ID. Valid values: `ip-name`, `resource-name`"
#   type        = string
#   default     = null
# }

# variable "outpost_subnet_names" {
#   description = "Explicit values to use in the Name tag on outpost subnets. If empty, Name tags are generated"
#   type        = list(string)
#   default     = []
# }

# variable "outpost_subnet_suffix" {
#   description = "Suffix to append to outpost subnets name"
#   type        = string
#   default     = "outpost"
# }

# variable "outpost_subnet_tags" {
#   description = "Additional tags for the outpost subnets"
#   type        = map(string)
#   default     = {}
# }

# ################################################################################
# # Outpost Network ACLs
# ################################################################################

# variable "outpost_dedicated_network_acl" {
#   description = "Whether to use dedicated network ACL (not default) and custom rules for outpost subnets"
#   type        = bool
#   default     = false
# }

# variable "outpost_inbound_acl_rules" {
#   description = "Outpost subnets inbound network ACLs"
#   type        = list(map(string))
#   default = [
#     {
#       rule_number = 100
#       rule_action = "allow"
#       from_port   = 0
#       to_port     = 0
#       protocol    = "-1"
#       cidr_block  = "0.0.0.0/0"
#     },
#   ]
# }

# variable "outpost_outbound_acl_rules" {
#   description = "Outpost subnets outbound network ACLs"
#   type        = list(map(string))
#   default = [
#     {
#       rule_number = 100
#       rule_action = "allow"
#       from_port   = 0
#       to_port     = 0
#       protocol    = "-1"
#       cidr_block  = "0.0.0.0/0"
#     },
#   ]
# }

# variable "outpost_acl_tags" {
#   description = "Additional tags for the outpost subnets network ACL"
#   type        = map(string)
#   default     = {}
# }

# ################################################################################
# # Internet Gateway
# ################################################################################

# variable "create_igw" {
#   description = "Controls if an Internet Gateway is created for public subnets and the related routes that connect them"
#   type        = bool
#   default     = true
# }

# variable "create_egress_only_igw" {
#   description = "Controls if an Egress Only Internet Gateway is created and its related routes"
#   type        = bool
#   default     = true
# }

# variable "igw_tags" {
#   description = "Additional tags for the internet gateway"
#   type        = map(string)
#   default     = {}
# }

# ################################################################################
# # NAT Gateway
# ################################################################################

variable "enable_nat_gateway" {
  description = "Should be true if you want to provision NAT Gateways for each of your private networks"
  type        = bool
  default     = true
}

# variable "nat_gateway_destination_cidr_block" {
#   description = "Used to pass a custom destination route for private NAT Gateway. If not specified, the default 0.0.0.0/0 is used as a destination route"
#   type        = string
#   default     = "0.0.0.0/0"
# }

variable "single_nat_gateway" {
  description = "Should be true if you want to provision a single shared NAT Gateway across all of your private networks"
  type        = bool
  default     = true
}

# variable "one_nat_gateway_per_az" {
#   description = "Should be true if you want only one NAT Gateway per availability zone. Requires `var.azs` to be set, and the number of `public_subnets` created to be greater than or equal to the number of availability zones specified in `var.azs`"
#   type        = bool
#   default     = false
# }

# variable "reuse_nat_ips" {
#   description = "Should be true if you don't want EIPs to be created for your NAT Gateways and will instead pass them in via the 'external_nat_ip_ids' variable"
#   type        = bool
#   default     = false
# }

# variable "external_nat_ip_ids" {
#   description = "List of EIP IDs to be assigned to the NAT Gateways (used in combination with reuse_nat_ips)"
#   type        = list(string)
#   default     = []
# }

# variable "external_nat_ips" {
#   description = "List of EIPs to be used for `nat_public_ips` output (used in combination with reuse_nat_ips and external_nat_ip_ids)"
#   type        = list(string)
#   default     = []
# }

# variable "nat_gateway_tags" {
#   description = "Additional tags for the NAT gateways"
#   type        = map(string)
#   default     = {}
# }

# variable "nat_eip_tags" {
#   description = "Additional tags for the NAT EIP"
#   type        = map(string)
#   default     = {}
# }

# ################################################################################
# # Customer Gateways
# ################################################################################

# variable "customer_gateways" {
#   description = "Maps of Customer Gateway's attributes (BGP ASN and Gateway's Internet-routable external IP address)"
#   type        = map(map(any))
#   default     = {}
# }

# variable "customer_gateway_tags" {
#   description = "Additional tags for the Customer Gateway"
#   type        = map(string)
#   default     = {}
# }

# ################################################################################
# # VPN Gateway
# ################################################################################

# variable "enable_vpn_gateway" {
#   description = "Should be true if you want to create a new VPN Gateway resource and attach it to the VPC"
#   type        = bool
#   default     = false
# }

# variable "vpn_gateway_id" {
#   description = "ID of VPN Gateway to attach to the VPC"
#   type        = string
#   default     = ""
# }

# variable "amazon_side_asn" {
#   description = "The Autonomous System Number (ASN) for the Amazon side of the gateway. By default the virtual private gateway is created with the current default Amazon ASN"
#   type        = string
#   default     = "64512"
# }

# variable "vpn_gateway_az" {
#   description = "The Availability Zone for the VPN Gateway"
#   type        = string
#   default     = null
# }

# variable "propagate_intra_route_tables_vgw" {
#   description = "Should be true if you want route table propagation"
#   type        = bool
#   default     = false
# }

# variable "propagate_private_route_tables_vgw" {
#   description = "Should be true if you want route table propagation"
#   type        = bool
#   default     = false
# }

# variable "propagate_public_route_tables_vgw" {
#   description = "Should be true if you want route table propagation"
#   type        = bool
#   default     = false
# }

# variable "vpn_gateway_tags" {
#   description = "Additional tags for the VPN gateway"
#   type        = map(string)
#   default     = {}
# }

# ################################################################################
# # Default VPC
# ################################################################################

# variable "manage_default_vpc" {
#   description = "Should be true to adopt and manage Default VPC"
#   type        = bool
#   default     = false
# }

# variable "default_vpc_name" {
#   description = "Name to be used on the Default VPC"
#   type        = string
#   default     = null
# }

# variable "default_vpc_enable_dns_support" {
#   description = "Should be true to enable DNS support in the Default VPC"
#   type        = bool
#   default     = true
# }

# variable "default_vpc_enable_dns_hostnames" {
#   description = "Should be true to enable DNS hostnames in the Default VPC"
#   type        = bool
#   default     = true
# }

# variable "default_vpc_tags" {
#   description = "Additional tags for the Default VPC"
#   type        = map(string)
#   default     = {}
# }

variable "manage_default_security_group" {
  description = "Should be true to adopt and manage default security group"
  type        = bool
  default     = true
}

variable "security_group" {
  description = "Name to be used on the default security group"
  type        = string
  default     = null
}

# variable "default_security_group_ingress" {
#   description = "List of maps of ingress rules to set on the default security group"
#   type        = list(map(string))
#   default     = []
# }

# variable "default_security_group_egress" {
#   description = "List of maps of egress rules to set on the default security group"
#   type        = list(map(string))
#   default     = []
# }

# variable "default_security_group_tags" {
#   description = "Additional tags for the default security group"
#   type        = map(string)
#   default     = {}
# }

# ################################################################################
# # Default Network ACLs
# ################################################################################

variable "manage_default_network_acl" {
  description = "Should be true to adopt and manage Default Network ACL"
  type        = bool
  default     = true
}

# variable "default_network_acl_name" {
#   description = "Name to be used on the Default Network ACL"
#   type        = string
#   default     = null
# }

# variable "default_network_acl_ingress" {
#   description = "List of maps of ingress rules to set on the Default Network ACL"
#   type        = list(map(string))
#   default = [
#     {
#       rule_no    = 100
#       action     = "allow"
#       from_port  = 0
#       to_port    = 0
#       protocol   = "-1"
#       cidr_block = "0.0.0.0/0"
#     },
#     {
#       rule_no         = 101
#       action          = "allow"
#       from_port       = 0
#       to_port         = 0
#       protocol        = "-1"
#       ipv6_cidr_block = "::/0"
#     },
#   ]
# }

# variable "default_network_acl_egress" {
#   description = "List of maps of egress rules to set on the Default Network ACL"
#   type        = list(map(string))
#   default = [
#     {
#       rule_no    = 100
#       action     = "allow"
#       from_port  = 0
#       to_port    = 0
#       protocol   = "-1"
#       cidr_block = "0.0.0.0/0"
#     },
#     {
#       rule_no         = 101
#       action          = "allow"
#       from_port       = 0
#       to_port         = 0
#       protocol        = "-1"
#       ipv6_cidr_block = "::/0"
#     },
#   ]
# }

# variable "default_network_acl_tags" {
#   description = "Additional tags for the Default Network ACL"
#   type        = map(string)
#   default     = {}
# }

# ################################################################################
# # Default Route
# ################################################################################

variable "manage_default_route_table" {
  description = "Should be true to manage default route table"
  type        = bool
}

# variable "default_route_table_name" {
#   description = "Name to be used on the default route table"
#   type        = string
#   default     = null
# }

# variable "default_route_table_propagating_vgws" {
#   description = "List of virtual gateways for propagation"
#   type        = list(string)
#   default     = []
# }

# variable "default_route_table_routes" {
#   description = "Configuration block of routes. See https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/default_route_table#route"
#   type        = list(map(string))
#   default     = []
# }

# variable "default_route_table_tags" {
#   description = "Additional tags for the default route table"
#   type        = map(string)
#   default     = {}
# }

# ################################################################################
# # Flow Log
# ################################################################################

# variable "enable_flow_log" {
#   description = "Whether or not to enable VPC Flow Logs"
#   type        = bool
#   default     = false
# }

# variable "vpc_flow_log_permissions_boundary" {
#   description = "The ARN of the Permissions Boundary for the VPC Flow Log IAM Role"
#   type        = string
#   default     = null
# }

# variable "flow_log_max_aggregation_interval" {
#   description = "The maximum interval of time during which a flow of packets is captured and aggregated into a flow log record. Valid Values: `60` seconds or `600` seconds"
#   type        = number
#   default     = 600
# }

# variable "flow_log_traffic_type" {
#   description = "The type of traffic to capture. Valid values: ACCEPT, REJECT, ALL"
#   type        = string
#   default     = "ALL"
# }

# variable "flow_log_destination_type" {
#   description = "Type of flow log destination. Can be s3, kinesis-data-firehose or cloud-watch-logs"
#   type        = string
#   default     = "cloud-watch-logs"
# }

# variable "flow_log_log_format" {
#   description = "The fields to include in the flow log record, in the order in which they should appear"
#   type        = string
#   default     = null
# }

# variable "flow_log_destination_arn" {
#   description = "The ARN of the CloudWatch log group or S3 bucket where VPC Flow Logs will be pushed. If this ARN is a S3 bucket the appropriate permissions need to be set on that bucket's policy. When create_flow_log_cloudwatch_log_group is set to false this argument must be provided"
#   type        = string
#   default     = ""
# }

# variable "flow_log_deliver_cross_account_role" {
#   description = "(Optional) ARN of the IAM role that allows Amazon EC2 to publish flow logs across accounts."
#   type        = string
#   default     = null
# }

# variable "flow_log_file_format" {
#   description = "(Optional) The format for the flow log. Valid values: `plain-text`, `parquet`"
#   type        = string
#   default     = null
# }

# variable "flow_log_hive_compatible_partitions" {
#   description = "(Optional) Indicates whether to use Hive-compatible prefixes for flow logs stored in Amazon S3"
#   type        = bool
#   default     = false
# }

# variable "flow_log_per_hour_partition" {
#   description = "(Optional) Indicates whether to partition the flow log per hour. This reduces the cost and response time for queries"
#   type        = bool
#   default     = false
# }

# variable "vpc_flow_log_tags" {
#   description = "Additional tags for the VPC Flow Logs"
#   type        = map(string)
#   default     = {}
# }

# ################################################################################
# # Flow Log CloudWatch
# ################################################################################

# variable "create_flow_log_cloudwatch_log_group" {
#   description = "Whether to create CloudWatch log group for VPC Flow Logs"
#   type        = bool
#   default     = false
# }

# variable "create_flow_log_cloudwatch_iam_role" {
#   description = "Whether to create IAM role for VPC Flow Logs"
#   type        = bool
#   default     = false
# }

# variable "flow_log_cloudwatch_iam_role_arn" {
#   description = "The ARN for the IAM role that's used to post flow logs to a CloudWatch Logs log group. When flow_log_destination_arn is set to ARN of Cloudwatch Logs, this argument needs to be provided"
#   type        = string
#   default     = ""
# }

# variable "flow_log_cloudwatch_log_group_name_prefix" {
#   description = "Specifies the name prefix of CloudWatch Log Group for VPC flow logs"
#   type        = string
#   default     = "/aws/vpc-flow-log/"
# }

# variable "flow_log_cloudwatch_log_group_name_suffix" {
#   description = "Specifies the name suffix of CloudWatch Log Group for VPC flow logs"
#   type        = string
#   default     = ""
# }

# variable "flow_log_cloudwatch_log_group_retention_in_days" {
#   description = "Specifies the number of days you want to retain log events in the specified log group for VPC flow logs"
#   type        = number
#   default     = null
# }

# variable "flow_log_cloudwatch_log_group_kms_key_id" {
#   description = "The ARN of the KMS Key to use when encrypting log data for VPC flow logs"
#   type        = string
#   default     = null
# }

# variable "flow_log_cloudwatch_log_group_skip_destroy" {
#   description = " Set to true if you do not wish the log group (and any logs it may contain) to be deleted at destroy time, and instead just remove the log group from the Terraform state"
#   type        = bool
#   default     = false
# }

# variable "flow_log_cloudwatch_log_group_class" {
#   description = "Specified the log class of the log group. Possible values are: STANDARD or INFREQUENT_ACCESS"
#   type        = string
#   default     = null
# }

#
variable "region" {
  description = "AWS region where these resources will get deployed"
  type = string
  default = "us-east-1"
}

#### S3 and KMS  ###########
variable "create" {
  description = "Determines whether resources will be created (affects all resources)"
  type        = bool
  default     = true
}



variable "deletion_window_in_days" {
  description = "The waiting period, specified in number of days. After the waiting period ends, AWS KMS deletes the KMS key. If you specify a value, it must be between `7` and `30`, inclusive. If you do not specify a value, it defaults to `30`"
  type        = number
  default     = 7
}

variable "aliases" {
  description = "A list of aliases to create. Note - due to the use of `toset()`, values must be static strings and not computed values"
  type        = list(string)
  default     = ["cloudtrail-root"]
}

variable "description" {
  description = "The description of the key as viewed in AWS console"
  type        = string
  default     = "The description of the key as viewed in AWS console"
}

variable "enable_key_rotation" {
  description = "Specifies whether key rotation is enabled. Defaults to `true`"
  type        = bool
  default     = true
}


# variable "attach_policy" {
#   type 		= bool
#   description =  "If this variable is set to true, you can attach the custom policy with variable var.policy, if it is false that means no custom policy is needed."
# }

# variable "s3_variable" {
#   type = map(any)
# }

variable "s3_variable" {
  type        = map(object({
    bucket_name =  string
    force_destroy = bool
    attach_policy = bool
  }))
  description = "Can create multiple S3"
}

# variable "versioning" {
#   description = "Map containing versioning configuration."
#   type        = map(string)
#   default     = {}
# }

 variable "lambda_functions" {
   description = "function"
   type        = map(any)
   default     = {}
 }

##################################### RDS VARIABLES #############################

variable "create_db_parameter_group" {
  type = bool
  default = false
}

variable "create_db_subnet_group" {
  type = bool
  default = false
}

variable "create_db_option_group" {
  type = bool
  default = false
}

variable "create_db_instance" {
  type = bool
  default = true
}

variable "db_subnet_group" {
  type = map(any)
  default = {
    
  }
}

variable "db_parameter_group" {
  type = map(any)
  default = {
    
  }
}

variable "db_option_group" {
  type = map(any)
  default = {
    
  }
}

variable "db_inst" {
  type = map(any)
  default = {
    
  }
}