data "aws_availability_zones" "available" {}

locals {
    azs      = slice(data.aws_availability_zones.available.names, 0, 3)
    region = var.region
    user_data = <<-EOT
    #!/bin/bash
    sudo yum update -y
    sudo yum install -y httpd
    systemctl start httpd
    systemctl enable httpd
    echo "<h1> this message from : $(hostname -i) </h1>"> /var/www/html/index.html
  EOT
  }

module "awsvpc" {
  source = "./vpc"
  name   = var.name
  cidr   = var.cidr

  azs             = var.azs
  #  private_subnets = [for k, v in var.azs : cidrsubnet(var.cidr, 8, k+2)]
  #  public_subnets  = [for k, v in var.azs : cidrsubnet(var.cidr, 8, k)]
  private_subnets = ["10.0.0.0/24","10.0.1.0/24"]
  public_subnets  = ["10.0.2.0/24","10.0.3.0/24"]
  public_subnet_names             = var.public_subnet_names 
  public_dedicated_network_acl    = var.public_dedicated_network_acl
  private_subnet_names          = var.private_subnet_names
  manage_default_network_acl    = var.manage_default_network_acl
  manage_default_route_table    = var.manage_default_route_table
  manage_default_security_group = var.manage_default_security_group
  

  enable_dns_hostnames = var.enable_dns_hostnames
  enable_dns_support   = var.enable_dns_support

  enable_nat_gateway = var.enable_nat_gateway
  single_nat_gateway = var.single_nat_gateway
  # enable_vpn_gateway = var.enable_vpn_gateway

  # enable_dhcp_options              = var.enable_dhcp_options
  # dhcp_options_domain_name         = var.dhcp_options_domain_name
  # dhcp_options_domain_name_servers = var.dhcp_options_domain_name_servers



  # enable_flow_log                      = var.enable_flow_log
  # create_flow_log_cloudwatch_log_group = var.create_flow_log_cloudwatch_log_group
  # create_flow_log_cloudwatch_iam_role  = var.create_flow_log_cloudwatch_iam_role
  # flow_log_max_aggregation_interval    = var.flow_log_max_aggregation_interval




  tags = var.tags
}

module "vpc_endpoint" {
  source = "./vpc_endpoint"
  for_each = var.endpoints

  vpc_id            = module.awsvpc.vpc_id
  service           = each.value.service
  service_name      = try(each.value.service_name, null)
  service_type      = try(each.value.service_type, "Interface")
  auto_accept       = try(each.value.auto_accept, null)
  security_group_ids = try(each.value.service_type, "Interface") == "Interface" ? [for sg in each.value.security_group_ids : module.security_group[sg].security_group_id]:null
  subnet_ids        =  try(each.value.service_type, "Interface") == "Interface" ?  module.awsvpc.private_subnets : null
  route_table_ids     = try(each.value.service_type, "Interface") == "Gateway" ? flatten([module.awsvpc.private_route_table_ids]): null 
  policy            = try(each.value.policy, null)
  private_dns_enabled = try(each.value.private_dns_enabled, null)
  tags =  merge(var.tags, try(each.value.tags, {}))
}


# module "security_group" {
#   source = "git::https://github.com/Quick-Iac/ceq_tf_template_aws_security_group.git"

#   for_each = var.SecurityGroups  # Creating SG per EC2 instance

#   name                   = "${each.key}-sg"  # Unique SG name per EC2 instance
#   description            = "${each.value.description}"
#   vpc_id                = module.awsvpc.vpc_id
#   ingress_cidr_blocks   = flatten([each.value.ingress_cidr_blocks])
#   egress_cidr_blocks    = flatten([each.value.egress_cidr_blocks])
#   ingress_rules         = flatten([each.value.ingress_rules])  # Passing dynamic rule per EC2
#   egress_rules          = flatten([each.value.engress_rules])  # Keeping egress the same for simplicity
#   egress_ipv6_cidr_blocks = null
#   tags                 = var.tags
# }

module "security_group" {
  source = "git::https://github.com/Quick-Iac/ceq_tf_template_aws_security_group.git"
  for_each = var.SecurityGroups  
  name                   = "${each.key}-sg"
  description            = each.value.description
  vpc_id                 = module.awsvpc.vpc_id
  number_of_computed_ingress_with_cidr_blocks = length(each.value.cidr_key)
  computed_ingress_with_cidr_blocks = length(each.value.cidr_key) > 0 ? [
    for k, v in each.value.cidr_key : {
      rule       = v.rule  
      from_port  = v.from_port
      to_port    = v.to_port
      protocol   = v.protocol
      cidr_blocks = v.source_security_group_id # FIXED: Ensuring it's a list of strings
    }
  ] : []
  egress_cidr_blocks     = flatten([each.value.egress_cidr_blocks])
  tags                   = var.tags
  # depends_on             = [module.security_group]
}





module "key_pair" {
  source = "git::https://github.com/Quick-Iac/ceq_tf_template_aws_ec2_keypair.git"
  key_name = "private_key_test"  # don't change the key name because if we change the key name so we need to update it in the apply.yml line number 179
}


module "security_group_RDS" {
  source = "git::https://github.com/Quick-Iac/ceq_tf_template_aws_security_group.git"

  for_each = var.SecurityGroups_RDS  

  name                   = "${each.key}-sg-RDS"
  description            = each.value.description
  vpc_id                 = module.awsvpc.vpc_id
  ingress_with_source_security_group_id = [
    for k,v in each.value.sg_key : {
      rule                     = v.rule  # Ensure this rule exists in var.rules
      from_port                = v.from_port
      to_port                  = v.to_port
      protocol                 = v.protocol
      source_security_group_id = module.security_group[k].security_group_id
    }
  ]
  number_of_computed_ingress_with_cidr_blocks = length(each.value.cidr_key)

  computed_ingress_with_cidr_blocks = length(each.value.cidr_key) > 0 ? [
    for k, v in each.value.cidr_key : {
      rule       = v.rule  
      from_port  = v.from_port
      to_port    = v.to_port
      protocol   = v.protocol
      cidr_blocks = v.source_security_group_id # FIXED: Ensuring it's a list of strings
    } if length(v.source_security_group_id) > 0
  ] : []


  egress_cidr_blocks     = flatten([each.value.egress_cidr_blocks])
  # ingress_rules          = flatten([each.value.ingress_rules])
  # egress_rules           = lookup(each.value, "egress_rules", [])  
  # egress_ipv6_cidr_blocks = null
  tags                   = var.tags
  depends_on             = [module.security_group]
}


# module "alb" {
#   source = "git::https://github.com/Quick-Iac/ceq_tf_template_aws_alb2.git"

#   for_each = var.albs
#   name                  = each.key
  
#   enable_deletion_protection = false
#   create_security_group = false
#   security_groups       = [module.security_group["ssh-rules"].security_group_id]
#   subnets              = module.awsvpc.public_subnets

#   timeouts = {
#     create = "10m"
#     update = "10m"
#     delete = "10m"
#   }

#   tags = var.tags

#   listeners = { for k, v in each.value.listeners :
#     k => {
#       port     = v.port
#       certificate_arn = v.port == 443 ? lookup(v, "certificate_arn", null) : null
#       # additional_certificate_arns = ["arn:aws:acm:us-east-1:533267235239:certificate/d3bfa7e3-c4cd-4c7f-ac2f-0b9501e9b29e"]
#       protocol = v.protocol
#       forward  = {
#         target_group_key = v.target_group_key
#         order            = v.order
#       }
#       default_action = {
#         type    = "forward"
#         forward = {
#           target_group_key = v.target_group_key
#           order            = v.order
#         }
#       }
#       rules = v.rules
#     }
#   }

#   target_groups = { for k, v in each.value.target_groups :
#     k => {
#       name              = v.name
#       port              = v.port
#       protocol          = v.protocol
#       target_type       = v.target_type
#       vpc_id            = module.awsvpc.vpc_id
#       create_attachment = v.create_attachment
#     }
#   }
# }





# module "ASG" {
#   source = "./Auto_scaling_group"
#   for_each = var.multipe_asg
#   use_name_prefix = false
#   instance_name   = "web-server-turbo"
#   tag_specifications = [
    
#     {
#       resource_type = "instance"
#       tags          = { 
#       "START_DATE"       = ""
#       "END_DATE"         = ""
#       "PROJECT_NAME"     = "CSB"
#       "DEPARTMENT_NAME"  = "DevOps"
#       "APPLICATION_NAME" = "AWS VPC"
#       "CLIENT_NAME"      = "CSB"
#       "OWNER_NAME"       = "suraj.kaul@cloudeq.com"
#       "SOW_NUMBER"       = "1284864" 
#       }
#     },
#     {
#       resource_type = "volume"
#       tags          = { 
#       "START_DATE"       = ""
#       "END_DATE"         = ""
#       "PROJECT_NAME"     = "CSB"
#       "DEPARTMENT_NAME"  = "DevOps"
#       "APPLICATION_NAME" = "AWS VPC"
#       "CLIENT_NAME"      = "CSB"
#       "OWNER_NAME"       = "suraj.kaul@cloudeq.com"
#       "SOW_NUMBER"       = "1284864" 
#       }
#     }
#   ,
#   ] 
# traffic_source_attachments = {
#     for k, lb in each.value.alb_arn : "example-${each.key}-${k}" => {
#       traffic_source_identifier = module.alb[lb].target_groups[k].arn
#       traffic_source_type       = "elbv2"
#     }
#   }

  # ignore_desired_capacity_changes = false

  # min_size                  = 1
  # max_size                  = 3
  # desired_capacity          = 1
  # wait_for_capacity_timeout = 0
  # default_instance_warmup   = 300
  # health_check_type         = "EC2"
  #  vpc_zone_identifier       = each.value.is_public ? module.awsvpc.public_subnets : module.awsvpc.private_subnets
  # name                        = each.value.name
  # launch_template_name        = each.value.launch_template_name
  # launch_template_description = each.value.launch_template_description #"web-asg-launch-template"
  # update_default_version      = true

  # image_id          = each.value.image_id #"ami-0c614dee691cbbf37"
  # instance_type     = each.value.instance_type #"t3.micro"
  # user_data         = base64encode(local.user_data)
  # ebs_optimized     = true
  # enable_monitoring = true


  # # Security group is set on the ENIs below
  # security_groups          = [module.asg_sg.security_group_id]
    # block_device_mappings =[ for mapping in each.value.block_device_mappings : {
    #   device_name = mapping.device_name
    #   no_device   = mapping.no_device
    #   ebs = {
    #     delete_on_termination = mapping.ebs.delete_on_termination
    #     encrypted             = mapping.ebs.encrypted
    #     volume_size           = mapping.ebs.volume_size
    #     volume_type           = mapping.ebs.volume_type
    #   }
    # }]
 

#   capacity_reservation_specification = {
#     capacity_reservation_preference = "open"
#   }

#   cpu_options = {
#     core_count       = 1
#     threads_per_core = 1
#   }

#   credit_specification = {
#     cpu_credits = "standard"
#   }

#   maintenance_options = {
#     auto_recovery = "default"
#   }

#   metadata_options = {
#     http_endpoint               = "enabled"
#     http_tokens                 = "required"
#     http_put_response_hop_limit = 32
#     instance_metadata_tags      = "enabled"
#   }

#   network_interfaces = [ for interface in each.value.network_interfaces : {

#   delete_on_termination = interface.delete_on_termination
#   description           = interface.description
#   associate_public_ip_address = interface.associate_public_ip_address
#   device_index          = interface.device_index
#   security_groups       = [for sg in each.value.security_groups : module.security_group_RDS[sg].security_group_id]
#   connection_tracking_specification = {
#     tcp_established_timeout = interface.connection_tracking_specification.tcp_established_timeout
#     udp_stream_timeout      = interface.connection_tracking_specification.udp_stream_timeout
#     udp_timeout             = interface.connection_tracking_specification.udp_timeout
#   }
# }]

# ########### IF YOU WANT TO RUN ASG THEN UNCOMMENT THE LINE 135 - 170 AND 329-340 AND 362-379 #########################  

  # network_interfaces = [
  #   {
  #     delete_on_termination = true
  #     description           = "eth0"
  #     device_index          = 0
  #     associate_public_ip_address = true
  #     security_groups       = [for sg in each.value.security_groups : module.security_group[sg].security_group_id]
  #     # subnet_id             = each.value.is_public ? module.awsvpc.public_subnets[index(keys(var.multipe_asg), each.key)] : module.awsvpc.private_subnets[index(keys(var.multipe_asg), each.key)] # Accessing subnet using k
  #     connection_tracking_specification = {
  #       tcp_established_timeout = 60
  #       udp_stream_timeout      = 60
  #       udp_timeout             = 60
  #     }
  #   }
  # ]

  # scaling_policies = {
  #   avg-cpu-policy-greater-than-50 = {
  #     policy_type               = "TargetTrackingScaling"
  #     estimated_instance_warmup = 300
  #     target_tracking_configuration = {
  #       predefined_metric_specification = {
  #         predefined_metric_type = "ASGAverageCPUUtilization"
  #       }
  #       target_value = 50.0
  #     }
  #   },
  #   predictive-scaling = {
  #     # policy_type = "PredictiveScaling"
  #     # predictive_scaling_configuration = {
  #     #   mode                         = "ForecastAndScale"
  #     #   scheduling_buffer_time       = 10
  #     #   max_capacity_breach_behavior = "IncreaseMaxCapaci-ty"
  #     #   max_capacity_buffer          = 10
  #     #   metric_specification = {
  #     #     target_value = 32
  #     #     predefined_scaling_metric_specification = {
  #     #       predefined_metric_type = "ASGAverageCPUUtilization"
  #     #       resource_label         = "testLabel"
  #     #     }
  #     #     predefined_load_metric_specification = {
  #     #       predefined_metric_type = "ASGTotalCPUUtilization"
  #     #       resource_label         = "testLabel"
  #     #     }
  #     #   }
  #     # }
  #   }
  #   request-count-per-target = {
  #     # policy_type               = "TargetTrackingScaling"
  #     # estimated_instance_warmup = 120
  #     # target_tracking_configuration = {
  #     #   predefined_metric_specification = {
  #     #     predefined_metric_type = "ALBRequestCountPerTarget"
  #     #     resource_label         = "${module.alb.arn_suffix}/${module.alb.target_groups["ex_asg"].arn_suffix}"
  #     #   }
  #     #   target_value = 800
  #     # }
  #   }
  #   scale-out = {
  #     # name                      = "scale-out"
  #     # adjustment_type           = "ExactCapacity"
  #     # policy_type               = "StepScaling"
  #     # estimated_instance_warmup = 120
  #     # step_adjustment = [
  #     #   {
  #     #     scaling_adjustment          = 1
  #     #     metric_interval_lower_bound = 0
  #     #     metric_interval_upper_bound = 10
  #     #   },
  #     #   {
  #     #     scaling_adjustment          = 2
  #     #     metric_interval_lower_bound = 10
  #     #   }
  #     # ]
  #   }
  # }

#  scaling_policies = { for k, v in each.value.scaling_policies : 
#  k => {
#   policy_type               = v.policy_type
#   estimated_instance_warmup = lookup(v, "estimated_instance_warmup", null)

#   # Target Tracking Configuration
#   target_tracking_configuration = lookup(v, "target_tracking_configuration", null) != null ? {
#     predefined_metric_specification = {
#       predefined_metric_type = v.target_tracking_configuration.predefined_metric_specification.predefined_metric_type
#     }
#     target_value = v.target_tracking_configuration.target_value
#   } : null

#   #Predictive Scaling Configuration (optional)
#   # predictive_scaling_configuration = lookup(v, "predictive_scaling_configuration", null) != null ? {
#   #   mode                         = v.predictive_scaling_configuration.mode
#   #   scheduling_buffer_time       = lookup(v.predictive_scaling_configuration, "scheduling_buffer_time", null)
#   #   max_capacity_breach_behavior = lookup(v.predictive_scaling_configuration, "max_capacity_breach_behavior", null)
#   #   max_capacity_buffer          = lookup(v.predictive_scaling_configuration, "max_capacity_buffer", null)
#   #   metric_specification = lookup(v.predictive_scaling_configuration, "metric_specification", null) != null ? {
#   #     target_value = v.predictive_scaling_configuration.metric_specification.target_value
#   #     predefined_scaling_metric_specification = lookup(v.predictive_scaling_configuration.metric_specification, "predefined_scaling_metric_specification", null) != null ? {
#   #       predefined_metric_type = v.predictive_scaling_configuration.metric_specification.predefined_scaling_metric_specification.predefined_metric_type
#   #       resource_label         = lookup(v.predictive_scaling_configuration.metric_specification.predefined_scaling_metric_specification, "resource_label", null)
#   #     } : null
#   #     predefined_load_metric_specification = lookup(v.predictive_scaling_configuration.metric_specification, "predefined_load_metric_specification", null) != null ? {
#   #       predefined_metric_type = v.predictive_scaling_configuration.metric_specification.predefined_load_metric_specification.predefined_metric_type
#   #       resource_label         = lookup(v.predictive_scaling_configuration.metric_specification.predefined_load_metric_specification, "resource_label", null)
#   #     } : null
#   #   } : null
#   # } : null

  #Step Adjustment Configuration (optional)
#   step_adjustment = lookup(v, "step_adjustment", null) != null ? [
#     for step in v.step_adjustment : {
#       scaling_adjustment          = step.scaling_adjustment
#       metric_interval_lower_bound = lookup(step, "metric_interval_lower_bound", null)
#       metric_interval_upper_bound = lookup(step, "metric_interval_upper_bound", null)
#     }
#   ] : []
# }}

    

#   placement = {
#     # availability_zone = each.value.availability_zone
#   }

#   tags = var.tags

# }





# module "root-cloudtrail" {
#   source                            = "./ceq_tf_template_root_account_cloudtrail"
#   depends_on = [module.s3_bucket]
#   enable_cloudwatch_logs            = var.enable_cloudwatch_logs
#   name                              = var.root_cloudtrail_name
#   cloudwatch_logs_retention_in_days = var.cloudwatch_logs_retention_in_days
#   create_kms_key                    = module.kms.key_arn
#   #enable_sns_notifications          = module.sns["cloudtrail"].topic_name
#   s3_bucket_name                    = module.s3_bucket["CSB1"].s3_bucket_id
#   s3_key_prefix                     = var.s3_key_prefix
#   enable_log_file_validation        = var.enable_log_file_validation
#   enable_logging                    = var.enable_logging
#   include_global_service_events     = var.include_global_service_events
#   is_multi_region_trail             = var.is_multi_region_trail
#   is_organization_trail             = var.is_organization_trail
#   event_selectors                   = var.event_selectors
#   insight_selectors                 = var.insight_selectors
#   tags                              = var.tags
# }

# module "alerts" {
#   source                    = "./ceq_tf_template_root_account_alert_cloudtrail"
#   root_usage                = var.root_usage
#   pattern                   = "{ $.userIdentity.type = \"Root\" && $.userIdentity.invokedBy NOT EXISTS && $.eventType != \"AwsServiceEvent\" }"
#   comparison_operator       = var.comparison_operator
#   cloudtrail_log_group_name = module.root-cloudtrail.cloudwatch_logs_group_name
#   metric_name               = var.metric_name
#   evaluation_periods        = var.evaluation_periods
#   alarm_namespace           = var.alarm_namespace
#   period                    = var.period
#   statistic                 = var.statistic
#   threshold                 = var.threshold
#   alarm_description         = var.alarm_description
#   alarm_sns_topic_arn       = module.sns["Root"].topic_arn
#   tags                      = var.tags

# }

# #---------------------------- KMS-----------------------------#
module "kms" {
  source                  = "./ceq_tf_template_aws_kms"
  create                  = var.create
  deletion_window_in_days = var.deletion_window_in_days
  description             = var.description
  enable_key_rotation     = var.enable_key_rotation
  aliases                 = var.aliases
  tags                    = var.tags
}

######## Data block for s3 cloudtrailalerts #########

# data "aws_iam_policy_document" "cloudtrail_policy" {
#   for_each = { for k, v in var.s3_variable : k => v if k == "CSB1" }
#   statement {
#     sid = "Allow PutObject"
#     actions = [
#       "s3:PutObject"
#     ]

#     resources = ["arn:aws:s3:::${each.value.bucket_name}/*"]

#     principals {
#       type        = "Service"
#       identifiers = ["cloudtrail.amazonaws.com"]
#     }
#     condition {
#       test     = "StringLike"
#       variable = "s3:x-amz-acl"
#       values   = ["bucket-owner-full-control"]
#     }
#     }
#   statement {
#     sid = "Allow GetBucketLocation"
#     actions = [
#       "s3:GetBucketLocation",
#       "s3:GetBucketAcl",
#       "s3:ListBucket"
#     ]

#     resources = ["arn:aws:s3:::${each.value.bucket_name}"]

#     principals {
#       type        = "Service"
#       identifiers = ["cloudtrail.amazonaws.com"]
#     }
#   }
# }
# # # #--------------------------------------------S3------------------------------------#
# module "s3_bucket" {
#   source = "./ceq_tf_template_aws_s3"
#   for_each = var.s3_variable
#   bucket =  each.value.bucket_name
#   force_destroy = each.value.force_destroy
#   server_side_encryption_configuration = {
#     rule = {
#       apply_server_side_encryption_by_default = {
#         kms_master_key_id = module.kms.key_id
#         sse_algorithm     = "aws:kms"
#       }
#       bucket_key_enabled = true
#     }
#   }
#   #  versioning = {
#   #   enabled = var.versioning
#   # }
#   attach_policy = each.value.attach_policy
#   policy        = each.key == "CSB1" ? data.aws_iam_policy_document.cloudtrail_policy["CSB1"].json :""
# }

# # ####### SNS #########

# module "sns" {
#   source            = "./ceq_tf_template_aws_sns"
#   for_each          = var.sns_variable
#   create            = var.create
#   name              = each.value.sns_topic_name
#   kms_master_key_id = module.kms.key_id
#   subscriptions     = each.value.subscriptions
#   tags              = var.tags
  

# }




# data "archive_file" "lambda" {
#   for_each = var.lambda_functions

#   type        = "zip"
#   source_file = "${each.value.file}"
#   output_path = "${path.module}/${each.key}.zip"
# }



# module "lambda_function" {
#   depends_on = [ module.s3_bucket ]
#   source = "./ceq_tf_template_aws_lambda"

#   for_each = var.lambda_functions  

#   function_name          = "${each.key}"
#   description            = "${each.value.description_lambda}"
#   handler                = "${each.value.lambda_handler}"
#   runtime                = "${each.value.runtime_lambda}"
#   ephemeral_storage_size = 10240
#   architectures          = flatten([each.value.architectures_lambda])
#   publish                = "${each.value.publish_lambda}"
#   kms_key_arn            = module.kms.key_arn
#   source_file =  data.archive_file.lambda[each.key].output_path
#   s3_object_override_default_tags  = true

#   # ✅ Use the ZIP storage bucket for Lambda deployment
#   store_on_s3 = "${each.value.store_on_s3_lambda}"
#   s3_bucket   = "${module.s3_bucket["CSB2"].s3_bucket_id}"
#   s3_prefix   = "lambda-builds/lambda1/"
#   create_s3_notification = "${each.value.create_s3_notification}"
#   s3_bucket_notification = {
#     for key, value in each.value.s3_bucket_notification : key => {
#       bucket_id       = "${module.s3_bucket[value.bucket_name].s3_bucket_id}"
#       event           = flatten([value.event])
#       policy_resource = "${module.s3_bucket[value.bucket_name].s3_bucket_arn}"
#       action          = "${value.action}"
#       role_name       = "${value.role_name}"
#       policy_name     = "${value.policy_name}"
#     }
#   } 

#   allowed_triggers = {
#     for key, value in each.value.allowed_triggers : key => {
#       statement_id   = "${value.statement_id}"
#       action         = "${value.action}"
#       function_name  = "${each.key}"
#       principal      = "${value.principal}"
#       source_arn     = try("${value.bucket_name}", null) != null ? "${module.s3_bucket[value.bucket_name].s3_bucket_arn}" : "${value.source_arn}"
#     }
#   }
#   artifacts_dir = "${path.root}/.terraform/lambda-builds/"
#   environment_variables = "${each.value.environment_variables_lambda}"

#   role_path   = "/tf-managed/"
#   policy_path = "/tf-managed/"

#   number_of_policy_jsons = each.value.number_of_policy_jsons_lambda
#   attach_policy          = "${each.value.attach_policy_lambda}"
#   policy                = "${each.value.policy_lambda}"
#   attach_policies       = "${each.value.attach_policies_lambda}"
#   policies              = flatten([each.value.policies_lambda])
#   number_of_policies    = each.value.number_of_policies_lambda

#   attach_policy_statements = "${each.value.attach_policy_statements_lambda}"
#   policy_statements        = "${each.value.policy_statements_lambda}"
#   timeouts                 = "${each.value.timeouts_lambda}"

#   function_tags = "${each.value.function_lang}"
#   tags = var.tags
# }






module "db_subnet_group" {
  source = "./modules/db_subnet_group"

  # create = local.create_db_subnet_group
  for_each = var.create_db_subnet_group ? var.db_subnet_group : {}

  name            = each.key
  # use_name_prefix = var.db_subnet_group_use_name_prefix
  description     = each.value.db_subnet_group_description
  subnet_ids      = module.awsvpc.public_subnets

  tags = var.tags
}

module "db_parameter_group" {
  source = "./modules/db_parameter_group"

  for_each = var.create_db_parameter_group ? var.db_parameter_group : {}

  name            = each.key
  description     = each.value.parameter_group_description
  family          = each.value.family

  # parameters = [for k, v in each.value.parameters : { name = k, value = v }]

  tags = var.tags
}

module "db_option_group" {
  source = "./modules/db_option_group"

  for_each = var.create_db_option_group ? var.db_option_group : {}

  name                     = each.key
  # use_name_prefix          = var.option_group_use_name_prefix
  option_group_description = each.value.option_group_description
  engine_name              = each.value.engine
  major_engine_version     = each.value.major_engine_version

  # options = var.options

  timeouts = each.value.option_group_timeouts

  tags = var.tags
}

module "secret_manager" {
  source = "./modules/Secret_manager"
  rds_username = var.rds_username
  rds_password = var.rds_password
  # secret_name = var.secret_name
}

module "db_instance" {
  source = "./modules/db_instance"

  for_each = var.create_db_instance ? var.db_inst : {}
  identifier            = each.value.identifier
  # # use_identifier_prefix = var.instance_use_identifier_prefix

  engine            = each.value.engine
  engine_version    = each.value.engine_version
  instance_class    = each.value.instance_class
  allocated_storage = each.value.allocated_storage
  storage_type      = each.value.storage_type
  storage_encrypted = each.value.storage_encrypted
  kms_key_id        = module.kms.key_arn
  license_model     = each.value.license_model

  username             = module.secret_manager.oracle_db_username
  password = module.secret_manager.oracle_db_password
  port                                = each.value.port


  # domain                              = var.domain
  # domain_auth_secret_arn              = var.domain_auth_secret_arn
  # domain_dns_ips                      = var.domain_dns_ips
  # domain_fqdn                         = var.domain_fqdn
  # domain_iam_role_name                = var.domain_iam_role_name
  # domain_ou                           = var.domain_ou
  iam_database_authentication_enabled = each.value.iam_database_authentication_enabled
  # custom_iam_instance_profile         = var.custom_iam_instance_profile
  # manage_master_user_password         = var.manage_master_user_password
  # master_user_secret_kms_key_id       = var.master_user_secret_kms_key_id

  # manage_master_user_password_rotation                   = var.manage_master_user_password_rotation
  # master_user_password_rotate_immediately                = var.master_user_password_rotate_immediately
  # master_user_password_rotation_automatically_after_days = var.master_user_password_rotation_automatically_after_days
  # master_user_password_rotation_duration                 = var.master_user_password_rotation_duration
  # master_user_password_rotation_schedule_expression      = var.master_user_password_rotation_schedule_expression

  vpc_security_group_ids = [for sg in each.value.security_group : module.security_group_RDS[sg].security_group_id]
  db_subnet_group_name   = module.db_subnet_group[each.value.db_subnet_group].db_subnet_group_id
  parameter_group_name   = module.db_parameter_group[each.value.parameter_group_name].db_parameter_group_id
  option_group_name      = each.value.engine != "postgres" ? module.db_option_group[each.value.option_group_name].db_option_group_id : null
  # network_type           = var.network_type

  # availability_zone    = each.value.availability_zone
  multi_az             = each.value.multi_az
  iops                 = each.value.iops
  # storage_throughput   = var.storage_throughput
  publicly_accessible  = each.value.publicly_accessible
  # ca_cert_identifier   = var.ca_cert_identifier
  # dedicated_log_volume = var.dedicated_log_volume

  # allow_major_version_upgrade = var.allow_major_version_upgrade
  # auto_minor_version_upgrade  = var.auto_minor_version_upgrade
  # apply_immediately           = var.apply_immediately
  maintenance_window          = each.value.maintenance_window
  # blue_green_update           = var.blue_green_update

  # snapshot_identifier              = var.snapshot_identifier
  # copy_tags_to_snapshot            = var.copy_tags_to_snapshot
  skip_final_snapshot              = each.value.skip_final_snapshot
  # final_snapshot_identifier_prefix = var.final_snapshot_identifier_prefix

  performance_insights_enabled          = each.value.performance_insights_enabled
  performance_insights_retention_period = each.value.performance_insights_retention_period
  # performance_insights_kms_key_id       = var.performance_insights_enabled ? var.performance_insights_kms_key_id : null

  # replicate_source_db                  = var.replicate_source_db
  replica_mode                         = each.value.replica_mode
  backup_retention_period              = each.value.backup_retention_period
  backup_window                        = each.value.backup_window
  max_allocated_storage                = each.value.max_allocated_storage
  # monitoring_interval                  = var.monitoring_interval
  # monitoring_role_arn                  = var.monitoring_role_arn
  # monitoring_role_name                 = var.monitoring_role_name
  # monitoring_role_use_name_prefix      = var.monitoring_role_use_name_prefix
  # monitoring_role_description          = var.monitoring_role_description
  # create_monitoring_role               = var.create_monitoring_role
  # monitoring_role_permissions_boundary = var.monitoring_role_permissions_boundary

  character_set_name       = each.value.character_set_name
  nchar_character_set_name = each.value.nchar_character_set_name
  # timezone                 = var.timezone

  enabled_cloudwatch_logs_exports        = flatten([each.value.enabled_cloudwatch_logs_exports])
  create_cloudwatch_log_group            = each.value.create_cloudwatch_log_group
  # cloudwatch_log_group_retention_in_days = var.cloudwatch_log_group_retention_in_days
  # cloudwatch_log_group_kms_key_id        = var.cloudwatch_log_group_kms_key_id
  # cloudwatch_log_group_skip_destroy      = var.cloudwatch_log_group_skip_destroy
  # cloudwatch_log_group_class             = var.cloudwatch_log_group_class

  # timeouts = var.timeouts

  # deletion_protection      = var.deletion_protection
  delete_automated_backups = each.value.delete_automated_backups

  # restore_to_point_in_time = var.restore_to_point_in_time
  # s3_import                = var.s3_import

  db_instance_tags = var.tags
  tags             = var.tags
}




# module "db_instance_role_association" {
#   source = "./modules/db_instance_role_association"
#   iam_policy_name = "rds-secret-access-policy"
#   role_name = "rds-secret-access-role"
#   policy_resource = "arn:aws:secretsmanager:us-east-1:533267235239:secret:${var.secret_name}"

#   # for_each = { for k, v in var.db_instance_role_associations : k => v if var.create_db_instance }

#   # feature_name           = each.key
#   # role_arn               = each.value
#   # db_instance_identifier = module.db_instance.db_instance_identifier
# }


