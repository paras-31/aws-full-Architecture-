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
  private_subnets = var.private_subnet
  public_subnets  = var.public_subnet
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


module "security_group" {
  source = "./Template SG"
  for_each = var.SecurityGroups  
  name                   = "${each.key}-sg"
  description            = each.value.description
  vpc_id                 = module.awsvpc.vpc_id
  number_of_computed_ingress_with_cidr_blocks = length(each.value.cidr_key)
  computed_ingress_with_cidr_blocks = length(each.value.cidr_key) > 0 ? [
    for k, v in each.value.cidr_key : {
      from_port  = v.from_port
      to_port    = v.to_port
      protocol   = v.protocol
      cidr_blocks = v.source_security_group_id # FIXED: Ensuring it's a list of strings
    }
  ] : []
  egress_cidr_blocks     = flatten([each.value.egress_cidr_blocks])
  tags                   = var.tags
}





module "key_pair" {
  source = "./Key_Pair"
  key_name = "private_key_test"  # don't change the key name because if we change the key name so we need to update it in the apply.yml line number 179
}


module "security_group_RDS" {
  source = "./Template SG"

  for_each = var.SecurityGroups_RDS  

  name                   = "${each.key}-sg-RDS"
  description            = each.value.description
  vpc_id                 = module.awsvpc.vpc_id
  ingress_with_source_security_group_id = [
    for k,v in each.value.sg_key : {
      from_port                = v.from_port
      to_port                  = v.to_port
      protocol                 = v.protocol
      source_security_group_id = module.security_group[k].security_group_id
    }
  ]
  number_of_computed_ingress_with_cidr_blocks = length(each.value.cidr_key)

  computed_ingress_with_cidr_blocks = length(each.value.cidr_key) > 0 ? [
    for k, v in each.value.cidr_key : {  
      from_port  = v.from_port
      to_port    = v.to_port
      protocol   = v.protocol
      cidr_blocks = v.source_security_group_id # FIXED: Ensuring it's a list of strings
    } if length(v.source_security_group_id) > 0
  ] : []


  egress_cidr_blocks     = flatten([each.value.egress_cidr_blocks])
  tags                   = var.tags
  depends_on             = [module.security_group]
}


module "alb" {
  source = "./ALB"

  for_each = var.albs
  name                  = each.value.alb_name
  
  enable_deletion_protection = false
  create_security_group = false
  security_groups       = [module.security_group[each.value.sg_name].security_group_id]
  subnets              = module.awsvpc.public_subnets

  timeouts = {
    create = "10m"
    update = "10m"
    delete = "10m"
  }

  tags = var.tags

  listeners = { for k, v in each.value.listeners :
    k => {
      port     = v.port
      certificate_arn = v.port == 443 ? lookup(v, "certificate_arn", null) : null
      # additional_certificate_arns = ["arn:aws:acm:us-east-1:533267235239:certificate/d3bfa7e3-c4cd-4c7f-ac2f-0b9501e9b29e"]
      protocol = v.protocol
      forward  = {
        target_group_key = v.target_group_key
        order            = v.order
      }
      default_action = {
        type    = "forward"
        forward = {
          target_group_key = v.target_group_key
          order            = v.order
        }
      }
      rules = v.rules
    }
  }

  target_groups = { for k, v in each.value.target_groups :
    k => {
      name              = v.name
      port              = v.port
      protocol          = v.protocol
      target_type       = v.target_type
      vpc_id            = module.awsvpc.vpc_id
      create_attachment = v.create_attachment
    }
  }
}





module "ASG" {
  source = "./Auto_scaling_group"
  for_each = var.multipe_asg
  use_name_prefix = false
  instance_name   = "web-server-turbo"
  tag_specifications = [
    
    {
      resource_type = "instance"
      tags          = { 
      "START_DATE"       = ""
      "END_DATE"         = ""
      "PROJECT_NAME"     = "CSB"
      "DEPARTMENT_NAME"  = "DevOps"
      "APPLICATION_NAME" = "AWS VPC"
      "CLIENT_NAME"      = "CSB"
      "OWNER_NAME"       = "suraj.kaul@cloudeq.com"
      "SOW_NUMBER"       = "1284864" 
      }
    },
    {
      resource_type = "volume"
      tags          = { 
      "START_DATE"       = ""
      "END_DATE"         = ""
      "PROJECT_NAME"     = "CSB"
      "DEPARTMENT_NAME"  = "DevOps"
      "APPLICATION_NAME" = "AWS VPC"
      "CLIENT_NAME"      = "CSB"
      "OWNER_NAME"       = "suraj.kaul@cloudeq.com"
      "SOW_NUMBER"       = "1284864" 
      }
    }
  ,
  ] 
traffic_source_attachments = {
    for k, lb in each.value.alb_arn : "example-${each.key}-${k}" => {
      traffic_source_identifier = module.alb[lb].target_groups[k].arn
      traffic_source_type       = "elbv2"
    }
  }

  # ignore_desired_capacity_changes = false

  min_size                  = each.value.min
  max_size                  = each.value.max
  desired_capacity          = each.value.desired_capacity
  wait_for_capacity_timeout = each.value.wait_for_capacity_timeout
  default_instance_warmup   = each.value.default_instance_warmup
  health_check_type         = each.value.health_check_type
  vpc_zone_identifier       = each.value.is_public ? module.awsvpc.public_subnets : module.awsvpc.private_subnets
  name                        = each.value.name
  launch_template_name        = each.value.launch_template_name
  launch_template_description = each.value.launch_template_description #"web-asg-launch-template"
  update_default_version      = true

  image_id          = each.value.image_id #"ami-0c614dee691cbbf37"
  instance_type     = each.value.instance_type #"t3.micro"
  user_data         = base64encode(local.user_data)
  ebs_optimized     = true
  enable_monitoring = true


  # Security group is set on the ENIs below
  
    block_device_mappings =[ for mapping in each.value.block_device_mappings : {
      device_name = mapping.device_name
      no_device   = mapping.no_device
      ebs = {
        delete_on_termination = mapping.ebs.delete_on_termination
        encrypted             = mapping.ebs.encrypted
        volume_size           = mapping.ebs.volume_size
        volume_type           = mapping.ebs.volume_type
      }
    }]
 

  capacity_reservation_specification = {
    capacity_reservation_preference = "open"
  }

  cpu_options = {
    core_count       = 1
    threads_per_core = 1
  }

  credit_specification = {
    cpu_credits = "standard"
  }

  maintenance_options = {
    auto_recovery = "default"
  }

  metadata_options = {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 32
    instance_metadata_tags      = "enabled"
  }

  network_interfaces = [ for interface in each.value.network_interfaces : {

  delete_on_termination = interface.delete_on_termination
  description           = interface.description
  associate_public_ip_address = interface.associate_public_ip_address
  device_index          = interface.device_index
  security_groups       = [for sg in each.value.security_groups : module.security_group_RDS[sg].security_group_id]
  connection_tracking_specification = {
    tcp_established_timeout = interface.connection_tracking_specification.tcp_established_timeout
    udp_stream_timeout      = interface.connection_tracking_specification.udp_stream_timeout
    udp_timeout             = interface.connection_tracking_specification.udp_timeout
  }
}]  
####### scaling policies ###############
 scaling_policies = { for k, v in each.value.scaling_policies : 
  k => {
  policy_type               = v.policy_type
  estimated_instance_warmup = lookup(v, "estimated_instance_warmup", null)

  # Target Tracking Configuration
  target_tracking_configuration = lookup(v, "target_tracking_configuration", null) != null ? {
    predefined_metric_specification = {
      predefined_metric_type = v.target_tracking_configuration.predefined_metric_specification.predefined_metric_type
    }
    target_value = v.target_tracking_configuration.target_value
  } : null


  #Step Adjustment Configuration (optional)
  step_adjustment = lookup(v, "step_adjustment", null) != null ? [
    for step in v.step_adjustment : {
      scaling_adjustment          = step.scaling_adjustment
      metric_interval_lower_bound = lookup(step, "metric_interval_lower_bound", null)
      metric_interval_upper_bound = lookup(step, "metric_interval_upper_bound", null)
    }
  ] : []
}}


  placement = {
    # availability_zone = each.value.availability_zone
  }

  tags = var.tags

}





module "root-cloudtrail" {
  source                            = "./ceq_tf_template_root_account_cloudtrail"
  depends_on = [module.s3_bucket]
  enable_cloudwatch_logs            = var.enable_cloudwatch_logs
  name                              = var.root_cloudtrail_name
  cloudwatch_logs_retention_in_days = var.cloudwatch_logs_retention_in_days
  create_kms_key                    = module.kms.key_arn
  #enable_sns_notifications          = module.sns["cloudtrail"].topic_name
  s3_bucket_name                    = module.s3_bucket["CSB1"].s3_bucket_id
  s3_key_prefix                     = var.s3_key_prefix
  enable_log_file_validation        = var.enable_log_file_validation
  enable_logging                    = var.enable_logging
  include_global_service_events     = var.include_global_service_events
  is_multi_region_trail             = var.is_multi_region_trail
  is_organization_trail             = var.is_organization_trail
  event_selectors                   = var.event_selectors
  insight_selectors                 = var.insight_selectors
  tags                              = var.tags
}

module "alerts" {
  source                    = "./ceq_tf_template_root_account_alert_cloudtrail"
  root_usage                = var.root_usage
  pattern                   = "{ $.userIdentity.type = \"Root\" && $.userIdentity.invokedBy NOT EXISTS && $.eventType != \"AwsServiceEvent\" }"
  comparison_operator       = var.comparison_operator
  cloudtrail_log_group_name = module.root-cloudtrail.cloudwatch_logs_group_name
  metric_name               = var.metric_name
  evaluation_periods        = var.evaluation_periods
  alarm_namespace           = var.alarm_namespace
  period                    = var.period
  statistic                 = var.statistic
  threshold                 = var.threshold
  alarm_description         = var.alarm_description
  alarm_sns_topic_arn       = module.sns["Root"].topic_arn
  tags                      = var.tags

}

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

data "aws_iam_policy_document" "cloudtrail_policy" {
  for_each = { for k, v in var.s3_variable : k => v if k == "CSB1" }
  statement {
    sid = "Allow PutObject"
    actions = [
      "s3:PutObject"
    ]

    resources = ["arn:aws:s3:::${each.value.bucket_name}/*"]

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    condition {
      test     = "StringLike"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }
    }
  statement {
    sid = "Allow GetBucketLocation"
    actions = [
      "s3:GetBucketLocation",
      "s3:GetBucketAcl",
      "s3:ListBucket"
    ]

    resources = ["arn:aws:s3:::${each.value.bucket_name}"]

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
  }
}
# # #--------------------------------------------S3------------------------------------#
module "s3_bucket" {
  source = "./ceq_tf_template_aws_s3"
  for_each = var.s3_variable
  bucket =  each.value.bucket_name
  force_destroy = each.value.force_destroy
  server_side_encryption_configuration = {
    rule = {
      apply_server_side_encryption_by_default = {
        kms_master_key_id = module.kms.key_id
        sse_algorithm     = "aws:kms"
      }
      bucket_key_enabled = true
    }
  }
  #  versioning = {
  #   enabled = var.versioning
  # }
  attach_policy = each.value.attach_policy
  policy        = each.key == "CSB1" ? data.aws_iam_policy_document.cloudtrail_policy["CSB1"].json :""
}

# # ####### SNS #########

module "sns" {
  source            = "./ceq_tf_template_aws_sns"
  for_each          = var.sns_variable
  create            = var.create
  name              = each.value.sns_topic_name
  kms_master_key_id = module.kms.key_id
  subscriptions     = each.value.subscriptions
  tags              = var.tags
  

}




data "archive_file" "lambda" {
  for_each = var.lambda_functions

  type        = "zip"
  source_file = "${each.value.file}"
  output_path = "${path.module}/${each.key}.zip"
}



module "lambda_function" {
  depends_on = [ module.s3_bucket ]
  source = "./ceq_tf_template_aws_lambda"

  for_each = var.lambda_functions  

  function_name          = "${each.key}"
  description            = "${each.value.description_lambda}"
  handler                = "${each.value.lambda_handler}"
  runtime                = "${each.value.runtime_lambda}"
  ephemeral_storage_size = 10240
  architectures          = flatten([each.value.architectures_lambda])
  publish                = "${each.value.publish_lambda}"
  kms_key_arn            = module.kms.key_arn
  source_file =  data.archive_file.lambda[each.key].output_path
  s3_object_override_default_tags  = true

  # ✅ Use the ZIP storage bucket for Lambda deployment
  store_on_s3 = "${each.value.store_on_s3_lambda}"
  s3_bucket   = "${module.s3_bucket["CSB2"].s3_bucket_id}"
  s3_prefix   = "lambda-builds/lambda1/"
  create_s3_notification = "${each.value.create_s3_notification}"
  s3_bucket_notification = {
    for key, value in each.value.s3_bucket_notification : key => {
      bucket_id       = "${module.s3_bucket[value.bucket_name].s3_bucket_id}"
      event           = flatten([value.event])
      policy_resource = "${module.s3_bucket[value.bucket_name].s3_bucket_arn}"
      action          = "${value.action}"
      role_name       = "${value.role_name}"
      policy_name     = "${value.policy_name}"
    }
  } 

  allowed_triggers = {
    for key, value in each.value.allowed_triggers : key => {
      statement_id   = "${value.statement_id}"
      action         = "${value.action}"
      function_name  = "${each.key}"
      principal      = "${value.principal}"
      source_arn     = try("${value.bucket_name}", null) != null ? "${module.s3_bucket[value.bucket_name].s3_bucket_arn}" : "${value.source_arn}"
    }
  }
  artifacts_dir = "${path.root}/.terraform/lambda-builds/"
  environment_variables = "${each.value.environment_variables_lambda}"

  role_path   = "/tf-managed/"
  policy_path = "/tf-managed/"

  number_of_policy_jsons = each.value.number_of_policy_jsons_lambda
  attach_policy          = "${each.value.attach_policy_lambda}"
  policy                = "${each.value.policy_lambda}"
  attach_policies       = "${each.value.attach_policies_lambda}"
  policies              = flatten([each.value.policies_lambda])
  number_of_policies    = each.value.number_of_policies_lambda

  attach_policy_statements = "${each.value.attach_policy_statements_lambda}"
  policy_statements        = "${each.value.policy_statements_lambda}"
  timeouts                 = "${each.value.timeouts_lambda}"

  function_tags = "${each.value.function_lang}"
  tags = var.tags
}






module "db_subnet_group" {
  source = "./modules/db_subnet_group"
  for_each = var.create_db_subnet_group ? var.db_subnet_group : {}
  name            = each.value.subnet_name
  description     = each.value.db_subnet_group_description
  subnet_ids      = module.awsvpc.private_subnets
  tags = var.tags
}

module "db_parameter_group" {
  source = "./modules/db_parameter_group"

  for_each = var.create_db_parameter_group ? var.db_parameter_group : {}

  name            = each.value.db_name
  description     = each.value.parameter_group_description
  family          = each.value.family


  tags = var.tags
}

module "db_option_group" {
  source = "./modules/db_option_group"

  for_each = var.create_db_option_group ? var.db_option_group : {}

  name                     = each.value.option_name
  option_group_description = each.value.option_group_description
  engine_name              = each.value.engine
  major_engine_version     = each.value.major_engine_version

  timeouts = each.value.option_group_timeouts

  tags = var.tags
}

module "secret_manager" {
  source = "./modules/Secret_manager"
  rds_username = var.rds_username
  rds_password = var.rds_password
  secret_name = var.secret_name
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

  iam_database_authentication_enabled = each.value.iam_database_authentication_enabled

  vpc_security_group_ids = [for sg in each.value.security_group : module.security_group_RDS[sg].security_group_id]
  db_subnet_group_name   = module.db_subnet_group[each.value.db_subnet_group].db_subnet_group_id
  parameter_group_name   = module.db_parameter_group[each.value.parameter_group_name].db_parameter_group_id
  option_group_name      = each.value.engine != "postgres" ? module.db_option_group[each.value.option_group_name].db_option_group_id : null
  multi_az             = each.value.multi_az
  iops                 = each.value.iops
  # storage_throughput   = var.storage_throughput
  publicly_accessible  = each.value.publicly_accessible

  maintenance_window          = each.value.maintenance_window

  skip_final_snapshot              = each.value.skip_final_snapshot
  # final_snapshot_identifier_prefix = var.final_snapshot_identifier_prefix

  performance_insights_enabled          = each.value.performance_insights_enabled
  performance_insights_retention_period = each.value.performance_insights_retention_period
  replica_mode                         = each.value.replica_mode
  backup_retention_period              = each.value.backup_retention_period
  backup_window                        = each.value.backup_window
  max_allocated_storage                = each.value.max_allocated_storage

  character_set_name       = each.value.character_set_name
  nchar_character_set_name = each.value.nchar_character_set_name

  enabled_cloudwatch_logs_exports        = flatten([each.value.enabled_cloudwatch_logs_exports])
  create_cloudwatch_log_group            = each.value.create_cloudwatch_log_group

  delete_automated_backups = each.value.delete_automated_backups
  db_instance_tags = var.tags
  tags             = var.tags
}



module "ip_set" {
  source              = "./WAF/IP_Set"
  for_each            = var.ip_set

  name               = each.value.name
  description        = each.value.description
  scope             = each.value.scope
  ip_address_version = each.value.ip_address_version
  addresses         = each.value.addresses

  tags = var.tags
}


module "regex" {
  source = "./WAF/regex_set"

  for_each = var.regex

  name        = each.value.name
  description = each.value.description
  scope       = each.value.scope
  regex_strings = each.value.regex_strings # Ensure this is a list of strings
}


module "rule_group" {
  source   = "./WAF/rule_group"
  for_each = var.rule_group

  # Rule Group Variables
  rule_group_name        = each.value.name
  rule_group_description = each.value.description
  rule_group_scope       = each.value.scope
  rule_group_capacity    = each.value.capacity

  # Reference IP Set and Regex Set
  ip_set_arn   = module.ip_set["ip_set_1"].ip_set_arn
  regex_set_arn = module.regex["example1"].arn

  # Define Rules for the Rule Group
  rule_group_rules = [
    for rule in each.value.rule_group_rules : {
      name     = rule.name
      priority = rule.priority
      action   = rule.action

      single_header = {
        name = rule.single_header.name
      }

      # Text Transformation Configuration (Proper Looping)
      text_transformation = [
        for transformation in rule.text_transformation : {
          type     = transformation.type
          priority = transformation.priority
        }
      ]

      # Visibility Configuration
      visibility_config = {
        cloudwatch_metrics = rule.visibility_config.cloudwatch_metrics
        name              = rule.name
        sampled_requests  = rule.visibility_config.sampled_requests
      }
    }
  ]

  # Visibility Configuration for the Rule Group
  rule_group_visibility_config = each.value.visibility_config

  # Tags for the Rule Group
  rule_group_resource_tag = var.tags
}


module "waf" {
  source   = "./WAF/waf_creation"
  for_each = var.waf_creation

  name              = each.key
  tags              = var.tags
  visibility_config = each.value.visibility_config

  byte_match_statement_rules = [
    for rule in each.value.byte_match_statement_rules : {
      name     = rule.name
      priority = rule.priority
      action   = rule.action
      statement = {
        positional_constraint = rule.statement.positional_constraint
        search_string         = rule.statement.search_string
        field_to_match = {
          single_header = { name = rule.statement.field_to_match.single_header.name }
        }
        text_transformation = [
          for tt in rule.statement.text_transformation : {
            priority = tt.priority
            type     = tt.type
          }
        ]
      }
      visibility_config = {
        cloudwatch_metrics_enabled = rule.visibility_config.cloudwatch_metrics_enabled
        metric_name                = rule.visibility_config.metric_name
        sampled_requests_enabled   = rule.visibility_config.sampled_requests_enabled
      }
    }
  ]

  # Geo Allowlist Statement Rules
  geo_allowlist_statement_rules = [
    for rule in each.value.geo_allowlist_statement_rules : {
      name     = rule.name
      priority = rule.priority
      action   = rule.action
      statement = {
        country_codes = rule.statement.country_codes
        forwarded_ip_config = {
          fallback_behavior = rule.statement.forwarded_ip_config.fallback_behavior
          header_name       = rule.statement.forwarded_ip_config.header_name
        }
      }
      visibility_config = {
        cloudwatch_metrics_enabled = rule.visibility_config.cloudwatch_metrics_enabled
        metric_name                = rule.visibility_config.metric_name
        sampled_requests_enabled   = rule.visibility_config.sampled_requests_enabled
      }
    }
  ]

  # Geo Match Statement Rules
  geo_match_statement_rules = [
    for rule in each.value.geo_match_statement_rules : {
      name     = rule.name
      priority = rule.priority
      action   = rule.action
      statement = {
        country_codes = rule.statement.country_codes
      }
      visibility_config = {
        cloudwatch_metrics_enabled = rule.visibility_config.cloudwatch_metrics_enabled
        metric_name                = rule.visibility_config.metric_name
        sampled_requests_enabled   = rule.visibility_config.sampled_requests_enabled
      }
    }
  ]

  # Managed Rule Group Statement Rules
  managed_rule_group_statement_rules = [
    for rule in each.value.managed_rule_group_statement_rules : {
      name            = rule.name
      priority        = rule.priority
      override_action = rule.override_action
      statement = {
        name        = rule.statement.name
        vendor_name = rule.statement.vendor_name
      }
      visibility_config = {
        cloudwatch_metrics_enabled = rule.visibility_config.cloudwatch_metrics_enabled
        metric_name                = rule.visibility_config.metric_name
        sampled_requests_enabled   = rule.visibility_config.sampled_requests_enabled
      }
      captcha_config = try(
        {
          immunity_time_property = {
            immunity_time = rule.captcha_config.immunity_time_property.immunity_time
          }
        },
        null
      )
    }
  ]

  # Rate-Based Statement Rules
  rate_based_statement_rules = [
    for rule in each.value.rate_based_statement_rules : {
      name     = rule.name
      priority = rule.priority
      action   = rule.action
      statement = {
        aggregate_key_type    = rule.statement.aggregate_key_type
        limit                 = rule.statement.limit
        evaluation_window_sec = rule.statement.evaluation_window_sec
        forwarded_ip_config = {
          fallback_behavior = rule.statement.forwarded_ip_config.fallback_behavior
          header_name       = rule.statement.forwarded_ip_config.header_name
        }
        scope_down_statement = try(
          {
            byte_match_statement = {
              positional_constraint = rule.statement.scope_down_statement.byte_match_statement.positional_constraint
              search_string         = rule.statement.scope_down_statement.byte_match_statement.search_string
              field_to_match = {
                single_header = {
                  name = rule.statement.scope_down_statement.byte_match_statement.field_to_match.single_header.name
                }
              }
              text_transformation = [
                for tt in rule.statement.scope_down_statement.byte_match_statement.text_transformation : {
                  priority = tt.priority
                  type     = tt.type
                }
              ]
            }
          },
          null
        )
      }
      visibility_config = {
        cloudwatch_metrics_enabled = rule.visibility_config.cloudwatch_metrics_enabled
        metric_name                = rule.visibility_config.metric_name
        sampled_requests_enabled   = rule.visibility_config.sampled_requests_enabled
      }
      captcha_config = try(
        {
          immunity_time_property = {
            immunity_time = rule.captcha_config.immunity_time_property.immunity_time
          }
        },
        null
      )
    }
  ]

  # Regex Pattern Set Reference Statement Rules
  regex_pattern_set_reference_statement_rules = [
    for rule in each.value.regex_pattern_set_reference_statement_rules : {
      name     = rule.name
      priority = rule.priority
      action   = rule.action
      statement = {
        arn =module.regex["example1"].arn
        field_to_match = {
          single_header = {
            name = rule.statement.field_to_match.single_header.name
          }
        }
        text_transformation = [
          for tt in rule.statement.text_transformation : {
            priority = tt.priority
            type     = tt.type
          }
        ]
      }
      visibility_config = {
        cloudwatch_metrics_enabled = rule.visibility_config.cloudwatch_metrics_enabled
        metric_name                = rule.visibility_config.metric_name
        sampled_requests_enabled   = rule.visibility_config.sampled_requests_enabled
      }
      captcha_config = try(
        {
          immunity_time_property = {
            immunity_time = rule.captcha_config.immunity_time_property.immunity_time
          }
        },
        null
      )
    }
  ]

  # Regex Match Statement Rules
  regex_match_statement_rules = [
    for rule in each.value.regex_match_statement_rules : {
      name     = rule.name
      priority = rule.priority
      action   = rule.action
      statement = {
        regex_string = rule.statement.regex_string
        field_to_match = {
          single_header = {
            name = rule.statement.field_to_match.single_header.name
          }
        }
        text_transformation = [
          for tt in rule.statement.text_transformation : {
            priority = tt.priority
            type     = tt.type
          }
        ]
      }
      visibility_config = {
        cloudwatch_metrics_enabled = rule.visibility_config.cloudwatch_metrics_enabled
        metric_name                = rule.visibility_config.metric_name
        sampled_requests_enabled   = rule.visibility_config.sampled_requests_enabled
      }
      captcha_config = try(
        {
          immunity_time_property = {
            immunity_time = rule.captcha_config.immunity_time_property.immunity_time
          }
        },
        null
      )
    }
  ]

  # Rule Group Reference Statement Rules
  rule_group_reference_statement_rules = [
    for rule in each.value.rule_group_reference_statement_rules : {
      name            = rule.name
      priority        = rule.priority
      override_action = rule.override_action
      statement = {
        arn = "${module.rule_group["rule_group_1"].op_rule_group_arn}"
        rule_action_override = {
          for k, v in rule.statement.rule_action_override : k => {
            action = v.action
            custom_response = try(
              {
                response_code            = v.custom_response.response_code
                custom_response_body_key = v.custom_response.custom_response_body_key
                response_header = {
                  name  = v.custom_response.response_header.name
                  value = v.custom_response.response_header.value
                }
              },
              null
            )
            custom_request_handling = try(
              {
                insert_header = {
                  name  = v.custom_request_handling.insert_header.name
                  value = v.custom_request_handling.insert_header.value
                }
              },
              null
            )
          }
        }
      }
      visibility_config = {
        cloudwatch_metrics_enabled = rule.visibility_config.cloudwatch_metrics_enabled
        metric_name                = rule.visibility_config.metric_name
        sampled_requests_enabled   = rule.visibility_config.sampled_requests_enabled
      }
      captcha_config = try(
        {
          immunity_time_property = {
            immunity_time = rule.captcha_config.immunity_time_property.immunity_time
          }
        },
        null
      )
    }
  ]

  # Size Constraint Statement Rules
  size_constraint_statement_rules = [
    for rule in each.value.size_constraint_statement_rules : {
      name     = rule.name
      priority = rule.priority
      action   = rule.action
      statement = {
        comparison_operator = rule.statement.comparison_operator
        size                = rule.statement.size
        field_to_match = try(
          {
            body = {
              oversize_handling = rule.statement.field_to_match.body.oversize_handling
            }
          },
          {
            query_string = {}
          }
        )
        text_transformation = [
          for tt in rule.statement.text_transformation : {
            priority = tt.priority
            type     = tt.type
          }
        ]
      }
      visibility_config = {
        cloudwatch_metrics_enabled = rule.visibility_config.cloudwatch_metrics_enabled
        metric_name                = rule.visibility_config.metric_name
        sampled_requests_enabled   = rule.visibility_config.sampled_requests_enabled
      }
      captcha_config = try(
        {
          immunity_time_property = {
            immunity_time = rule.captcha_config.immunity_time_property.immunity_time
          }
        },
        null
      )
    }
  ]

  # SQL Injection Match Statement Rules
  sqli_match_statement_rules = [
    for rule in each.value.sqli_match_statement_rules : {
      name     = rule.name
      priority = rule.priority
      action   = rule.action
      statement = {
        field_to_match = try(
          {
            query_string = {}
          },
          {
            body = {}
          }
        )
        text_transformation = [
          for tt in rule.statement.text_transformation : {
            priority = tt.priority
            type     = tt.type
          }
        ]
      }
      visibility_config = {
        cloudwatch_metrics_enabled = rule.visibility_config.cloudwatch_metrics_enabled
        metric_name                = rule.visibility_config.metric_name
        sampled_requests_enabled   = rule.visibility_config.sampled_requests_enabled
      }
    }
  ]

  # XSS Match Statement Rules
  xss_match_statement_rules = [
    for rule in each.value.xss_match_statement_rules : {
      name     = rule.name
      priority = rule.priority
      action   = rule.action
      statement = {
        field_to_match = try(
          {
            query_string = {}
          },
          {
            body = {}
          }
        )
        text_transformation = [
          for tt in rule.statement.text_transformation : {
            priority = tt.priority
            type     = tt.type
          }
        ]
      }
      visibility_config = {
        cloudwatch_metrics_enabled = rule.visibility_config.cloudwatch_metrics_enabled
        metric_name                = rule.visibility_config.metric_name
        sampled_requests_enabled   = rule.visibility_config.sampled_requests_enabled
      }
    }
  ]

  depends_on = [module.ip_set, module.regex, module.rule_group]
}

module "waf_web_acl_association" {
  source = "./WAF/WAF_assoication"
  web_acl_arn = "${module.waf["my-waf"].waf_arn}"
  web_acl_association_resource_arn = "${module.alb["testalb1"].arn}"
}
