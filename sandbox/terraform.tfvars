region = "us-east-1"
tags = {
  "START_DATE"       = ""
  "END_DATE"         = ""
  "PROJECT_NAME"     = "CSB"
  "DEPARTMENT_NAME"  = "DevOps"
  "APPLICATION_NAME" = "AWS VPC"
  "CLIENT_NAME"      = "CSB"
  "OWNER_NAME"       = "suraj.kaul@cloudeq.com"
  "SOW_NUMBER"       = "1284864"
}

############ VPC ###################

name = "my-vpc"
cidr = "10.0.0.0/16"
public_subnet_names   = ["Turbo Public Subnet One", "Turbo Public Subnet Two"]
azs                 = ["us-east-1a","us-east-1b"]
public_dedicated_network_acl = true
private_subnet = ["10.0.0.0/24","10.0.1.0/24"]
public_subnet = ["10.0.2.0/24","10.0.3.0/24"]

private_subnet_names = ["Turbo Private Subnet One", "Turbo Private Subnet Two"]
manage_default_network_acl    = false
manage_default_route_table    = false
manage_default_security_group = false

enable_dns_hostnames = true
enable_dns_support   = true

enable_nat_gateway = false ## if this is true then it will create NAT gateway 
single_nat_gateway = false  ## IF this is true then it create elastic ip


########## vpc endpoints ########

endpoints = {
   s3 = {
      service      = "s3"
      service_type = "Gateway"  # If you are using "gateway" then it will automatically pick route-tables as gateway doesn,t work on securtiy gorup
       private_dns_enabled = false
      
      tags = { Name = "s3-vpc-endpoint" }
    },
    dynamodb = {
      service      = "dynamodb"
      service_type = "Gateway"
       private_dns_enabled = false
    
      tags = { Name = "dyanmo-vpc-endpoint" }
    }
}


########################## alb ##################################

albs = {
  testalb1 = { ######### alb creation with this key with all configuration 
    alb_name = "alb1"
    sg_name = "alb-rules"
    listeners = {
      alb1 = {
        port     = 443
        # certificate_arn = "arn:aws:acm:us-east-1:533267235239:certificate/d3bfa7e3-c4cd-4c7f-ac2f-0b9501e9b29e"  #if you will change your port to 443 and you need to pass certificate arn then uncomment this attribute and paste your arn here
        protocol = "HTTPS"
        target_group_key = "alb1"
        order    = 1
        rules = {
          rule1 = {
            priority = 100
            conditions = [
              {
                http_header = {
                  http_header_name = "X-Custom-Header"
                  values           = ["CustomValue"]
                }
              }
            ]
            actions = [
              {
                type             = "forward"
                order            = 1
                target_group_key = "alb1"
              }
            ]
          }
        }
      },
      alb2 = {
        port     = 80
        # certificate_arn = "arn:aws:acm:us-east-1:533267235239:certificate/d3bfa7e3-c4cd-4c7f-ac2f-0b9501e9b29e"  #if you will change your port to 443 and you need to pass certificate arn then uncomment this attribute and paste your arn here
        protocol = "HTTP"
        target_group_key = "alb2"
        order    = 1
        rules = {
          rule1 = {
            priority = 100
            conditions = [
              {
                http_header = {
                  http_header_name = "X-Custom-Header"
                  values           = ["CustomValue"]
                }
              }
            ]
            actions = [
              {
                type             = "forward"
                order            = 1
                target_group_key = "alb2"
              }
            ]
          }
        }
      }
    }
    target_groups = {
      alb1 = {
        name              = "target1"
        port              = 443
        protocol          = "HTTPS"
        target_type       = "instance"
        create_attachment = false
      },
      alb2 = {
        name              = "target2"
        port              = 80
        protocol          = "HTTP"
        target_type       = "instance"
        create_attachment = false
      }
    }
  }
}

######################### security group only with CIDR ranges ###########################################

SecurityGroups = {
  "db-rules" = {
    description   = "Database security group"
    cidr_key = {
      http-80 = {
        from_port                = 80
        to_port                  = 80
        protocol                 = "tcp"
        source_security_group_id = "0.0.0.0/0"
      }
      ssh-22 = {
        from_port                = 22
        to_port                  = 22
        protocol                 = "tcp"
        source_security_group_id = "0.0.0.0/0"
      }
    }
    egress_cidr_blocks = ["0.0.0.0/0"]
  }
  "alb-rules" = {
    description   = "alb security group"
    cidr_key = {
      http-80 = {
        from_port                = 80
        to_port                  = 80
        protocol                 = "tcp"
        source_security_group_id = "0.0.0.0/0"
      }
      https-22 = {
        from_port                = 443
        to_port                  = 443
        protocol                 = "tcp"
        source_security_group_id = "0.0.0.0/0"
      }
    }
    egress_cidr_blocks = ["0.0.0.0/0"]
  }
}

####################### security group adding both as a source of CIDR AND Security group  ###############################

SecurityGroups_RDS = {
  "db-rules" = {
    description   = "Database security group"
    sg_key = {
      db-rules = {
        from_port                = 1521
        to_port                  = 1521
        protocol                 = "tcp"
      }
    }
    cidr_key = {  # if you want to pass CIDR ranges then you need to specify the cidr key object like this and if you don't want make it empty like cidr_key = {}
      db-rules-2 = {
        from_port                = 80
        to_port                  = 80
        protocol                 = "tcp"
        source_security_group_id = "0.0.0.0/0"
      }
    }
    egress_cidr_blocks = ["0.0.0.0/0"]
  }
}


###################### ASG ##############################################

multipe_asg = {
  "asg-1" = {
    name = "dev-web-server-turbo-asg"
    max = 2
    min = 1
    desired_capacity          = 1
    wait_for_capacity_timeout = 0
    default_instance_warmup   = 300
    health_check_type         = "EC2"
    launch_template_name = "dev-asg"
    image_id = "ami-0c614dee691cbbf37"
    launch_template_description = "web-asg-launch-template"
    instance_type = "t3.micro"
    is_public = true
    security_groups = ["web-rules"]
     alb_arn = {
      alb1 = "alb1"
      alb2 = "alb1"
    
    }
    block_device_mappings = [ 
  {
    device_name = "/dev/xvda"
    no_device   = 0
    ebs = {
      delete_on_termination = true
      encrypted             = true
      volume_size           = 20
      volume_type           = "gp2"
    }
  },
  {
    device_name = "/dev/xvdf"
    no_device   = 0
    ebs = {
      delete_on_termination = true
      encrypted             = true
      volume_size           = 50
      volume_type           = "gp3"
    }
  }
]
  network_interfaces = [
  {
    delete_on_termination = true
    description           = "eth0"
    device_index          = 0
    associate_public_ip_address = true
    connection_tracking_specification = {
      tcp_established_timeout = 60
      udp_stream_timeout      = 60
      udp_timeout             = 60
    }
  },

]
  scaling_policies = {
  "avg-cpu-policy-greater-than-50" = {
    policy_type               = "TargetTrackingScaling"
    estimated_instance_warmup = 300
    target_tracking_configuration = {
      predefined_metric_specification = {
        predefined_metric_type = "ASGAverageCPUUtilization"
      }
      target_value = 50.0
    }
  }
  # "predictive-scaling" = {
  #   policy_type = "PredictiveScaling"
  #   predictive_scaling_configuration = {
  #     mode                         = "ForecastAndScale"
  #     scheduling_buffer_time       = 10
  #     max_capacity_breach_behavior = "IncreaseMaxCapacity"
  #     max_capacity_buffer          = 10
  #     metric_specification = {
  #       target_value = 32
  #       predefined_scaling_metric_specification = {
  #         predefined_metric_type = "ASGAverageCPUUtilization"
  #         resource_label         = "testLabel"
  #       }
  #       predefined_load_metric_specification = {
  #         predefined_metric_type = "ASGTotalCPUUtilization"
  #         resource_label         = "testLabel"
  #       }
  #     }
  #   }
  # },
  # "scale-out" = {
  #   name                      = "scale-out"
  #   adjustment_type           = "ExactCapacity"
  #   policy_type               = "StepScaling"
  #   estimated_instance_warmup = 120
  #   step_adjustment = [
  #     {
  #       scaling_adjustment          = 1
  #       metric_interval_lower_bound = 0
  #       metric_interval_upper_bound = 10
  #     },
  #     {
  #       scaling_adjustment          = 2
  #       metric_interval_lower_bound = 10
  #     }
  #   ]
  # }
     }
  },

  "asg-2" = {
    name = "prod-web-server-turbo-asg"
    launch_template_name = "prod-asg"
    image_id = "ami-0c614dee691cbbf37"
    launch_template_description = "prod-asg-launch-template"
    instance_type = "t3.micro"
    is_public = true
    security_groups = ["web-rules"]
     alb_arn = {
    
      alb3 = "alb1"
    }
    block_device_mappings = [ 
  {
    device_name = "/dev/xvda"
    no_device   = 0
    ebs = {
      delete_on_termination = true
      encrypted             = true
      volume_size           = 20
      volume_type           = "gp2"
    }
  },
  {
    device_name = "/dev/xvdf"
    no_device   = 0
    ebs = {
      delete_on_termination = true
      encrypted             = true
      volume_size           = 50
      volume_type           = "gp3"
    }
  }
]
  network_interfaces = [
  {
    delete_on_termination = true
    description           = "eth0"
    device_index          = 0
    associate_public_ip_address = true
    connection_tracking_specification = {
      tcp_established_timeout = 60
      udp_stream_timeout      = 60
      udp_timeout             = 60
    }
  },

]
  scaling_policies = {
    "avg-cpu-policy-greater-than-50" = {
    policy_type               = "TargetTrackingScaling"
    estimated_instance_warmup = 300
    target_tracking_configuration = {
      predefined_metric_specification = {
        predefined_metric_type = "ASGAverageCPUUtilization"
      }
      target_value = 50.0
    }
  }
  }
  }
}

#-------------S3 Inputs----------------#

## Make sure KEY should not be changed as it is integerated with other modules i.e "CSB" is the key so only vaule can be changed under that KEY ####


s3_variable = {
  "CSB1" = {
    bucket_name = "csbtech1"
    force_destroy = true
    attach_policy = true
     }

   "CSB2" = {
      bucket_name = "csbtech2"
      force_destroy = true
      attach_policy = false 
    }
}

#### SNS ####

## Make sure KEY should not be changed as it is integerated with other modules i.e "root" is the key so only vaule can be changed under that KEY ####

sns_variable ={
 "Root"= {
     sns_topic_name = "turbo-root-account-alarm"
     subscriptions = {
      "0" ={
        protocol = "email"
        endpoint  = "suraj.kaul@cloudeq.com" 
          }
           }
    }
}

# Create Cloudtrail on organization to monitor all the activity and event for all Accounts  

root_cloudtrail_name = "Root-account-wafr"
s3_key_prefix                     = null
enable_cloudwatch_logs            = true
cloudwatch_logs_retention_in_days = 365
enable_logging                    = true
enable_log_file_validation        = true
include_global_service_events     = true
is_multi_region_trail             = false
is_organization_trail             = false
event_selectors                   = []
insight_selectors                 = []


####### Alert root account ####
alarm_namespace = "CISBenchmark"
alarm_prefix = ""
root_usage = true
alarm_description = "Monitoring for root account logins will provide visibility into the use of a fully privileged account and an opportunity to reduce the use of it."
threshold = 1
statistic = "Sum"
period  = 300
comparison_operator =  "GreaterThanOrEqualToThreshold"
evaluation_periods  = 1
metric_name = "RootUsage"



########## lambda ###########

lambda_functions = {
  "test-lambda-1" = {
    description_lambda = "my lambda function description"
    lambda_handler = "index.lambda_handler"
    runtime_lambda = "python3.12"
    create_s3_notification = true
    file = "index.py"
    # ephemeral_storage_size_lambda = 10240
    architectures_lambda = ["x86_64"]
    publish_lambda = true
    s3_object_tags_lambda = {
      S3ObjectName = "lambda1"
      Override     = "true"
    }
    environment_variables_lambda = {
      Hello      = "World"
      Serverless = "Terraform"
    }
    store_on_s3_lambda = true
    s3_prefix_lambda = "lambda-builds/"
    s3_object_override_default_tags_lambda = true
    tracing_mode_lambda = "Active"
    allowed_triggers = {      ####### for trigger u need to uncomment the below code and update the trigger as per your requirements 
      # S3_bucket_1 = {
      #   bucket_name = "CSB1"         ##### s3 key name #####
      #   statement_id   = "AllowS3Invoke"
      #   action        = "lambda:InvokeFunction"
      #   principal     = "s3.amazonaws.com"
      # }
      # delete_event = {
      #   statement_id  = "AllowS3InvokeDelete"
      #   action        = "lambda:InvokeFunction"
      #   function_name = "test-lambda-1"
      #   principal     = "s3.amazonaws.com"
      #   bucket_name   = "CSB2"       ##### s3 key name #####
      # }
    }
    s3_bucket_notification = {    ######## you can put events for s3 bucket that you put s3_bucket_notification ########
      # test-bucket-final-3 ={
      #   bucket_name = "CSB1"
      #   action = "s3:PutBucketNotification"
      #   role_name = "tf-managed-test-lambda-2"
      #   policy_name = "tf-managed-test-lambda-2_policy"
      #   event = ["s3:ObjectCreated:Put"]
      # } 
      # delete_event = {
      #   bucket_name = "CSB2"
      #   event       = ["s3:ObjectRemoved:*"]
      #   action      = "lambda:InvokeFunction"
      #   role_name   = "lambda_execution_role"
      #   policy_name = "s3_lambda_policy"
      # }
    }
    policy_lambda = "arn:aws:iam::aws:policy/service-role/AmazonS3ObjectLambdaExecutionRolePolicy"
    policies_lambda = ["arn:aws:iam::aws:policy/AmazonS3FullAccess"]
    attach_policy_json_lambda = true

    attach_policy_jsons_lambda = true

    number_of_policy_jsons_lambda = 1

    attach_policy_lambda = true

    number_of_policies_lambda = 1

    attach_policies_lambda = true
    attach_policy_statements_lambda = true

    policy_statements_lambda = {
      dynamodb = {
        effect    = "Allow",
        actions   = ["dynamodb:BatchWriteItem"],
        resources = ["arn:aws:dynamodb:us-east-1:052212379155:table/Test"]
      },
      s3_read = {
        effect    = "Allow",
        actions   = ["s3:HeadObject", "s3:GetObject"],
        resources = ["arn:aws:s3:::my-bucket/*"]
      }
    } 
    timeouts_lambda = {
      create = "20m"
      update = "20m"
      delete = "20m"
    } 
    function_lang =   {
      Language = "python"
    }
    
  }
  
}

secret_name = "oracle_rds_secret"  ######## make sure when ever you run the terraform script name will be unique with privious one


###################### RDS ############################


create_db_parameter_group = true
create_db_subnet_group = true
create_db_option_group = true

db_subnet_group = {
  test1 = {
    subnet_name = "oracle_subnet_group"
    db_subnet_group_description = "Managed by Terraform"
  }
}

db_parameter_group = {
  test1 = {
    db_name = "oracle_db_parameter"
    parameter_group_description = "Managed by Terraform"
    family                     = "oracle-ee-19"
  }
}


db_option_group = {
  test1 = {
    option_name = "oracle_db_option"
    option_group_description = "Managed by Terraform"
    engine = "oracle-ee"
    major_engine_version = "19"
    option_group_timeouts = {
      create = "30m"
      update = "30m"
      delete = "30m"
    }
  }
}

db_inst = {
  ORACLEMAIN = {
    identifier        = "demoorcl"
    security_group = ["db-rules"]
    db_subnet_group = "test1"
    parameter_group_name = "test1"
    option_group_name = "test1"
    engine           = "oracle-ee"
    engine_version   = "19"
    instance_class   = "db.t3.large"
    allocated_storage = 200
    iam_database_authentication_enabled = false
    storage_type     = "gp3"
    storage_encrypted = true
    iops = 13000
    license_model    = "bring-your-own-license"
    username        = "complete_oracle"
    port           = 1521
    multi_az         = true
    publicly_accessible = true
    maintenance_window = "Mon:00:00-Mon:03:00"
    skip_final_snapshot = true
    performance_insights_enabled = true
    performance_insights_retention_period = 7
    backup_retention_period = 1
    backup_window = "03:00-06:00"
    max_allocated_storage = 400 
    character_set_name       = "AL32UTF8"
    nchar_character_set_name = "AL16UTF16"
    enabled_cloudwatch_logs_exports = ["alert", "audit"]
    create_cloudwatch_log_group     = true
    delete_automated_backups = true
    replica_mode = "mounted"
  }
}

################## waf ###############

rule_group = {
  rule_group_1 = {
    name        = "example-rule-group-1"
    description = "Example WAF Rule Group 1"
    scope       = "REGIONAL"
    capacity    = 100

    rule_group_rules = [
      {
        name     = "BlockBadBots"    ######## make sure the rule name that you specified here will also same in waf rule group ##########
        priority = 1
        action   = "block"

        single_header = {
          name = "user-agent"
        }

        text_transformation = [
          {
            type     = "LOWERCASE"
            priority = 0
          }
        ]

        visibility_config = {
          cloudwatch_metrics = true
          sampled_requests  = true
        }
      },
      {
        name     = "RateLimitRule"
        priority = 2
        action   = "count"

        single_header = {
          name = "user-agent"
        }

        text_transformation = [
          {
            type     = "NONE"
            priority = 1
          }
        ]

        visibility_config = {
          cloudwatch_metrics = true
          sampled_requests  = true
        }
      }
    ]

    visibility_config = {
      cloudwatch_metrics_enabled = true
      metric_name                = "example-rule-group-1-metrics"
      sampled_requests_enabled   = true
    }
  }
}

regex = {
  "example1" = {
    name        = "example-regex-set-1"
    description = "Example regex pattern set 1"
    scope       = "REGIONAL"
    regex_strings = [
      "^example1.*",
      "^test1.*"
    ]
  }
}

ip_set = {
  ip_set_1 = {
    name               = "example-ip-set-1"
    description        = "IP Set for Application 1"
    scope             = "REGIONAL"
    ip_address_version = "IPV4"
    addresses         = ["192.168.1.0/24", "10.0.0.0/16"]
  }
}


waf_creation = {
  "my-waf" = {
    visibility_config = {
      cloudwatch_metrics_enabled = true
      metric_name                = "MyWAFMetric"
      sampled_requests_enabled   = true
    }
    byte_match_statement_rules = [
      {
        name     = "ByteMatchRule30"
        priority = 1
        action   = "allow"
        statement = {
          positional_constraint = "EXACTLY"
          search_string         = "/cp-key"
          field_to_match = {
            single_header = { name = "x-forwarded-for" }
          }
          text_transformation = [
            {
              priority = 1
              type     = "LOWERCASE"
            }
          ]
        }
        visibility_config = {
          cloudwatch_metrics_enabled = true
          metric_name                = "BlockBadBotsMetric"
          sampled_requests_enabled   = true
        }
      }
    ]
    geo_allowlist_statement_rules = [
      {
        name     = "GeoAllowlistRule90"
        priority = 2
        action   = "count"
        statement = {
          country_codes = ["US"]
          forwarded_ip_config = {
            fallback_behavior = "NO_MATCH"
            header_name       = "X-Forwarded-For"
          }
        }
        visibility_config = {
          cloudwatch_metrics_enabled = false
          metric_name                = "AllowOnlyUSUKMetric"
          sampled_requests_enabled   = false
        }
      }
    ]
    geo_match_statement_rules = [
      {
        name     = "AllowUSUK"
        priority = 3
        action   = "allow"
        statement = {
          country_codes = ["US"]
        }
        visibility_config = {
          cloudwatch_metrics_enabled = false
          metric_name                = "GeoMatchRule60"
          sampled_requests_enabled   = false
        }
      }
    ]
    managed_rule_group_statement_rules = [
      {
        name      = "AWSManagedRulesCommonRuleSet"
        priority  = 4
        override_action = "count"
        statement = {
          name        = "AWSManagedRulesCommonRuleSet"
          vendor_name = "AWS"
        }
        visibility_config = {
          cloudwatch_metrics_enabled = true
          metric_name                = "common-rule-metric"
          sampled_requests_enabled   = true
        }
        captcha_config = {
          immunity_time_property = {
            immunity_time = 60
          }
        }
      }
    ]
    rate_based_statement_rules = [
      {
        name     = "RateLimitRule1"
        priority = 5
        action   = "block"
        statement = {
          aggregate_key_type    = "IP"
          limit                 = 1000
          evaluation_window_sec = 300
          forwarded_ip_config = {
            fallback_behavior = "MATCH"
            header_name       = "X-Forwarded-For"
          }
          scope_down_statement = {
            byte_match_statement = {
              positional_constraint = "CONTAINS"
              search_string         = "malicious"
              field_to_match = {
                single_header = {
                  name = "user-agent"
                }
              }
              text_transformation = [
                {
                  priority = 2
                  type     = "NONE"
                }
              ]
            }
          }
        }
        visibility_config = {
          cloudwatch_metrics_enabled = true
          metric_name                = "RateLimitRule1Metric"
          sampled_requests_enabled   = true
        }
        captcha_config = {
          immunity_time_property = {
            immunity_time = 60
          }
        }
      }
    ]
    regex_pattern_set_reference_statement_rules = [
      {
        name     = "BlockMaliciousUserAgents"
        priority = 6
        action   = "block"
        statement = {
          arn = "arn:aws:wafv2:us-east-1:123456789012:regional/regexpatternset/my-regex-set" ######### ignore this arn ##########
          field_to_match = {
            single_header = {
              name = "user-agent"
            }
          }
          text_transformation = [
            {
              priority = 3
              type     = "NONE"
            }
          ]
        }
        visibility_config = {
          cloudwatch_metrics_enabled = true
          metric_name                = "BlockMaliciousUserAgentsMetric"
          sampled_requests_enabled   = true
        }
        captcha_config = {
          immunity_time_property = {
            immunity_time = 60
          }
        }
      }
    ]
    regex_match_statement_rules = [
      {
        name     = "BlockBadBots"
        priority = 7
        action   = "block"
        statement = {
          regex_string = ".*(BadBot|EvilScraper).*"
          field_to_match = {
            single_header = {
              name = "user-agent"
            }
          }
          text_transformation = [
            {
              priority = 0
              type     = "NONE"
            }
          ]
        }
        visibility_config = {
          cloudwatch_metrics_enabled = true
          metric_name                = "BlockBadBotsMetric"
          sampled_requests_enabled   = true
        }
        captcha_config = {
          immunity_time_property = {
            immunity_time = 60
          }
        }
      }
    ]
    rule_group_reference_statement_rules = [
      {
        name     = "ExampleRuleGroup"
        priority = 8
        override_action = "count"
        statement = {
          arn = "arn:aws:wafv2:us-east-1:123456789012:regional/rulegroup/my-rule-group"
          rule_action_override = {
            "BlockBadBots" = {
              action = "block"
              custom_response = {
                response_code = 403
                custom_response_body_key = "custom-body-key"
                response_header = {
                  name  = "X-Custom-Header"
                  value = "Blocked"
                }
              }
            }
            "RateLimitRule" = {
              action = "count"
              custom_request_handling = {
                insert_header = {
                  name  = "X-Rate-Limit"
                  value = "Exceeded"
                }
              }
            }
          }
        }
        visibility_config = {
          cloudwatch_metrics_enabled = true
          metric_name                = "ExampleMetric"
          sampled_requests_enabled   = true
        }
        captcha_config = {
          immunity_time_property = {
            immunity_time = 60
          }
        }
      }
    ]
    size_constraint_statement_rules = [
      {
        name     = "BlockLargeRequestBodies"
        priority = 9
        action   = "block"
        statement = {
          comparison_operator = "GT"
          size                = 8192
          field_to_match = {
            body = {
              oversize_handling = "MATCH"
            }
          }
          text_transformation = [
            {
              priority = 5
              type     = "NONE"
            }
          ]
        }
        visibility_config = {
          cloudwatch_metrics_enabled = true
          metric_name                = "BlockLargeRequestBodiesMetric"
          sampled_requests_enabled   = true
        }
        captcha_config = {
          immunity_time_property = {
            immunity_time = 60
          }
        }
      },
      {
        name     = "BlockLargeQueryStrings"
        priority = 10
        action   = "block"
        statement = {
          comparison_operator = "GT"
          size                = 1024
          field_to_match = {
            query_string = {}
          }
          text_transformation = [
            {
              priority = 1
              type     = "NONE"
            }
          ]
        }
        visibility_config = {
          cloudwatch_metrics_enabled = true
          metric_name                = "BlockLargeQueryStringsMetric"
          sampled_requests_enabled   = true
        }
      }
    ]
    sqli_match_statement_rules = [
      {
        name     = "BlockSQLInjectionInQuery"
        priority = 11
        action   = "block"
        statement = {
          field_to_match = {
            query_string = {}
          }
          text_transformation = [
            {
              priority = 6
              type     = "URL_DECODE"
            },
            {
              priority = 7
              type     = "LOWERCASE"
            }
          ]
        }
        visibility_config = {
          cloudwatch_metrics_enabled = true
          metric_name                = "BlockSQLInjectionInQueryMetric"
          sampled_requests_enabled   = true
        }
      },
      {
        name     = "BlockSQLInjectionInBody"
        priority = 12
        action   = "block"
        statement = {
          field_to_match = {
            body = {}
          }
          text_transformation = [
            {
              priority = 1
              type     = "COMPRESS_WHITE_SPACE"
            },
            {
              priority = 2
              type     = "HTML_ENTITY_DECODE"
            }
          ]
        }
        visibility_config = {
          cloudwatch_metrics_enabled = true
          metric_name                = "BlockSQLInjectionInBodyMetric"
          sampled_requests_enabled   = true
        }
      }
    ]
    xss_match_statement_rules = [
      {
        name     = "BlockXSSInQuery"
        priority = 13
        action   = "block"
        statement = {
          field_to_match = {
            query_string = {}
          }
          text_transformation = [
            {
              priority = 8
              type     = "HTML_ENTITY_DECODE"
            },
            {
              priority = 9
              type     = "LOWERCASE"
            }
          ]
        }
        visibility_config = {
          cloudwatch_metrics_enabled = true
          metric_name                = "BlockXSSInQueryMetric"
          sampled_requests_enabled   = true
        }
      },
      {
        name     = "BlockXSSInBody"
        priority = 14
        action   = "block"
        statement = {
          field_to_match = {
            body = {}
          }
          text_transformation = [
            {
              priority = 11
              type     = "COMPRESS_WHITE_SPACE"
            },
            {
              priority = 12
              type     = "URL_DECODE"
            }
          ]
        }
        visibility_config = {
          cloudwatch_metrics_enabled = true
          metric_name                = "BlockXSSInBodyMetric"
          sampled_requests_enabled   = true
        }
      }
    ]
  }
}
