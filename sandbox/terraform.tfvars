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


name = "my-vpc"
cidr = "10.0.0.0/16"
public_subnet_names   = ["Turbo Public Subnet One", "Turbo Public Subnet Two"]
azs                 = ["us-east-1a","us-east-1b"]
public_dedicated_network_acl = true

private_subnet_names = ["Turbo Private Subnet One", "Turbo Private Subnet Two"]
# create_database_subnet_group  = false
manage_default_network_acl    = false
manage_default_route_table    = false
manage_default_security_group = false

enable_dns_hostnames = true
enable_dns_support   = true

enable_nat_gateway = false
single_nat_gateway = false

# enable_vpn_gateway = true

# enable_dhcp_options              = true
# dhcp_options_domain_name         = "service.consul"
# dhcp_options_domain_name_servers = ["127.0.0.1", "10.10.0.2"]

# # VPC Flow Logs (Cloudwatch log group and IAM role will be created)
# enable_flow_log                       = true
# create_flow_log_cloudwatch_log_group  = true
# create_flow_log_cloudwatch_iam_role   = true
# flow_log_max_aggregation_interval     = 60

security_group = "my-sg-test"
# instance_type = "t2.micro"
# ami = ["ami-0c614dee691cbbf37","ami-0f214d1b3d031dc53"]
# volume_tags = {
#  "START_DATE"       = ""
#   "END_DATE"         = ""
#   "PROJECT_NAME"     = "CSB"
#   "DEPARTMENT_NAME"  = "DevOps"
#   "APPLICATION_NAME" = "AWS VPC"
#   "CLIENT_NAME"      = "CSB"
#   "OWNER_NAME"       = "suraj.kaul@cloudeq.com"
#   "SOW_NUMBER"       = "123232"
# }

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
    },
    ecs = {
      service             = "ecs"
      private_dns_enabled = true
      security_group_ids = [ "ssh-rules"]
      tags = { Name = "ecs-vpc-endpoint" }
    }
}





########################## alb ##################################

albs = {
  testalb1 = {
    listeners = {
      alb1 = {
        port     = 443
        certificate_arn = "arn:aws:acm:us-east-1:533267235239:certificate/d3bfa7e3-c4cd-4c7f-ac2f-0b9501e9b29e"  #if you will change your port to 443 and you need to pass certificate arn then uncomment this attribute and paste your arn here
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
  },

  testalb2 = {
    listeners = {
      alb3 = {
        port     = 443
        certificate_arn = "arn:aws:acm:us-east-1:533267235239:certificate/d3bfa7e3-c4cd-4c7f-ac2f-0b9501e9b29e"
        protocol = "HTTPS"
        target_group_key = "alb3"
        order    = 1
        rules = {
          rule1 = {
            priority = 100
            conditions = [
              {
                http_header = {
                  http_header_name = "X-Secure-Header"
                  values           = ["SecureValue"]
                }
              }
            ]
            actions = [
              {
                type             = "forward"
                order            = 1
                target_group_key = "alb3"
              }
            ]
          }
        }
      }
    }
    target_groups = {
      alb3 = {
        name              = "target3"
        port              = 443
        protocol          = "HTTPS"
        target_type       = "instance"
        create_attachment = false
      }
    }
  }
}




# SecurityGroups = {
#   "web-rules" = {
#     description   = "Web security group"
#     ingress_rules = ["http-80-tcp","ssh-tcp", "https-443-tcp"]
#     engress_rules = ["all-all"]
#     ingress_cidr_blocks = ["0.0.0.0/0"]
#     egress_cidr_blocks = ["0.0.0.0/0"]
#   }
#   "ssh-rules" = {
#     description   = "SSH security group"
#     ingress_rules = ["http-80-tcp","ssh-tcp"]
#     engress_rules = ["all-all"]
#     ingress_cidr_blocks = ["0.0.0.0/0"]
#     egress_cidr_blocks = ["0.0.0.0/0"]
#   }
#   "db-rules" = {
#     description   = "Database security group"
#     ingress_rules = ["http-80-tcp","ssh-tcp"]
#     engress_rules = ["all-all"]
#     ingress_cidr_blocks = ["0.0.0.0/0"]
#     egress_cidr_blocks = ["0.0.0.0/0"]
#   }
# }

SecurityGroups = {
  "db-rules" = {
    description   = "Database security group"
    # number_of_computed_ingress_with_cidr_blocks = 1
    cidr_key = {
      http-80 = {
        rule                     = "http-80-tcp"  # Ensure this rule exists in var.rules
        from_port                = 80
        to_port                  = 80
        protocol                 = "tcp"
        source_security_group_id = "0.0.0.0/0"
      }
      ssh-22 = {
        rule                     = "ssh-tcp"  # Ensure this rule exists in var.rules
        from_port                = 22
        to_port                  = 22
        protocol                 = "tcp"
        source_security_group_id = "0.0.0.0/0"
      }
    }
    # ingress_cidr_blocks = ["0.0.0.0/0"]
    egress_cidr_blocks = ["0.0.0.0/0"]
  }
  "ssh-rules" = {
    description   = "ssh security group"
    # number_of_computed_ingress_with_cidr_blocks = 1
    cidr_key = {
      http-80 = {
        rule                     = "http-80-tcp"  # Ensure this rule exists in var.rules
        from_port                = 80
        to_port                  = 80
        protocol                 = "tcp"
        source_security_group_id = "0.0.0.0/0"
      }
      ssh-22 = {
        rule                     = "ssh-tcp"  # Ensure this rule exists in var.rules
        from_port                = 22
        to_port                  = 22
        protocol                 = "tcp"
        source_security_group_id = "0.0.0.0/0"
      }
    }
    # ingress_cidr_blocks = ["0.0.0.0/0"]
    egress_cidr_blocks = ["0.0.0.0/0"]
  }
}

SecurityGroups_RDS = {
  "db-rules" = {
    description   = "Database security group"
    # number_of_computed_ingress_with_cidr_blocks = 1
    sg_key = {
      db-rules = {
        rule                     = "http-80-tcp"  # Ensure this rule exists in var.rules
        from_port                = 80
        to_port                  = 80
        protocol                 = "tcp"
      }
    }
    cidr_key = {
      db-rules-2 = {
        rule                     = "http-80-tcp"  # Ensure this rule exists in var.rules
        from_port                = 80
        to_port                  = 80
        protocol                 = "tcp"
        source_security_group_id = "0.0.0.0/0"
      }
    }
    # ingress_cidr_blocks = ["0.0.0.0/0"]
    egress_cidr_blocks = ["0.0.0.0/0"]
  }
  "web-rules" = {
    description   = "asg security group"
    # number_of_computed_ingress_with_cidr_blocks = 1
    sg_key = {
      ssh-rules = {
        rule                     = "http-80-tcp"  # Ensure this rule exists in var.rules
        from_port                = 80
        to_port                  = 80
        protocol                 = "tcp"
      }
    }
    cidr_key = {
      db-rules-1 = {
        rule                     = "http-80-tcp"  # Ensure this rule exists in var.rules
        from_port                = 80
        to_port                  = 80
        protocol                 = "tcp"
        source_security_group_id = "0.0.0.0/0"
      }
    }
    # ingress_cidr_blocks = ["0.0.0.0/0"]
    egress_cidr_blocks = ["0.0.0.0/0"]
  }
}




multipe_asg = {
  "asg-1" = {
    name = "dev-web-server-turbo-asg"
    launch_template_name = "dev-asg"
    image_id = "ami-0c614dee691cbbf37"
    launch_template_description = "web-asg-launch-template"
    instance_type = "t3.micro"
    is_public = true
    security_groups = ["web-rules"]
     alb_arn = {
      alb1 = "testalb1"
      alb2 = "testalb1"
    
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
    
      alb3 = "testalb2"
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

#  attach_policy = true

#### SNS ####
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
    allowed_triggers = {
      S3_bucket_1 = {
        bucket_name = "CSB1"
        statement_id   = "AllowS3Invoke"
        action        = "lambda:InvokeFunction"
        principal     = "s3.amazonaws.com"
      }
      delete_event = {
        statement_id  = "AllowS3InvokeDelete"
        action        = "lambda:InvokeFunction"
        function_name = "test-lambda-1"
        principal     = "s3.amazonaws.com"
        bucket_name   = "CSB2"
      }
    }
    s3_bucket_notification = {
      test-bucket-final-3 ={
        bucket_name = "CSB1"
        action = "s3:PutBucketNotification"
        role_name = "tf-managed-test-lambda-2"
        policy_name = "tf-managed-test-lambda-2_policy"
        event = ["s3:ObjectCreated:Put"]
      } 
      delete_event = {
        bucket_name = "CSB2"
        event       = ["s3:ObjectRemoved:*"]
        action      = "lambda:InvokeFunction"
        role_name   = "lambda_execution_role"
        policy_name = "s3_lambda_policy"
      }
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
  # "test-lambda-2" = {
  #   description_lambda = "my lambda function description"
  #   lambda_handler = "archive.index.lambda_handler"
  #   runtime_lambda = "python3.12"
  #   file = "index.py"
  #   # ephemeral_storage_size_lambda = 10240
  #   create_s3_notification = false
  #   architectures_lambda = ["x86_64"]
  #   publish_lambda = true
  #   s3_object_tags_lambda = {
  #     S3ObjectName = "lambda2"
  #     Override     = "true"
  #   }
  #   environment_variables_lambda = {
  #     Hello      = "World"
  #     Serverless = "Terraform"
  #   }
  #   store_on_s3_lambda = true
  #   s3_prefix_lambda = "lambda-builds/"
  #   s3_object_override_default_tags_lambda = true
  #   tracing_mode_lambda = "Active"
  #   allowed_triggers = {
  #     # APIGatewayAny = {
  #     #     statement_id = "AllowAPIGatewayInvoke"
  #     #     action       = "lambda:InvokeFunction"
  #     #     principal    = "apigateway.amazonaws.com"
  #     #     source_arn   = "arn:aws:execute-api:us-east-1:533267235239:aqnku8akd0/*/*/*"
  #     # }
  #   }
  #   s3_bucket_notification = {
  #     delete_event = {
  #       bucket_name = "test-bucket-final-5"
  #       event       = ["s3:ObjectRemoved:*"]
  #       action      = "lambda:InvokeFunction"
  #       role_name   = "lambda_execution_role_2"
  #       policy_name = "s3_lambda_policy_2"
  #     }
  #   }
  #   policy_lambda = "arn:aws:iam::aws:policy/service-role/AmazonS3ObjectLambdaExecutionRolePolicy"

  #   policies_lambda = ["arn:aws:iam::aws:policy/AmazonAPIGatewayInvokeFullAccess"]
  #   attach_policy_json_lambda = true

  #   attach_policy_jsons_lambda = true

  #   number_of_policy_jsons_lambda = 1

  #   attach_policy_lambda = true

  #   number_of_policies_lambda = 1

  #   attach_policies_lambda = true
  #   attach_policy_statements_lambda = true

  #   policy_statements_lambda = {
  #     dynamodb = {
  #       effect    = "Allow",
  #       actions   = ["dynamodb:BatchWriteItem"],
  #       resources = ["arn:aws:dynamodb:us-east-1:052212379155:table/Test"]
  #     },
  #     s3_read = {
  #       effect    = "Allow",
  #       actions   = ["s3:HeadObject", "s3:GetObject"],
  #       resources = ["arn:aws:s3:::my-bucket/*"]
  #     }
  #   } 
  #   timeouts_lambda = {
  #     create = "20m"
  #     update = "20m"
  #     delete = "20m"
  #   } 
  #   function_lang =   {
  #     Language = "python"
  #   }
    
  # }
  # "test-lambda-3" = {
  #   description_lambda = "my lambda function description"
  #   lambda_handler = "archive.index.lambda_handler"
  #   runtime_lambda = "python3.12"
  #   file = "index.py"
  #   # ephemeral_storage_size_lambda = 10240
  #   create_s3_notification = true
  #   architectures_lambda = ["x86_64"]
  #   publish_lambda = true
  #   s3_object_tags_lambda = {
  #     S3ObjectName = "lambda2"
  #     Override     = "true"
  #   }
  #   environment_variables_lambda = {
  #     Hello      = "World"
  #     Serverless = "Terraform"
  #   }
  #   store_on_s3_lambda = true
  #   s3_prefix_lambda = "lambda-builds/"
  #   s3_object_override_default_tags_lambda = true
  #   tracing_mode_lambda = "Active"
  #   allowed_triggers = {
  #     delete_event = {
  #       statement_id  = "AllowS3InvokeDelete"
  #       action        = "lambda:InvokeFunction"
  #       function_name = "test-lambda-3"
  #       principal     = "s3.amazonaws.com"
  #       bucket_name   = "test-bucket-final-5"
  #     }
  #   }
  #   s3_bucket_notification = {
  #     delete_event = {
  #       bucket_name = "test-bucket-final-5"
  #       event       = ["s3:ObjectRemoved:*"]
  #       action      = "lambda:InvokeFunction"
  #       role_name   = "lambda_execution_role_2"
  #       policy_name = "s3_lambda_policy_2"
  #     }
  #   }
  #   policy_lambda = "arn:aws:iam::aws:policy/service-role/AmazonS3ObjectLambdaExecutionRolePolicy"

  #   policies_lambda = ["arn:aws:iam::aws:policy/AmazonS3FullAccess"]
  #   attach_policy_json_lambda = true

  #   attach_policy_jsons_lambda = true

  #   number_of_policy_jsons_lambda = 1

  #   attach_policy_lambda = true

  #   number_of_policies_lambda = 1

  #   attach_policies_lambda = true
  #   attach_policy_statements_lambda = true

  #   policy_statements_lambda = {
  #     dynamodb = {
  #       effect    = "Allow",
  #       actions   = ["dynamodb:BatchWriteItem"],
  #       resources = ["arn:aws:dynamodb:us-east-1:052212379155:table/Test"]
  #     },
  #     s3_read = {
  #       effect    = "Allow",
  #       actions   = ["s3:HeadObject", "s3:GetObject"],
  #       resources = ["arn:aws:s3:::my-bucket/*"]
  #     }
  #   } 
  #   timeouts_lambda = {
  #     create = "20m"
  #     update = "20m"
  #     delete = "20m"
  #   } 
  #   function_lang =   {
  #     Language = "python"
  #   }
    
  # }
}



###################### RDS ############################

create_db_parameter_group = true
create_db_subnet_group = true
create_db_option_group = true

db_subnet_group = {
  test1 = {
    subnet_name = "main1"
    # identifier = "demodb-oracle"
    db_subnet_group_description = "Managed by Terraform"
  }
}

db_parameter_group = {
  test1 = {
    parameter_group_description = "Managed by Terraform"
    family                     = "oracle-ee-19"
  #   parameters = [
  #     { name = "processes", value = "500" },
  #     { name = "sessions", value = "1000" },
  #     { name = "transactions_per_session", value = "100" },
  #     { name = "open_cursors", value = "300" },
  #     { name = "sort_area_size", value = "65536" },
  #     { name = "shared_pool_size", value = "536870912" }
  #   ]
  # }
  }
}


db_option_group = {
  test1 = {
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

