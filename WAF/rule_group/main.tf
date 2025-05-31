# ## RULE GROUP RESOURCE
# resource "aws_wafv2_rule_group" "waf_rule_group" {
#   name     = var.rule_group_name
#   description = var.rule_group_description
#   scope    = var.rule_group_scope
#   capacity = var.rule_group_capacity
  
#   dynamic "rule" {
#     for_each = var.rule_group_rules
    
#     content {
#       name = rule.value.name
#       priority = rule.value.priority

#       dynamic "action" {
#         for_each = length(lookup(rule.value, "action", {})) == 0 ? [] : [1]
        
#         content {
#           dynamic "allow" {
#             for_each = lookup(rule.value, "action") == "allow" ? [1] : []
#             content {}
#           }

#           dynamic "block" {
#             for_each = lookup(rule.value, "action") == "block" ? [1] : []
#             content {}
#           }

#           dynamic "count" {
#             for_each = lookup(rule.value, "action") == "count" ? [1] : []
#             content {}
#           }

#           dynamic "captcha" {
#             for_each = lookup(rule.value, "action") == "captcha" ? [1] : []
#             content {}
#           } 
#         }
#       }

#       statement {
#         or_statement {
#           statement {
#             ip_set_reference_statement {
#               arn = var.ip_set_arn
#             }
#           }

#           statement {
#             regex_pattern_set_reference_statement {
#               arn = var.regex_set_arn

#               field_to_match {
#                 dynamic "single_header" {
#                   for_each = [lookup(rule.value, "single_header", {})]
#                   content {
#                     name = single_header.value.name
#                   }
#                 }
#               }

#               dynamic "text_transformation" {
#                 for_each = length(lookup(rule.value, "text_transformation", {})) == 0 ? [] : [lookup(rule.value, "text_transformation", {})]
#                 content {
#                   type = text_transformation.value.type
#                   priority = text_transformation.value.priority
#                 }
#               }
#             }
#           }
#         }
#       }

#       dynamic "visibility_config" {
#         for_each = length(lookup(rule.value, "visibility_config", {})) == 0 ? [] : [lookup(rule.value, "visibility_config", {})]
#         content {
#           cloudwatch_metrics_enabled = lookup(visibility_config.value, "cloudwatch_metrics")
#           metric_name = lookup(rule.value, "name")
#           sampled_requests_enabled = lookup(visibility_config.value, "sampled_requests")
#         }
#       }

#       # visibility_config {
#       #   cloudwatch_metrics_enabled = rule.value.cloudwatch_metrics
#       #   metric_name = rule.value.name
#       #   sampled_requests_enabled =  rule.value.sampled_requests
#       # }
#     }
#   }

#   visibility_config {
#     cloudwatch_metrics_enabled = var.rule_group_visibility_config.cloudwatch_metrics_enabled
#     metric_name                = var.rule_group_visibility_config.metric_name
#     sampled_requests_enabled   = var.rule_group_visibility_config.sampled_requests_enabled
#   }

#   tags = var.rule_group_resource_tag
# }



resource "aws_wafv2_rule_group" "waf_rule_group" {
  name        = var.rule_group_name
  description = var.rule_group_description
  scope       = var.rule_group_scope
  capacity    = var.rule_group_capacity

  dynamic "rule" {
    for_each = var.rule_group_rules

    content {
      name     = rule.value.name
      priority = rule.value.priority

      dynamic "action" {
        for_each = length(lookup(rule.value, "action", {})) == 0 ? [] : [1]

        content {
          dynamic "allow" {
            for_each = rule.value.action == "allow" ? [1] : []
            content {}
          }

          dynamic "block" {
            for_each = rule.value.action == "block" ? [1] : []
            content {}
          }

          dynamic "count" {
            for_each = rule.value.action == "count" ? [1] : []
            content {}
          }

          dynamic "captcha" {
            for_each = rule.value.action == "captcha" ? [1] : []
            content {}
          }
        }
      }

      statement {
        or_statement {
          statement {
            ip_set_reference_statement {
              arn = var.ip_set_arn
            }
          }

        #   statement {
        #     regex_pattern_set_reference_statement {
        #       arn = var.regex_set_arn

        #       field_to_match {
        #         dynamic "single_header" {
        #           for_each = lookup(rule.value, "single_header", {}) != {} ? [rule.value.single_header] : []
        #           content {
        #             name = single_header.value.name
        #           }
        #         }
        #       }

        #       dynamic "text_transformation" {
        #         for_each = lookup(rule.value, "text_transformation", [])
        #         content {
        #           type     = text_transformation.value.type
        #           priority = text_transformation.value.priority
        #         }
        #       }
        #     }
        #   }
statement {
  regex_pattern_set_reference_statement {
    arn = var.regex_set_arn

    field_to_match {
      dynamic "single_header" {
        for_each = length(lookup(rule.value, "single_header", {})) > 0 ? [rule.value.single_header] : []
        content {
          name = single_header.value.name
        }
      }
    }

    dynamic "text_transformation" {
      for_each = rule.value.text_transformation
      content {
        type     = text_transformation.value.type
        priority = text_transformation.value.priority
      }
    }
  }
}


        }
      }

      dynamic "visibility_config" {
        for_each = length(lookup(rule.value, "visibility_config", {})) == 0 ? [] : [lookup(rule.value, "visibility_config", {})]
        content {
          cloudwatch_metrics_enabled = visibility_config.value.cloudwatch_metrics
          metric_name               = rule.value.name
          sampled_requests_enabled  = visibility_config.value.sampled_requests
        }
      }
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = var.rule_group_visibility_config.cloudwatch_metrics_enabled
    metric_name                = var.rule_group_visibility_config.metric_name
    sampled_requests_enabled   = var.rule_group_visibility_config.sampled_requests_enabled
  }

  tags = var.rule_group_resource_tag
}