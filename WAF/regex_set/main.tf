resource "aws_wafv2_regex_pattern_set" "example" {
  name        = var.name
  description = var.description
  scope       = var.scope # Change to "CLOUDFRONT" if using CloudFront


    dynamic "regular_expression" {
    for_each = var.regex_strings
    content {
      regex_string = regular_expression.value
    }
  }
}




#   regular_expression {
#     regex_string = ".*example.*" # Replace with your regex
#   }

#   regular_expression {
#     regex_string = ".*test.*" # Add more regex patterns as needed
#   }