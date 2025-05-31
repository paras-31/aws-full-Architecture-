## WEB ACL ASSOCIATION RESOURCE
resource "aws_wafv2_web_acl_association" "waf_web_acl_association" {
  resource_arn = var.web_acl_association_resource_arn
  web_acl_arn  = var.web_acl_arn
}