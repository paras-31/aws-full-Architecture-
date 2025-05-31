# resource "aws_wafv2_ip_set" "example" {

#   name               = "example"
#   description        = "Example IP set"
#   scope              = "REGIONAL"
#   ip_address_version = "IPV4"
#   addresses          = ["1.2.3.4/32", "5.6.7.8/32"]

#   tags = {
#     "START_DATE"       = ""
#     "END_DATE"         = ""
#     "PROJECT_NAME"     = "CSB"
#     "DEPARTMENT_NAME"  = "DevOps"
#     "APPLICATION_NAME" = "AWS VPC"
#     "CLIENT_NAME"      = "CSB"
#     "OWNER_NAME"       = "paras.kamboj@cloudeq.com"
#     "SOW_NUMBER"       = "1284864"
#     }
# }


resource "aws_wafv2_ip_set" "example" {
  name               = var.name
  description        = var.description
  scope              = var.scope
  ip_address_version = var.ip_address_version
  addresses          = var.addresses
  tags = {
    "START_DATE"       = ""
    "END_DATE"         = ""
    "PROJECT_NAME"     = "CSB"
    "DEPARTMENT_NAME"  = "DevOps"
    "APPLICATION_NAME" = "AWS VPC"
    "CLIENT_NAME"      = "CSB"
    "OWNER_NAME"       = "paras.kamboj@cloudeq.com"
    "SOW_NUMBER"       = "1284864"
   }
}