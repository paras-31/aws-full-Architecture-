output "waf_arn" {
  value = aws_wafv2_web_acl.default[0].arn
}
