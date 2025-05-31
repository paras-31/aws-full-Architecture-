## RULE GROUP ARN OUTPUT
output "op_rule_group_arn" {
  value = aws_wafv2_rule_group.waf_rule_group.arn
}