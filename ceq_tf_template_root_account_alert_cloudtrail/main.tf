locals {
  resource_tags = merge(var.tags, { "Automation" = "Terraform" })
  alarm_prefix  = var.alarm_prefix != "" ? "${var.alarm_prefix}-" : ""
}



resource "aws_cloudwatch_log_metric_filter" "root_usage" {
  count = var.root_usage ? 1 : 0

  name           = var.metric_name 
  pattern        = var.pattern 
  log_group_name = var.cloudtrail_log_group_name

  metric_transformation {
    name      = var.metric_name
    namespace = var.alarm_namespace
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "root_usage" {
  count = var.root_usage ? 1 : 0

  alarm_name                = "${local.alarm_prefix}RootUsage"
  comparison_operator       = var.comparison_operator 
  evaluation_periods        = var.evaluation_periods 
  metric_name               = aws_cloudwatch_log_metric_filter.root_usage[0].id
  namespace                 = var.alarm_namespace
  period                    = var.period 
  statistic                 = var.statistic
  threshold                 = var.threshold 
  alarm_description         = var.alarm_description 
  alarm_actions             = [var.alarm_sns_topic_arn]
  treat_missing_data        = "notBreaching"
  insufficient_data_actions = []

  tags = local.resource_tags
}
