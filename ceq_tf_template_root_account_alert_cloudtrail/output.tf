output "root_usage" {
  value = {
    metric_filter_id = aws_cloudwatch_log_metric_filter.root_usage[0].id
    alarm_name       = aws_cloudwatch_metric_alarm.root_usage[0].alarm_name
  }
}
