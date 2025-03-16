
data "aws_region" "current" {
}

data "aws_caller_identity" "current" {
}

############
# Cloudwatch
############
data "aws_iam_policy_document" "cloudtrail_assume_role" {

  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
  }
   
}

data "aws_iam_policy_document" "cloudtrail_cloudwatch_logs" {

  statement {
    effect = "Allow"
    actions = [
      "logs:CreateLogStream",
      "logs:PutLogEvents",
    ]
    resources = ["arn:aws:logs:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:log-group:${var.name}-cloudtrail-log-group:*"]
  }
}

resource "aws_iam_role" "cloudtrail_cloudwatch_role" {
  count = var.enable_cloudwatch_logs ? 1 : 0

  name               = "${var.name}-cloudtrail-iam-role"
  assume_role_policy = data.aws_iam_policy_document.cloudtrail_assume_role.json

  tags = var.tags
}

resource "aws_iam_policy" "cloudtrail_cloudwatch_logs" {
  count = var.enable_cloudwatch_logs ? 1 : 0

  name   = "${var.name}-cloudtrail-cloudwatch-logs-policy"
  policy = data.aws_iam_policy_document.cloudtrail_cloudwatch_logs.json

  tags = var.tags
}

resource "aws_iam_role_policy_attachment" "cloudwatch_logs" {
  count = var.enable_cloudwatch_logs ? 1 : 0

  policy_arn = aws_iam_policy.cloudtrail_cloudwatch_logs[0].arn
  role       = aws_iam_role.cloudtrail_cloudwatch_role[0].name
}

resource "aws_cloudwatch_log_group" "cloudtrail" {
  count = var.enable_cloudwatch_logs ? 1 : 0

  name              = "${var.name}-cloudtrail-log-group"
  retention_in_days = var.cloudwatch_logs_retention_in_days
  kms_key_id        = var.create_kms_key 

  tags = var.tags
}

resource "aws_cloudtrail" "this" {
  name = "${var.name}-cloudtrail"

  s3_bucket_name                = var.s3_bucket_name
  s3_key_prefix                 = var.s3_key_prefix
  cloud_watch_logs_role_arn     = var.enable_cloudwatch_logs ? aws_iam_role.cloudtrail_cloudwatch_role[0].arn : null
  cloud_watch_logs_group_arn    = var.enable_cloudwatch_logs ? "${aws_cloudwatch_log_group.cloudtrail[0].arn}:*" : null
  enable_log_file_validation    = var.enable_log_file_validation
  enable_logging                = var.enable_logging
  include_global_service_events = var.include_global_service_events
  is_multi_region_trail         = var.is_multi_region_trail
  is_organization_trail         = var.is_organization_trail
  kms_key_id                    = var.create_kms_key           
  #sns_topic_name                = var.enable_sns_notifications 

  tags = var.tags

  dynamic "event_selector" {
    for_each = var.event_selectors
    content {
      include_management_events = lookup(event_selector.value, "include_management_events", null)
      read_write_type           = lookup(event_selector.value, "read_write_type", null)
      data_resource {
        type   = lookup(event_selector.value.data_resource, "type", null)
        values = lookup(event_selector.value.data_resource, "values", null)
      }
    }
  }

  dynamic "insight_selector" {
    for_each = var.insight_selectors
    content {
      insight_type = lookup(insight_selector.value, "insight_type", null)
    }
  }
}



