# resource "aws_db_instance_role_association" "this" {
#   count = var.create ? 1 : 0

#   db_instance_identifier = var.db_instance_identifier
#   feature_name           = var.feature_name
#   role_arn               = var.role_arn
# }

resource "aws_iam_role" "rds_secret_access_role" {
  name = var.role_name

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "rds.amazonaws.com"
        }
      }
    ]
  })
}
resource "aws_iam_policy" "rds_secret_access_policy" {
  name        = var.iam_policy_name
  description = "Policy to allow RDS to retrieve secrets from Secrets Manager"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = [
          "secretsmanager:GetSecretValue"
        ]
        Effect   = "Allow"
        Resource = var.policy_resource
      }
    ]
  })
}
resource "aws_iam_role_policy_attachment" "rds_secret_access_attachment" {
  role       = aws_iam_role.rds_secret_access_role.name
  policy_arn = aws_iam_policy.rds_secret_access_policy.arn
}