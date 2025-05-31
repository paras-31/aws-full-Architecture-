resource "aws_secretsmanager_secret" "db_password" {
  name        = var.secret_name
  description = "Password for the Oracle RDS instance"
}

resource "aws_secretsmanager_secret_version" "db_password_value" {
  secret_id     = aws_secretsmanager_secret.db_password.id
  secret_string = jsonencode({
    username = var.rds_username  # Replace with actual username
    password = var.rds_password # Replace with actual strong password
  })
}

