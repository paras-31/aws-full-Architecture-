output "oracle_db_username" {
  value = jsondecode(aws_secretsmanager_secret_version.db_password_value.secret_string)["username"]
  sensitive = true
}

output "oracle_db_password" {
  value = jsondecode(aws_secretsmanager_secret_version.db_password_value.secret_string)["password"]
  sensitive = true
}
