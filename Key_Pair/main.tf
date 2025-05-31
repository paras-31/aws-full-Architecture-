resource "tls_private_key" "rsa-4096-example" {
  algorithm = "RSA"
  rsa_bits  = 4096
}
resource "aws_key_pair" "deployer" {
  key_name   = var.key_name
  public_key = tls_private_key.rsa-4096-example.public_key_openssh
  tags = {
    Name            = "AWS-WAFR-Infra-Poject"
    ApplicationName = "AWS Wafr Infra"
    ProjectName     = "AWS Wafr"
    Role            = "aws-war-cf-pipeline"
    Owner           = "divya@cloudeq.com"
    Environment     = "Dev"
    SOW_NUMBER      = "CEQSOW24084OV"
    PROJECT_NAME    = "AWS DevSecOps WAFR Solutions"
  }
}

resource "local_file" "private_key" {
  content  = tls_private_key.rsa-4096-example.private_key_pem
  filename = var.key_name



}
