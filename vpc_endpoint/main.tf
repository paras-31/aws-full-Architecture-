# Data block to fetch VPC endpoint service details
data "aws_vpc_endpoint_service" "this" {
  service      = var.service
  service_name = var.service_name

  filter {
    name   = "service-type"
    values = [var.service_type]
  }
}

# VPC Endpoint Resource
resource "aws_vpc_endpoint" "this" {
  vpc_id            = var.vpc_id
  service_name      = var.service_name != null ? var.service_name : data.aws_vpc_endpoint_service.this.service_name
  vpc_endpoint_type = var.service_type
  auto_accept       = var.auto_accept

  # Conditional arguments based on service type
  security_group_ids  = var.service_type == "Interface" ? var.security_group_ids : null
  subnet_ids          = var.service_type == "Interface" ? var.subnet_ids : null
  route_table_ids     = var.service_type == "Gateway" ? var.route_table_ids : null
  policy              = var.policy
  private_dns_enabled = var.service_type == "Interface" ? var.private_dns_enabled : null

  tags = var.tags

  timeouts {
    create = var.timeouts.create
    update = var.timeouts.update
    delete = var.timeouts.delete
  }
}