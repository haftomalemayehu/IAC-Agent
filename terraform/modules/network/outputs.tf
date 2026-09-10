output "vpc_id" {
  description = "VPC identifier"
  value       = aws_vpc.main.id
}

output "public_subnet_ids" {
  description = "Public subnet identifiers"
  value       = aws_subnet.public[*].id
}

output "private_subnet_ids" {
  description = "Private subnet identifiers"
  value       = aws_subnet.private[*].id
}

output "internet_gateway_id" {
  description = "Internet gateway identifier"
  value       = aws_internet_gateway.main.id
}
