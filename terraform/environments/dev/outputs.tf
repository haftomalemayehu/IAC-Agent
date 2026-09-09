output "vpc_id" {
  description = "Dev environment VPC ID"
  value       = module.network.vpc_id
}

output "public_subnet_ids" {
  description = "Dev environment public subnets"
  value       = module.network.public_subnet_ids
}
