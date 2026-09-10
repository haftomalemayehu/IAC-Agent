variable "name" {
  description = "Base name for the VPC resources"
  type        = string
}

variable "environment" {
  description = "Target environment"
  type        = string
  default     = "dev"
}

variable "cidr_block" {
  description = "CIDR for the VPC"
  type        = string
  default     = "10.10.0.0/16"
}

variable "availability_zones" {
  description = "Availability zones to create subnets in"
  type        = list(string)
  default     = ["us-east-1a", "us-east-1b", "us-east-1c"]
}

variable "public_subnets" {
  description = "Public subnet CIDR blocks"
  type        = list(string)
  default     = ["10.10.1.0/24", "10.10.2.0/24", "10.10.3.0/24"]
}

variable "private_subnets" {
  description = "Private subnet CIDR blocks"
  type        = list(string)
  default     = ["10.10.11.0/24", "10.10.12.0/24", "10.10.13.0/24"]
}
