module "network" {
  source = "../../modules/network"

  name        = "iac-agent-dev"
  environment = "dev"
  cidr_block  = "10.40.0.0/16"

  availability_zones = ["us-east-1a", "us-east-1b", "us-east-1c"]
  public_subnets     = ["10.40.1.0/24", "10.40.2.0/24", "10.40.3.0/24"]
  private_subnets    = ["10.40.11.0/24", "10.40.12.0/24", "10.40.13.0/24"]
}
