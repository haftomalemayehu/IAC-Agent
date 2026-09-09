run "validate_module" {
  command = plan

  variables {
    name        = "iac-agent"
    environment = "dev"
    cidr_block  = "10.20.0.0/16"
  }

  assert {
    condition     = length(aws_vpc.main.tags) > 0
    error_message = "VPC should be tagged"
  }
}
