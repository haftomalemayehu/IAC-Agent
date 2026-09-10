run "vpc_has_expected_cidr" {
  command = plan

  assert {
    condition     = aws_vpc.main.cidr_block == "10.20.0.0/16"
    error_message = "VPC CIDR block must match the expected value"
  }
}
