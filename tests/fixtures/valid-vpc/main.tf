terraform {
  required_version = ">= 1.6.0, < 2.0.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region                      = "us-east-1"
  access_key                 = "test"
  secret_key                 = "test"
  skip_credentials_validation = true
  skip_metadata_api_check    = true
  skip_requesting_account_id = true
}

resource "aws_vpc" "main" {
  cidr_block = "10.20.0.0/16"

  tags = {
    Name = "valid-vpc"
  }
}

resource "aws_default_security_group" "default" {
  vpc_id  = aws_vpc.main.id
  ingress = []
  egress  = []
}

resource "aws_kms_key" "vpc_flow" {
  description             = "KMS key for VPC flow log encryption"
  deletion_window_in_days = 10
  enable_key_rotation     = true
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid    = "EnableRootPermissions"
      Effect = "Allow"
      Principal = {
        AWS = "arn:aws:iam::123456789012:root"
      }
      Action   = "kms:*"
      Resource = "*"
    }]
  })
}

resource "aws_kms_alias" "vpc_flow" {
  name          = "alias/valid-vpc-flow"
  target_key_id = aws_kms_key.vpc_flow.key_id
}

resource "aws_cloudwatch_log_group" "vpc_flow" {
  name              = "/aws/vpc/valid-vpc-flow"
  retention_in_days = 365
  kms_key_id        = aws_kms_key.vpc_flow.arn
}

resource "aws_iam_role" "vpc_flow" {
  name = "valid-vpc-flow-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "vpc-flow-logs.amazonaws.com"
      }
    }]
  })
}

resource "aws_iam_role_policy" "vpc_flow" {
  name = "valid-vpc-flow-policy"
  role = aws_iam_role.vpc_flow.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "CreateLogGroup"
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup"
        ]
        Resource = "arn:aws:logs:us-east-1:*:log-group:/aws/vpc/valid-vpc-flow"
      },
      {
        Sid    = "WriteFlowLog"
        Effect = "Allow"
        Action = [
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = [
          "arn:aws:logs:us-east-1:*:log-group:/aws/vpc/valid-vpc-flow:log-stream:*"
        ]
      }
    ]
  })
}

resource "aws_flow_log" "vpc" {
  log_destination_type = "cloud-watch-logs"
  log_group_name       = aws_cloudwatch_log_group.vpc_flow.name
  iam_role_arn         = aws_iam_role.vpc_flow.arn
  traffic_type         = "ALL"
  vpc_id               = aws_vpc.main.id
}

resource "aws_subnet" "private" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = "10.20.1.0/24"
  map_public_ip_on_launch = false
  availability_zone       = "us-east-1a"

  tags = {
    Name = "valid-vpc-private"
  }
}
