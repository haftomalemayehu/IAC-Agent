# Tool Architecture

The agent interacts with infrastructure through explicit boundaries.

## Repository tools

- repo.read
- repo.search
- repo.write
- repo.tree

## Terraform tools

- terraform.version
- terraform.fmt
- terraform.init
- terraform.validate
- terraform.test
- terraform.plan
- terraform.show

## Security and policy tools

- tflint
- checkov
- trivy
- conftest
- OPA / Sentinel policies

## Cost tools

- infracost

## Git tools

- git status
- git diff
- git log
- git branch
- git checkout -b
- git add
- git commit

## Cloud read-only tools

- AWS STS / EC2 / RDS / IAM read-only queries

Deployment, destruction, and state operations remain behind an explicit approval gate.
