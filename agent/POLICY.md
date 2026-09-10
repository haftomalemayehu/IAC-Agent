# Policy and Security Baseline

## Governance requirements

- Block CRITICAL and HIGH findings unless an explicit exception exists.
- Require approval for production apply, replacements, destroys, import, force-unlock, state operations, and network/IAM exposure changes.
- Never store secrets in Terraform files, variables, logs, or agent outputs.
- Do not permit direct pushes to protected branches.
- Require plan review and risk assessment for any material cost increase.

## Forbidden commands

```bash
terraform destroy
terraform apply -auto-approve
terraform state rm
terraform state mv
terraform force-unlock
terraform import
```

## Validation semantics

- PASS means command executed successfully.
- FAIL means the command ran and reported a failure.
- BLOCKED means a required tool or credential dependency prevented execution.
- NOT RUN means the stage was intentionally skipped or unavailable.
