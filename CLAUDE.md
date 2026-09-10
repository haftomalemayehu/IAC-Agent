# Terraform Agent Repository

Read before modifying infrastructure:

- agent/CONTRACT.md
- agent/POLICY.md
- agent/WORKFLOW.md

## Mandatory workflow

Inspect → Design → Verify Schema → Author → Validate → Test → Plan → Review.

Never invent provider attributes.

For unfamiliar provider resources, verify against:

terraform providers schema -json

Never claim validation succeeded unless the command ran successfully.

Production apply and destructive/state-changing operations require explicit approval.

Do not modify unrelated infrastructure.

Use the smallest safe change.

After changes run:

make verify

Return results using the agent output contract.
