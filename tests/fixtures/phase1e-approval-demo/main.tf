# Phase 1E acceptance-evidence fixture: cloud-free (no AWS calls, no
# credentials) resource whose committed state intentionally diverges
# from this config, forcing a real `terraform plan` replace so the PR
# review pipeline's APPROVAL_REQUIRED path can be exercised against a
# real GitHub PR without touching any real infrastructure.
terraform {
  required_version = ">= 1.6.0, < 2.0.0"
}

resource "terraform_data" "demo" {
  triggers_replace = ["v2"]
}
