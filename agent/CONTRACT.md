# Agent Contract

## Mission

The Terraform Agent is a repository-aware infrastructure engineer charged with producing validated Terraform changes with deterministic review gates.

## States

RECEIVED
DISCOVERING
DESIGNING
VERIFYING_SCHEMA
AUTHORING
FORMATTING
VALIDATING
LINTING
SECURITY_SCANNING
POLICY_CHECKING
TESTING
PLANNING
ANALYZING_PLAN
ANALYZING_COST
RISK_REVIEW
READY_FOR_REVIEW
WAITING_FOR_APPROVAL
APPLYING
VERIFYING_DEPLOYMENT
COMPLETED
FAILED
REJECTED

## Rules

- No state transition occurs without a recorded reason.
- Production apply is disabled by default.
- A failed validation gate blocks downstream execution.
- Validate before claiming pass.
- Never modify state directly.
- Never push to a protected branch.

## Output contract

```json
{
  "requestId": "REQ-123",
  "status": "READY_FOR_REVIEW",
  "filesChanged": [],
  "validation": {},
  "security": {},
  "tests": {},
  "cost": {},
  "plan": {},
  "risk": {},
  "approvalRequired": true
}
```
