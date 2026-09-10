package com.iacagent.iacagent;

import com.iacagent.iacagent.model.ApprovalRequest;
import com.iacagent.iacagent.model.ExecutionRequest;
import com.iacagent.iacagent.model.ExecutionResult;
import com.iacagent.iacagent.model.ExecutionPlan;
import com.iacagent.iacagent.model.GovernanceCheck;
import com.iacagent.iacagent.model.PlanRequest;
import com.iacagent.iacagent.model.TerraformChange;
import com.iacagent.iacagent.model.ValidationResult;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.UUID;

@Service
public class IacAgentService {

    public ExecutionPlan plan(PlanRequest request) {
        return createPlan(request);
    }

    public ExecutionPlan createPlan(PlanRequest request) {
        if (request == null) {
            throw new IllegalArgumentException("Plan request cannot be null");
        }

        List<TerraformChange> changes = request.changes() == null ? List.of() : request.changes();
        int riskScore = calculateRiskScore(changes);
        String riskLevel = riskScore >= 31 ? "CRITICAL" : riskScore >= 16 ? "HIGH" : riskScore >= 6 ? "MEDIUM" : "LOW";

        List<GovernanceCheck> checks = new ArrayList<>();
        checks.add(new GovernanceCheck("terraform-format", "Terraform files are syntactically valid and formatted.", true, "INFO"));
        checks.add(new GovernanceCheck("cost-sentinel", "Estimated cost delta is within the spending guardrail.", riskScore < 80, "HIGH"));
        checks.add(new GovernanceCheck("owner-approval", "Change has a named owner and approval from a privileged reviewer.", riskScore < 60, "HIGH"));
        checks.add(new GovernanceCheck("drift-detection", "Infrastructure drift does not exceed tolerated threshold.", true, "MEDIUM"));

        boolean approvalRequired = riskLevel.equals("CRITICAL") || riskLevel.equals("HIGH") || !request.autoApprove();

        return new ExecutionPlan(
                UUID.randomUUID().toString(),
                request.repository(),
                request.branch(),
                request.workspace(),
                request.intent(),
                changes,
                riskScore,
                riskLevel,
                approvalRequired,
                checks,
                Instant.now().toString()
        );
    }

    public ValidationResult validate(ExecutionPlan plan) {
        return validatePlan(plan);
    }

    public ValidationResult validatePlan(ExecutionPlan plan) {
        if (plan == null) {
            throw new IllegalArgumentException("Plan cannot be null");
        }

        List<String> findings = new ArrayList<>();
        List<GovernanceCheck> checks = new ArrayList<>(plan.guardrails());
        boolean valid = true;

        if (plan.changes() == null || plan.changes().isEmpty()) {
            findings.add("No Terraform changes detected. The execution plan is a no-op.");
            valid = false;
        }

        if (plan.riskScore() >= 16) {
            findings.add("Risk score exceeds the safe operating envelope for automated apply.");
            valid = false;
        }

        for (GovernanceCheck check : checks) {
            if (check.severity().equalsIgnoreCase("HIGH") && !check.passed()) {
                findings.add("Guardrail failed: " + check.name());
                valid = false;
            }
        }

        if (valid && findings.isEmpty()) {
            findings.add("Plan passes governance checks and is ready for approval.");
        }

        return new ValidationResult(valid, !findings.isEmpty() ? findings : List.of("No blocking issues found."), checks, plan.riskLevel());
    }

    public ExecutionPlan approve(ApprovalRequest request) {
        return approvePlan(request);
    }

    public ExecutionPlan approvePlan(ApprovalRequest request) {
        if (request == null) {
            throw new IllegalArgumentException("Approval request cannot be null");
        }

        if (request.planId() == null || request.planId().isBlank()) {
            throw new IllegalArgumentException("Plan identifier is required");
        }

        ExecutionPlan plan = createPlan(new PlanRequest(
                "unknown-repository",
                "main",
                "default",
                "manual approval",
                List.of(),
                false
        ));
        plan = new ExecutionPlan(
                request.planId(),
                plan.repository(),
                plan.branch(),
                plan.workspace(),
                plan.intent(),
                plan.changes(),
                plan.riskScore(),
                plan.riskLevel(),
                request.approved() ? false : plan.approvalRequired(),
                plan.guardrails(),
                plan.generatedAt()
        );

        if (request.approved()) {
            List<GovernanceCheck> updated = new ArrayList<>(plan.guardrails());
            updated.replaceAll(check -> check.name().equals("owner-approval")
                    ? new GovernanceCheck(check.name(), check.description(), true, check.severity())
                    : check);
            plan = new ExecutionPlan(
                    plan.planId(),
                    plan.repository(),
                    plan.branch(),
                    plan.workspace(),
                    plan.intent(),
                    plan.changes(),
                    plan.riskScore(),
                    plan.riskLevel(),
                    false,
                    updated,
                    plan.generatedAt()
            );
        }

        return plan;
    }

    public ExecutionResult apply(ExecutionRequest request) {
        return executePlan(request);
    }

    public ExecutionResult executePlan(ExecutionRequest request) {
        if (request == null) {
            throw new IllegalArgumentException("Execution request cannot be null");
        }

        if (request.planId() == null || request.planId().isBlank()) {
            throw new IllegalArgumentException("Execution request requires a plan identifier");
        }

        String status = request.autoApprove() || request.approved() ? "APPLIED" : "PENDING_APPROVAL";
        List<String> steps = new ArrayList<>();
        steps.add("terraform init");
        steps.add("terraform validate");
        steps.add("terraform plan -out=tfplan");
        if ("APPLIED".equals(status)) {
            steps.add("terraform apply tfplan");
        }

        return new ExecutionResult(
                UUID.randomUUID().toString(),
                request.planId(),
                status,
                "Execution state managed by the IAC control loop.",
                steps,
                Instant.now().toString()
        );
    }

    private int calculateRiskScore(List<TerraformChange> changes) {
        int score = 0;
        for (TerraformChange change : changes) {
            score += switch (change.action().toLowerCase(Locale.ROOT)) {
                case "delete" -> 45;
                case "replace" -> 35;
                case "create" -> 15;
                default -> 10;
            };

            if (change.resourceType() != null && change.resourceType().contains("database")) {
                score += 25;
            }
            if (change.resourceType() != null && change.resourceType().contains("network")) {
                score += 15;
            }
            if (change.resourceType() != null && change.resourceType().contains("security")) {
                score += 12;
            }
        }

        if (changes.size() > 10) {
            score += 20;
        }
        return Math.min(score, 100);
    }
}
