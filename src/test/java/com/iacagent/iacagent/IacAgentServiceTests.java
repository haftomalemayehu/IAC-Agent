package com.iacagent.iacagent;

import com.iacagent.iacagent.model.ExecutionPlan;
import com.iacagent.iacagent.model.PlanRequest;
import com.iacagent.iacagent.model.TerraformChange;
import com.iacagent.iacagent.model.ValidationResult;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class IacAgentServiceTests {

    private final IacAgentService service = new IacAgentService();

    @Test
    void createPlanReturnsRiskScoreAndApprovalFlag() {
        PlanRequest request = new PlanRequest(
                "example/repo",
                "main",
                "dev",
                "Add VPC",
                List.of(
                        new TerraformChange("create", "aws_vpc", "main", "network", null, "10.10.0.0/16"),
                        new TerraformChange("create", "aws_subnet", "public", "network", null, "10.10.1.0/24"),
                        new TerraformChange("replace", "aws_security_group", "api", "network", "old", "new")
                ),
                false
        );

        ExecutionPlan plan = service.createPlan(request);

        assertNotNull(plan);
        assertNotNull(plan.planId());
        assertTrue(plan.approvalRequired());
        assertTrue(plan.riskScore() >= 15);
        assertNotNull(plan.guardrails());
    }

    @Test
    void validatePlanFlagsHighRiskChanges() {
        PlanRequest request = new PlanRequest(
                "example/repo",
                "main",
                "prod",
                "Database replacement",
                List.of(
                        new TerraformChange("replace", "aws_db_instance", "orders", "database", "old", "new")
                ),
                false
        );

        ExecutionPlan plan = service.createPlan(request);
        ValidationResult validation = service.validatePlan(plan);

        assertFalse(validation.valid());
        assertFalse(validation.findings().isEmpty());
        assertEquals("CRITICAL", plan.riskLevel());
    }

    @Test
    void missingPlanRequestThrows() {
        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () -> service.createPlan(null));
        assertTrue(exception.getMessage().contains("cannot be null"));
    }
}
