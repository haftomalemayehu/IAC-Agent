package com.iacagent.iacagent;

import com.iacagent.iacagent.model.ApprovalRequest;
import com.iacagent.iacagent.model.ExecutionPlan;
import com.iacagent.iacagent.model.ExecutionRequest;
import com.iacagent.iacagent.model.ExecutionResult;
import com.iacagent.iacagent.model.PlanRequest;
import com.iacagent.iacagent.model.ValidationResult;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/**
 * Phase 2B-3 final amendment: this controller no longer wires {@code TerraformExecutionService} to
 * any HTTP endpoint - the {@code /pipeline}/{@code /execute-pipeline} mapping that used to do so has
 * been removed entirely. That was the only Spring-reachable path into the Phase 1 generic execution
 * engine. {@code TerraformExecutionService}, {@code TerraformCliAdapter}, and the
 * {@code PipelineRequest}/{@code PipelineResult} records that existed only to serve them have since
 * been deleted from {@code src/main} outright (they had no other production consumer);
 * {@code CommandRunner}'s {@link ProcessBuilder}-based generic {@code String... command} surface has
 * been moved to {@code src/test} so {@code Phase1bTests} can keep exercising it directly without it
 * being part of the running application at all. {@code src/main} now contains exactly one
 * process-spawning class, {@code com.iacagent.iacagent.runner.ControlledTerraformProcess} - see
 * {@code ProductionExecutionSurfaceTests} for the structural proof, and
 * {@code docs/phase-2b3-controlled-terraform-process.md} SS13 for the full inventory and
 * reasoning. {@code /apply}/{@code /execute} below remain wired to {@link IacAgentService#executePlan}
 * only, which is a pure simulation (a list of textual step descriptions) with no process-spawning
 * capability of any kind.
 */
@RestController
@RequestMapping({"/api/v1/iac", "/api/v1/agent"})
public class IacAgentController {

    private final IacAgentService service;

    public IacAgentController(IacAgentService service) {
        this.service = service;
    }

    @GetMapping({"/health", "/status"})
    public Map<String, String> health() {
        return Map.of("status", "healthy", "service", "iac-agent");
    }

    @PostMapping({"/plan", "/create-plan"})
    public ResponseEntity<ExecutionPlan> createPlan(@Valid @RequestBody PlanRequest request) {
        return ResponseEntity.ok(service.createPlan(request));
    }

    @PostMapping({"/validate", "/check-plan"})
    public ResponseEntity<ValidationResult> validatePlan(@Valid @RequestBody ExecutionPlan plan) {
        return ResponseEntity.ok(service.validatePlan(plan));
    }

    @PostMapping({"/approve", "/approval"})
    public ResponseEntity<ExecutionPlan> approve(@Valid @RequestBody ApprovalRequest request) {
        return ResponseEntity.ok(service.approvePlan(request));
    }

    @PostMapping({"/apply", "/execute"})
    public ResponseEntity<ExecutionResult> apply(@Valid @RequestBody ExecutionRequest request) {
        return ResponseEntity.ok(service.executePlan(request));
    }
}
