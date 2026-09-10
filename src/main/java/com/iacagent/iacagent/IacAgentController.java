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

@RestController
@RequestMapping({"/api/v1/iac", "/api/v1/agent"})
public class IacAgentController {

    private final IacAgentService service;
    private final TerraformExecutionService terraformExecutionService = new TerraformExecutionService();

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

    @PostMapping({"/pipeline", "/execute-pipeline"})
    public ResponseEntity<PipelineResult> executePipeline(@RequestBody PipelineRequest request) {
        return ResponseEntity.ok(terraformExecutionService.execute(request));
    }
}
