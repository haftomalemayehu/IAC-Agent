package com.iacagent.iacagent;

import tools.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public class TerraformExecutionService {
    private final CommandRunner commandRunner = new CommandRunner();
    private final TerraformCliAdapter terraformCliAdapter = new TerraformCliAdapter(commandRunner);
    private final RiskEngine riskEngine = new RiskEngine();
    private final ApprovalEngine approvalEngine = new ApprovalEngine();
    private final ArtifactSessionManager artifactSessionManager = new ArtifactSessionManager();
    private final ObjectMapper mapper = new ObjectMapper();

    public PipelineResult execute(PipelineRequest request) {
        if (request == null) {
            throw new IllegalArgumentException("Pipeline request cannot be null");
        }

        String workingDirectory = request.workingDirectory() == null || request.workingDirectory().isBlank()
                ? System.getProperty("user.dir")
                : request.workingDirectory();

        Map<String, ValidationState> stages = new LinkedHashMap<>();
        List<String> reasons = new ArrayList<>();

        try {
            Path sessionDirectory = artifactSessionManager.createSessionDirectory(request.requestId());
            artifactSessionManager.saveJson(sessionDirectory, "request.json", request);

            CommandResult init = terraformCliAdapter.initBackendFalse(workingDirectory);
            stages.put("init", init.status());
            artifactSessionManager.saveText(sessionDirectory, "init.json", mapper.writeValueAsString(init));
            if (init.status() != ValidationState.PASS) {
                return new PipelineResult(request.requestId(), ValidationState.BLOCKED, RiskLevel.LOW, DeploymentEligibility.BLOCKED, stages, new PlanSummary(0, 0, 0, 0, 0, List.of()), null, reasons);
            }

            CommandResult schemaCommand = terraformCliAdapter.providerSchema(workingDirectory);
            stages.put("providerSchema", schemaCommand.status());
            artifactSessionManager.saveText(sessionDirectory, "provider-schema.json", schemaCommand.stdout() == null ? "" : schemaCommand.stdout());
            if (schemaCommand.status() == ValidationState.PASS) {
                ProviderSchemaService schemaService = new ProviderSchemaService(workingDirectory);
                schemaService.cache(schemaCommand.stdout());
                if (!schemaService.isSchemaVerified()) {
                    stages.put("providerSchema", ValidationState.BLOCKED);
                    reasons.add("SCHEMA_UNVERIFIED");
                    return new PipelineResult(request.requestId(), ValidationState.BLOCKED, RiskLevel.LOW, DeploymentEligibility.BLOCKED, stages, new PlanSummary(0, 0, 0, 0, 0, List.of()), null, reasons);
                }
            } else {
                reasons.add("SCHEMA_UNVERIFIED");
                return new PipelineResult(request.requestId(), ValidationState.BLOCKED, RiskLevel.LOW, DeploymentEligibility.BLOCKED, stages, new PlanSummary(0, 0, 0, 0, 0, List.of()), null, reasons);
            }

            CommandResult fmt = terraformCliAdapter.fmtCheck(workingDirectory);
            stages.put("fmt", fmt.status());
            artifactSessionManager.saveText(sessionDirectory, "fmt.json", mapper.writeValueAsString(fmt));

            CommandResult validate = terraformCliAdapter.validate(workingDirectory);
            stages.put("validate", validate.status());
            artifactSessionManager.saveText(sessionDirectory, "validate.json", mapper.writeValueAsString(validate));
            if (validate.status() != ValidationState.PASS) {
                return new PipelineResult(request.requestId(), ValidationState.FAIL, RiskLevel.LOW, DeploymentEligibility.BLOCKED, stages, new PlanSummary(0, 0, 0, 0, 0, List.of()), null, List.of("terraform validate failed"));
            }

            CommandResult lint = terraformCliAdapter.lint(workingDirectory);
            stages.put("lint", lint.status());
            artifactSessionManager.saveText(sessionDirectory, "tflint.json", mapper.writeValueAsString(lint));

            CommandResult security = terraformCliAdapter.security(workingDirectory);
            stages.put("security", security.status());
            artifactSessionManager.saveText(sessionDirectory, "checkov.json", mapper.writeValueAsString(security));

            CommandResult test = terraformCliAdapter.test(workingDirectory);
            stages.put("test", test.status());
            artifactSessionManager.saveText(sessionDirectory, "test.json", mapper.writeValueAsString(test));

            String planPath = Path.of(workingDirectory, ".agent", "artifacts", "tfplan").toString();
            CommandResult plan = terraformCliAdapter.plan(workingDirectory, planPath);
            stages.put("plan", plan.status());
            artifactSessionManager.saveText(sessionDirectory, "tfplan", plan.stdout() == null ? "" : plan.stdout());
            if (plan.status() != ValidationState.PASS) {
                return new PipelineResult(request.requestId(), ValidationState.FAIL, RiskLevel.LOW, DeploymentEligibility.BLOCKED, stages, new PlanSummary(0, 0, 0, 0, 0, List.of()), null, List.of("terraform plan failed"));
            }

            CommandResult showPlanJson = terraformCliAdapter.showPlanJson(workingDirectory, planPath);
            stages.put("showPlanJson", showPlanJson.status());
            artifactSessionManager.saveText(sessionDirectory, "plan.json", showPlanJson.stdout() == null ? "" : showPlanJson.stdout());
            if (showPlanJson.status() != ValidationState.PASS) {
                return new PipelineResult(request.requestId(), ValidationState.FAIL, RiskLevel.LOW, DeploymentEligibility.BLOCKED, stages, new PlanSummary(0, 0, 0, 0, 0, List.of()), null, List.of("terraform show failed"));
            }

            PlanSummary planSummary = new PlanJsonParser().parse(showPlanJson.stdout());
            artifactSessionManager.saveJson(sessionDirectory, "plan-summary.json", planSummary);
            RiskAssessment riskAssessment = riskEngine.assess(planSummary, request.environment());
            artifactSessionManager.saveJson(sessionDirectory, "risk.json", riskAssessment);

            ApprovalEngine.ApprovalBinding approval = approvalEngine.bindApproval(request.requestId(), request.environment(), "sha256:pending", "human", "risk=" + riskAssessment.level());
            approval = new ApprovalEngine.ApprovalBinding(request.requestId(), request.environment(), "sha256:pending", "human", java.time.Instant.now().toString(), "risk=" + riskAssessment.level(), List.of("HIGH_RISK"));
            if (riskAssessment.deploymentEligibility() == DeploymentEligibility.APPROVAL_REQUIRED) {
                reasons.add("HIGH_RISK");
                reasons.add("RESOURCE_REPLACEMENT");
            }

            ValidationState validity = stages.values().stream().allMatch(v -> v == ValidationState.PASS) ? ValidationState.PASS : ValidationState.FAIL;
            DeploymentEligibility deploymentEligibility = validity == ValidationState.PASS
                    ? riskAssessment.deploymentEligibility()
                    : DeploymentEligibility.BLOCKED;

            return new PipelineResult(request.requestId(), validity, riskAssessment.level(), deploymentEligibility, stages, planSummary, approval, reasons);
        } catch (IOException e) {
            return new PipelineResult(request.requestId(), ValidationState.BLOCKED, RiskLevel.LOW, DeploymentEligibility.BLOCKED, stages, new PlanSummary(0, 0, 0, 0, 0, List.of()), null, List.of(e.getMessage()));
        }
    }
}
