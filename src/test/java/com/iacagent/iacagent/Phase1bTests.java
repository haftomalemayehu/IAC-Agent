package com.iacagent.iacagent;

import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class Phase1bTests {

    @Test
    void missingTerraformBinaryReturnsBlocked() {
        CommandRunner runner = new CommandRunner();
        CommandResult result = runner.run("/tmp", "definitely-not-a-real-command-xyz");
        assertEquals(ValidationState.BLOCKED, result.status());
    }

    @Test
    void secretRedactionMasksSensitiveValues() {
        CommandRunner runner = new CommandRunner();
        String redacted = runner.redact("token=super-secret-value password=letsgo");
        assertTrue(redacted.contains("[REDACTED]"));
        assertFalse(redacted.contains("super-secret-value"));
    }

    @Test
    void invalidStateTransitionIsRejected() {
        assertTrue(StateTransitionValidator.isValidTransition(ExecutionState.RECEIVED, ExecutionState.DISCOVERING));
        assertFalse(StateTransitionValidator.isValidTransition(ExecutionState.RECEIVED, ExecutionState.TESTING));
    }

    @Test
    void planJsonParserDetectsCreateUpdateReplaceAndDestroy() throws IOException {
        String json = """
                {
                  "resource_changes": [
                    {"address":"aws_vpc.main","type":"aws_vpc","name":"main","change":{"actions":["create"],"before":null,"after":{"cidr_block":"10.0.0.0/16"}}},
                    {"address":"aws_security_group.api","type":"aws_security_group","name":"api","change":{"actions":["update"],"before":{"ingress":["a"]},"after":{"ingress":["b"]}}},
                    {"address":"module.db.aws_db_instance.orders","type":"aws_db_instance","name":"orders","change":{"actions":["delete","create"],"before":{"id":"1"},"after":{"id":"2"}}},
                    {"address":"aws_s3_bucket.logs","type":"aws_s3_bucket","name":"logs","change":{"actions":["delete"],"before":{"id":"x"},"after":null}}
                  ]
                }
                """;

        PlanSummary summary = new PlanJsonParser().parse(json);

        assertEquals(1, summary.create());
        assertEquals(1, summary.update());
        assertEquals(1, summary.replace());
        assertEquals(1, summary.destroy());
        assertEquals(4, summary.changes().size());
    }

    @Test
    void productionRiskMultiplierRaisesRiskAndApprovalRequirement() {
        RiskEngine engine = new RiskEngine();
        PlanSummary summary = new PlanSummary(
                0,
                0,
                1,
                0,
                0,
                List.of(new ResourceChange("replace", "aws_db_instance", "orders", null, "{}", "{}"))
        );

        RiskAssessment assessment = engine.assess(summary, "prod");
        assertEquals(RiskLevel.HIGH, assessment.level());
        assertEquals(DeploymentEligibility.APPROVAL_REQUIRED, assessment.deploymentEligibility());
    }

    @Test
    void approvalMismatchInvalidatesPlanApproval() {
        ApprovalEngine engine = new ApprovalEngine();
        assertFalse(engine.isPlanHashValid("sha256:aaa", "sha256:bbb"));
        assertTrue(engine.isPlanHashValid("sha256:aaa", "sha256:aaa"));
    }

    @Test
    void forbiddenCommandsAreRejected() {
        CommandRunner runner = new CommandRunner();
        CommandResult result = runner.guard("/tmp", "terraform", "destroy");
        assertEquals(ValidationState.BLOCKED, result.status());
        assertTrue(result.stderr().contains("Forbidden"));
    }

    @Test
    void malformedJsonFailsParsing() {
        assertThrows(Exception.class, () -> new PlanJsonParser().parse("{not-valid-json"));
    }

    @Test
    void schemaVerificationRejectsUnknownResourceAndAttribute() {
        String schema = """
                {
                  "provider_schemas": {
                    "registry.terraform.io/hashicorp/aws": {
                      "resource_schemas": {
                        "aws_vpc": {
                          "block": {
                            "attributes": {
                              "cidr_block": {"type": "string"}
                            }
                          }
                        }
                      }
                    }
                  }
                }
                """;

        ProviderSchemaService service = new ProviderSchemaService("/tmp");
        try {
            service.cache(schema);
            assertFalse(service.resourceExists("registry.terraform.io/hashicorp/aws", "aws_unknown_resource"));
            assertFalse(service.attributeExists("aws_vpc", "unknown_attr"));
            assertEquals("UNKNOWN_RESOURCE_TYPE", service.schemaVerificationReason("registry.terraform.io/hashicorp/aws", "aws_unknown_resource", null));
            assertEquals("UNKNOWN_RESOURCE_ATTRIBUTE", service.schemaVerificationReason("registry.terraform.io/hashicorp/aws", "aws_vpc", "unknown_attr"));
        } catch (IOException e) {
            fail("schema cache should have been written");
        }
    }
}
