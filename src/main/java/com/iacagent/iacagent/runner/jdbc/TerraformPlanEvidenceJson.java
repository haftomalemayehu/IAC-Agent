package com.iacagent.iacagent.runner.jdbc;

import com.iacagent.iacagent.identity.WorkloadIdentityEvidence;
import com.iacagent.iacagent.runner.RunnerReasonCode;
import com.iacagent.iacagent.runner.TerraformPlanEvidence;
import com.iacagent.iacagent.runner.TerraformProcessState;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

/** Manual JSON (de)serialization for {@link TerraformPlanEvidence} - same discipline as
 * {@link TerraformProcessEvidenceJson}/{@link TerraformInitEvidenceJson}: a fixed, small, fully
 * known field set, hand-written rather than relying on Jackson POJO/record data binding. Never
 * carries credential material - {@link TerraformPlanEvidence} itself has no field for it; its
 * embedded {@link WorkloadIdentityEvidence} (Phase 2B-7) is, by its own construction, equally
 * incapable of carrying one (see that record's javadoc). */
final class TerraformPlanEvidenceJson {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private TerraformPlanEvidenceJson() {
    }

    static String toJson(TerraformPlanEvidence evidence) {
        if (evidence == null) {
            return null;
        }
        StringBuilder json = new StringBuilder("{");
        field(json, "runnerRequestId", evidence.runnerRequestId());
        field(json, "runnerId", evidence.runnerId());
        field(json, "repository", evidence.repository());
        field(json, "commitSha", evidence.commitSha());
        field(json, "environment", evidence.environment());
        field(json, "configSha256", evidence.configSha256());
        field(json, "stateIdentitySha256", evidence.stateIdentitySha256());
        field(json, "planInputSha256", evidence.planInputSha256());
        field(json, "executableSha256Expected", evidence.executableSha256Expected());
        field(json, "executableSha256Observed", evidence.executableSha256Observed());
        field(json, "terraformVersionExpected", evidence.terraformVersionExpected());
        field(json, "terraformVersionObserved", evidence.terraformVersionObserved());
        field(json, "providerLockHash", evidence.providerLockHash());
        field(json, "backendType", evidence.backendType());
        field(json, "backendInstanceId", evidence.backendInstanceId());
        field(json, "credentialSourceIdentifier", evidence.credentialSourceIdentifier());
        field(json, "planArtifactId", evidence.planArtifactId());
        field(json, "planSha256", evidence.planSha256());
        rawField(json, "planByteSize", String.valueOf(evidence.planByteSize()));
        field(json, "showJsonSha256", evidence.showJsonSha256());
        rawField(json, "showJsonByteSize", String.valueOf(evidence.showJsonByteSize()));
        rawField(json, "createCount", evidence.createCount() == null ? "null" : String.valueOf(evidence.createCount()));
        rawField(json, "updateCount", evidence.updateCount() == null ? "null" : String.valueOf(evidence.updateCount()));
        rawField(json, "replaceCount", evidence.replaceCount() == null ? "null" : String.valueOf(evidence.replaceCount()));
        rawField(json, "destroyCount", evidence.destroyCount() == null ? "null" : String.valueOf(evidence.destroyCount()));
        rawField(json, "exitCode", evidence.exitCode() == null ? "null" : String.valueOf(evidence.exitCode()));
        rawField(json, "timedOut", String.valueOf(evidence.timedOut()));
        field(json, "processState", evidence.processState().name());
        rawField(json, "reasonCodes", "[" + evidence.reasonCodes().stream().map(rc -> quote(rc.name())).collect(Collectors.joining(",")) + "]");
        field(json, "startedAt", evidence.startedAt() == null ? null : evidence.startedAt().toString());
        field(json, "completedAt", evidence.completedAt() == null ? null : evidence.completedAt().toString());
        rawField(json, "workloadIdentityEvidence", workloadIdentityEvidenceToJson(evidence.workloadIdentityEvidence()), false);
        json.append("}");
        return json.toString();
    }

    private static String workloadIdentityEvidenceToJson(WorkloadIdentityEvidence e) {
        if (e == null) {
            return "null";
        }
        StringBuilder json = new StringBuilder("{");
        field(json, "issuer", e.issuer());
        field(json, "subjectSha256", e.subjectSha256());
        field(json, "audience", e.audience());
        field(json, "repository", e.repository());
        field(json, "repositoryOwner", e.repositoryOwner());
        field(json, "workflowRef", e.workflowRef());
        field(json, "ref", e.ref());
        field(json, "environment", e.environment());
        field(json, "commitSha", e.commitSha());
        field(json, "issuedAt", e.issuedAt() == null ? null : e.issuedAt().toString());
        field(json, "expiresAt", e.expiresAt() == null ? null : e.expiresAt().toString());
        field(json, "verifiedAt", e.verifiedAt().toString());
        field(json, "verifierType", e.verifierType());
        field(json, "verifierVersion", e.verifierVersion());
        rawField(json, "authorized", String.valueOf(e.authorized()));
        field(json, "credentialProviderType", e.credentialProviderType());
        field(json, "cloudRoleIdentifier", e.cloudRoleIdentifier());
        field(json, "credentialExpiresAt", e.credentialExpiresAt() == null ? null : e.credentialExpiresAt().toString(), false);
        json.append("}");
        return json.toString();
    }

    private static WorkloadIdentityEvidence workloadIdentityEvidenceFromJson(JsonNode node) {
        if (node == null || node.isMissingNode() || node.isNull()) {
            return null;
        }
        return new WorkloadIdentityEvidence(
                textOrNull(node, "issuer"),
                textOrNull(node, "subjectSha256"),
                textOrNull(node, "audience"),
                textOrNull(node, "repository"),
                textOrNull(node, "repositoryOwner"),
                textOrNull(node, "workflowRef"),
                textOrNull(node, "ref"),
                textOrNull(node, "environment"),
                textOrNull(node, "commitSha"),
                instantOrNull(node, "issuedAt"),
                instantOrNull(node, "expiresAt"),
                Instant.parse(node.path("verifiedAt").asText()),
                textOrNull(node, "verifierType"),
                textOrNull(node, "verifierVersion"),
                node.path("authorized").asBoolean(false),
                textOrNull(node, "credentialProviderType"),
                textOrNull(node, "cloudRoleIdentifier"),
                instantOrNull(node, "credentialExpiresAt"));
    }

    private static Instant instantOrNull(JsonNode root, String field) {
        JsonNode node = root.path(field);
        return node.isMissingNode() || node.isNull() ? null : Instant.parse(node.asText());
    }

    static TerraformPlanEvidence fromJson(String json) {
        if (json == null || json.isBlank()) {
            return null;
        }
        JsonNode root = MAPPER.readTree(json);
        return new TerraformPlanEvidence(
                textOrNull(root, "runnerRequestId"),
                textOrNull(root, "runnerId"),
                textOrNull(root, "repository"),
                textOrNull(root, "commitSha"),
                textOrNull(root, "environment"),
                textOrNull(root, "configSha256"),
                textOrNull(root, "stateIdentitySha256"),
                textOrNull(root, "planInputSha256"),
                textOrNull(root, "executableSha256Expected"),
                textOrNull(root, "executableSha256Observed"),
                textOrNull(root, "terraformVersionExpected"),
                textOrNull(root, "terraformVersionObserved"),
                textOrNull(root, "providerLockHash"),
                textOrNull(root, "backendType"),
                textOrNull(root, "backendInstanceId"),
                textOrNull(root, "credentialSourceIdentifier"),
                textOrNull(root, "planArtifactId"),
                textOrNull(root, "planSha256"),
                root.path("planByteSize").asLong(0),
                textOrNull(root, "showJsonSha256"),
                root.path("showJsonByteSize").asLong(0),
                intOrNull(root, "createCount"),
                intOrNull(root, "updateCount"),
                intOrNull(root, "replaceCount"),
                intOrNull(root, "destroyCount"),
                intOrNull(root, "exitCode"),
                root.path("timedOut").asBoolean(false),
                TerraformProcessState.valueOf(root.path("processState").asText()),
                reasonCodeList(root.path("reasonCodes")),
                Instant.parse(root.path("startedAt").asText()),
                Instant.parse(root.path("completedAt").asText()))
                .withWorkloadIdentityEvidence(workloadIdentityEvidenceFromJson(root.path("workloadIdentityEvidence")));
    }

    private static List<RunnerReasonCode> reasonCodeList(JsonNode arrayNode) {
        List<RunnerReasonCode> codes = new ArrayList<>();
        for (JsonNode entry : arrayNode) {
            codes.add(RunnerReasonCode.valueOf(entry.asText()));
        }
        return codes;
    }

    private static String textOrNull(JsonNode root, String field) {
        JsonNode node = root.path(field);
        return node.isMissingNode() || node.isNull() ? null : node.asText();
    }

    private static Integer intOrNull(JsonNode root, String field) {
        JsonNode node = root.path(field);
        return node.isMissingNode() || node.isNull() ? null : node.asInt();
    }

    private static void field(StringBuilder json, String name, String value) {
        field(json, name, value, true);
    }

    private static void field(StringBuilder json, String name, String value, boolean trailingComma) {
        json.append(quote(name)).append(':').append(value == null ? "null" : quote(value));
        if (trailingComma) {
            json.append(',');
        }
    }

    private static void rawField(StringBuilder json, String name, String rawValue) {
        rawField(json, name, rawValue, true);
    }

    private static void rawField(StringBuilder json, String name, String rawValue, boolean trailingComma) {
        json.append(quote(name)).append(':').append(rawValue);
        if (trailingComma) {
            json.append(',');
        }
    }

    private static String quote(String value) {
        StringBuilder sb = new StringBuilder(value.length() + 2).append('"');
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            switch (c) {
                case '"' -> sb.append("\\\"");
                case '\\' -> sb.append("\\\\");
                case '\n' -> sb.append("\\n");
                case '\r' -> sb.append("\\r");
                case '\t' -> sb.append("\\t");
                default -> {
                    if (c < 0x20) {
                        sb.append(String.format("\\u%04x", (int) c));
                    } else {
                        sb.append(c);
                    }
                }
            }
        }
        return sb.append('"').toString();
    }
}
