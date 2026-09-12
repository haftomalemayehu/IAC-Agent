package com.iacagent.iacagent.runner.jdbc;

import com.iacagent.iacagent.runner.RunnerReasonCode;
import com.iacagent.iacagent.runner.TerraformBackendMode;
import com.iacagent.iacagent.runner.TerraformInitEvidence;
import com.iacagent.iacagent.runner.TerraformNetworkRequirement;
import com.iacagent.iacagent.runner.TerraformProcessState;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

/**
 * Manual, explicit JSON (de)serialization for {@link TerraformInitEvidence} - same hand-written
 * discipline as {@link TerraformProcessEvidenceJson}, for the same reason (a fixed, small, fully
 * known field set; this codebase's Jackson variant is used only for tree parsing, never POJO/record
 * data binding). Package-visible so {@link TerraformValidateEvidenceJson}/
 * {@link TerraformProviderSchemaEvidenceJson} can reuse it to (de)serialize their embedded
 * {@code initEvidence} field.
 */
final class TerraformInitEvidenceJson {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private TerraformInitEvidenceJson() {
    }

    static String toJson(TerraformInitEvidence evidence) {
        if (evidence == null) {
            return null;
        }
        StringBuilder json = new StringBuilder("{");
        field(json, "runnerRequestId", evidence.runnerRequestId(), true);
        field(json, "runnerId", evidence.runnerId(), true);
        field(json, "configSha256", evidence.configSha256(), true);
        field(json, "executableSha256Expected", evidence.executableSha256Expected(), true);
        field(json, "executableSha256Observed", evidence.executableSha256Observed(), true);
        field(json, "terraformVersionExpected", evidence.terraformVersionExpected(), true);
        field(json, "terraformVersionObserved", evidence.terraformVersionObserved(), true);
        field(json, "backendMode", evidence.backendMode() == null ? null : evidence.backendMode().name(), true);
        field(json, "networkRequirement", evidence.networkRequirement() == null ? null : evidence.networkRequirement().name(), true);
        rawField(json, "providerSourcesRequested", stringArray(evidence.providerSourcesRequested()), true);
        rawField(json, "moduleSourcesRequested", stringArray(evidence.moduleSourcesRequested()), true);
        field(json, "lockfileHashBefore", evidence.lockfileHashBefore(), true);
        field(json, "lockfileHashAfter", evidence.lockfileHashAfter(), true);
        rawField(json, "exitCode", evidence.exitCode() == null ? "null" : String.valueOf(evidence.exitCode()), true);
        rawField(json, "timedOut", String.valueOf(evidence.timedOut()), true);
        field(json, "processState", evidence.processState().name(), true);
        rawField(json, "reasonCodes", stringArray(evidence.reasonCodes().stream().map(Enum::name).toList()), true);
        rawField(json, "stdoutSize", String.valueOf(evidence.stdoutSize()), true);
        rawField(json, "stderrSize", String.valueOf(evidence.stderrSize()), true);
        field(json, "stdoutSha256", evidence.stdoutSha256(), true);
        field(json, "stderrSha256", evidence.stderrSha256(), true);
        field(json, "startedAt", evidence.startedAt() == null ? null : evidence.startedAt().toString(), true);
        field(json, "completedAt", evidence.completedAt() == null ? null : evidence.completedAt().toString(), false);
        json.append("}");
        return json.toString();
    }

    static TerraformInitEvidence fromJson(JsonNode root) {
        if (root == null || root.isMissingNode() || root.isNull()) {
            return null;
        }
        return new TerraformInitEvidence(
                textOrNull(root, "runnerRequestId"),
                textOrNull(root, "runnerId"),
                textOrNull(root, "configSha256"),
                textOrNull(root, "executableSha256Expected"),
                textOrNull(root, "executableSha256Observed"),
                textOrNull(root, "terraformVersionExpected"),
                textOrNull(root, "terraformVersionObserved"),
                TerraformBackendMode.valueOf(root.path("backendMode").asText()),
                TerraformNetworkRequirement.valueOf(root.path("networkRequirement").asText()),
                stringList(root.path("providerSourcesRequested")),
                stringList(root.path("moduleSourcesRequested")),
                textOrNull(root, "lockfileHashBefore"),
                textOrNull(root, "lockfileHashAfter"),
                intOrNull(root, "exitCode"),
                root.path("timedOut").asBoolean(false),
                TerraformProcessState.valueOf(root.path("processState").asText()),
                reasonCodeList(root.path("reasonCodes")),
                root.path("stdoutSize").asLong(0),
                root.path("stderrSize").asLong(0),
                textOrNull(root, "stdoutSha256"),
                textOrNull(root, "stderrSha256"),
                Instant.parse(root.path("startedAt").asText()),
                Instant.parse(root.path("completedAt").asText()));
    }

    static JsonNode parseTree(String json) {
        return json == null || json.isBlank() ? null : MAPPER.readTree(json);
    }

    private static List<String> stringList(JsonNode arrayNode) {
        List<String> values = new ArrayList<>();
        for (JsonNode entry : arrayNode) {
            values.add(entry.asText());
        }
        return values;
    }

    private static List<RunnerReasonCode> reasonCodeList(JsonNode arrayNode) {
        List<RunnerReasonCode> codes = new ArrayList<>();
        for (JsonNode entry : arrayNode) {
            codes.add(RunnerReasonCode.valueOf(entry.asText()));
        }
        return codes;
    }

    private static String stringArray(List<String> values) {
        return "[" + values.stream().map(TerraformInitEvidenceJson::quote).collect(Collectors.joining(",")) + "]";
    }

    private static String textOrNull(JsonNode root, String field) {
        JsonNode node = root.path(field);
        return node.isMissingNode() || node.isNull() ? null : node.asText();
    }

    private static Integer intOrNull(JsonNode root, String field) {
        JsonNode node = root.path(field);
        return node.isMissingNode() || node.isNull() ? null : node.asInt();
    }

    private static void field(StringBuilder json, String name, String value, boolean trailingComma) {
        json.append(quote(name)).append(':').append(value == null ? "null" : quote(value));
        if (trailingComma) {
            json.append(',');
        }
    }

    private static void rawField(StringBuilder json, String name, String rawValue, boolean trailingComma) {
        json.append(quote(name)).append(':').append(rawValue);
        if (trailingComma) {
            json.append(',');
        }
    }

    static String quote(String value) {
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
