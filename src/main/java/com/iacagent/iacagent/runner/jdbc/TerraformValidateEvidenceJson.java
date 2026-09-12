package com.iacagent.iacagent.runner.jdbc;

import com.iacagent.iacagent.runner.RunnerReasonCode;
import com.iacagent.iacagent.runner.TerraformInitEvidence;
import com.iacagent.iacagent.runner.TerraformProcessState;
import com.iacagent.iacagent.runner.TerraformValidateEvidence;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

/** Manual JSON (de)serialization for {@link TerraformValidateEvidence} - same discipline as
 * {@link TerraformProcessEvidenceJson}; embeds {@link TerraformInitEvidenceJson}'s own serialization
 * for the {@code initEvidence} field rather than duplicating it. */
final class TerraformValidateEvidenceJson {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private TerraformValidateEvidenceJson() {
    }

    static String toJson(TerraformValidateEvidence evidence) {
        if (evidence == null) {
            return null;
        }
        StringBuilder json = new StringBuilder("{");
        field(json, "runnerRequestId", evidence.runnerRequestId(), true);
        field(json, "runnerId", evidence.runnerId(), true);
        rawField(json, "initEvidence", TerraformInitEvidenceJson.toJson(evidence.initEvidence()), true);
        field(json, "configSha256", evidence.configSha256(), true);
        rawField(json, "valid", evidence.valid() == null ? "null" : String.valueOf(evidence.valid()), true);
        rawField(json, "errorCount", evidence.errorCount() == null ? "null" : String.valueOf(evidence.errorCount()), true);
        rawField(json, "warningCount", evidence.warningCount() == null ? "null" : String.valueOf(evidence.warningCount()), true);
        rawField(json, "diagnosticFingerprints",
                "[" + evidence.diagnosticFingerprints().stream().map(TerraformInitEvidenceJson::quote).collect(Collectors.joining(",")) + "]", true);
        rawField(json, "exitCode", evidence.exitCode() == null ? "null" : String.valueOf(evidence.exitCode()), true);
        rawField(json, "timedOut", String.valueOf(evidence.timedOut()), true);
        field(json, "processState", evidence.processState().name(), true);
        rawField(json, "reasonCodes",
                "[" + evidence.reasonCodes().stream().map(rc -> TerraformInitEvidenceJson.quote(rc.name())).collect(Collectors.joining(",")) + "]", true);
        field(json, "stdoutSha256", evidence.stdoutSha256(), true);
        field(json, "startedAt", evidence.startedAt() == null ? null : evidence.startedAt().toString(), true);
        field(json, "completedAt", evidence.completedAt() == null ? null : evidence.completedAt().toString(), false);
        json.append("}");
        return json.toString();
    }

    static TerraformValidateEvidence fromJson(String json) {
        if (json == null || json.isBlank()) {
            return null;
        }
        JsonNode root = MAPPER.readTree(json);
        TerraformInitEvidence initEvidence = TerraformInitEvidenceJson.fromJson(root.path("initEvidence"));
        return new TerraformValidateEvidence(
                textOrNull(root, "runnerRequestId"),
                textOrNull(root, "runnerId"),
                initEvidence,
                textOrNull(root, "configSha256"),
                boolOrNull(root, "valid"),
                intOrNull(root, "errorCount"),
                intOrNull(root, "warningCount"),
                stringList(root.path("diagnosticFingerprints")),
                intOrNull(root, "exitCode"),
                root.path("timedOut").asBoolean(false),
                TerraformProcessState.valueOf(root.path("processState").asText()),
                reasonCodeList(root.path("reasonCodes")),
                textOrNull(root, "stdoutSha256"),
                Instant.parse(root.path("startedAt").asText()),
                Instant.parse(root.path("completedAt").asText()));
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

    private static String textOrNull(JsonNode root, String field) {
        JsonNode node = root.path(field);
        return node.isMissingNode() || node.isNull() ? null : node.asText();
    }

    private static Integer intOrNull(JsonNode root, String field) {
        JsonNode node = root.path(field);
        return node.isMissingNode() || node.isNull() ? null : node.asInt();
    }

    private static Boolean boolOrNull(JsonNode root, String field) {
        JsonNode node = root.path(field);
        return node.isMissingNode() || node.isNull() ? null : node.asBoolean();
    }

    private static void field(StringBuilder json, String name, String value, boolean trailingComma) {
        json.append(TerraformInitEvidenceJson.quote(name)).append(':').append(value == null ? "null" : TerraformInitEvidenceJson.quote(value));
        if (trailingComma) {
            json.append(',');
        }
    }

    private static void rawField(StringBuilder json, String name, String rawValue, boolean trailingComma) {
        json.append(TerraformInitEvidenceJson.quote(name)).append(':').append(rawValue == null ? "null" : rawValue);
        if (trailingComma) {
            json.append(',');
        }
    }
}
