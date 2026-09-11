package com.iacagent.iacagent.runner.jdbc;

import com.iacagent.iacagent.runner.ControlledTerraformOperation;
import com.iacagent.iacagent.runner.RunnerReasonCode;
import com.iacagent.iacagent.runner.TerraformProcessEvidence;
import com.iacagent.iacagent.runner.TerraformProcessState;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

/**
 * Manual, explicit JSON (de)serialization for {@link TerraformProcessEvidence}, used only to store
 * it in the {@code runner_requests.terraform_process_evidence} column
 * ({@code V2__add_terraform_process_evidence.sql}). Deliberately hand-written rather than relying
 * on Jackson's POJO/record data-binding for a fixed, small, fully-known field set - avoids any
 * dependency on this project's Jackson variant's record/{@link Instant}/enum binding support
 * (elsewhere in this codebase, {@code tools.jackson.databind.ObjectMapper} is used only for tree
 * parsing, e.g. {@code HostAttestedRunnerIdentityProvider}, never POJO binding) and keeps the exact
 * on-disk shape fully explicit and reviewable in one place.
 */
final class TerraformProcessEvidenceJson {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private TerraformProcessEvidenceJson() {
    }

    static String toJson(TerraformProcessEvidence evidence) {
        if (evidence == null) {
            return null;
        }
        StringBuilder json = new StringBuilder("{");
        field(json, "runnerRequestId", evidence.runnerRequestId(), true);
        field(json, "runnerId", evidence.runnerId(), true);
        field(json, "operation", evidence.operation() == null ? null : evidence.operation().name(), true);
        field(json, "executablePathIdentity", evidence.executablePathIdentity(), true);
        field(json, "executableSha256Expected", evidence.executableSha256Expected(), true);
        field(json, "executableSha256Observed", evidence.executableSha256Observed(), true);
        field(json, "terraformVersionExpected", evidence.terraformVersionExpected(), true);
        field(json, "terraformVersionObserved", evidence.terraformVersionObserved(), true);
        field(json, "workingDirectoryIdentity", evidence.workingDirectoryIdentity(), true);
        field(json, "planSha256Expected", evidence.planSha256Expected(), true);
        field(json, "planSha256Observed", evidence.planSha256Observed(), true);
        field(json, "argvTemplateId", evidence.argvTemplateId(), true);
        rawField(json, "exitCode", evidence.exitCode() == null ? "null" : String.valueOf(evidence.exitCode()), true);
        rawField(json, "timedOut", String.valueOf(evidence.timedOut()), true);
        field(json, "processState", evidence.processState().name(), true);
        rawField(json, "reasonCodes", "[" + evidence.reasonCodes().stream().map(rc -> quote(rc.name())).collect(Collectors.joining(",")) + "]", true);
        rawField(json, "stdoutSize", String.valueOf(evidence.stdoutSize()), true);
        rawField(json, "stderrSize", String.valueOf(evidence.stderrSize()), true);
        field(json, "stdoutSha256", evidence.stdoutSha256(), true);
        field(json, "stderrSha256", evidence.stderrSha256(), true);
        field(json, "startedAt", evidence.startedAt() == null ? null : evidence.startedAt().toString(), true);
        field(json, "completedAt", evidence.completedAt() == null ? null : evidence.completedAt().toString(), false);
        json.append("}");
        return json.toString();
    }

    static TerraformProcessEvidence fromJson(String json) {
        if (json == null || json.isBlank()) {
            return null;
        }
        JsonNode root = MAPPER.readTree(json);
        return new TerraformProcessEvidence(
                textOrNull(root, "runnerRequestId"),
                textOrNull(root, "runnerId"),
                ControlledTerraformOperation.valueOf(root.path("operation").asText()),
                textOrNull(root, "executablePathIdentity"),
                textOrNull(root, "executableSha256Expected"),
                textOrNull(root, "executableSha256Observed"),
                textOrNull(root, "terraformVersionExpected"),
                textOrNull(root, "terraformVersionObserved"),
                textOrNull(root, "workingDirectoryIdentity"),
                textOrNull(root, "planSha256Expected"),
                textOrNull(root, "planSha256Observed"),
                textOrNull(root, "argvTemplateId"),
                intOrNull(root, "exitCode"),
                root.path("timedOut").asBoolean(false),
                TerraformProcessState.valueOf(root.path("processState").asText()),
                parseReasonCodes(root.path("reasonCodes")),
                root.path("stdoutSize").asLong(0),
                root.path("stderrSize").asLong(0),
                textOrNull(root, "stdoutSha256"),
                textOrNull(root, "stderrSha256"),
                Instant.parse(root.path("startedAt").asText()),
                Instant.parse(root.path("completedAt").asText()));
    }

    private static List<RunnerReasonCode> parseReasonCodes(JsonNode arrayNode) {
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
