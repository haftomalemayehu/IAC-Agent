package com.iacagent.iacagent;

import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

public class InfracostCostService {
    private static final ObjectMapper MAPPER = new ObjectMapper();

    public CostDelta evaluate(Path workingDirectory) {
        if (workingDirectory == null) {
            return CostDelta.notRun("No working directory available");
        }
        if (!Files.exists(Path.of(workingDirectory.toString(), ".tool-versions"))) {
            return CostDelta.notRun("Infracost not configured");
        }
        return CostDelta.notRun("Infracost not executed in this environment");
    }

    public static CostDelta parseJson(String json) {
        if (json == null || json.isBlank()) {
            return CostDelta.notRun("No Infracost JSON available");
        }
        try {
            JsonNode root = MAPPER.readTree(json);
            double current = readDouble(root, "currentMonthlyCost", "totalMonthlyCost", "summary.currentMonthlyCost");
            double proposed = readDouble(root, "proposedMonthlyCost", "diffTotalMonthlyCost", "summary.proposedMonthlyCost");
            if (current == 0d && proposed == 0d) {
                return CostDelta.notRun("No cost values found in Infracost output");
            }
            return CostDelta.fromCurrentAndProposed(current, proposed);
        } catch (Exception e) {
            return CostDelta.blocked("Malformed Infracost JSON");
        }
    }

    private static double readDouble(JsonNode root, String... names) {
        for (String name : names) {
            JsonNode node = resolve(root, name);
            if (node != null && !node.isNull() && node.isNumber()) {
                return node.doubleValue();
            }
        }
        return 0d;
    }

    private static JsonNode resolve(JsonNode root, String dottedPath) {
        String[] parts = dottedPath.split("\\.");
        JsonNode current = root;
        for (String part : parts) {
            if (current == null || current.isNull()) {
                return null;
            }
            current = current.get(part);
        }
        return current;
    }
}
