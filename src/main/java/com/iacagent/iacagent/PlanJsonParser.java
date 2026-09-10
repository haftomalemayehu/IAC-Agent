package com.iacagent.iacagent;

import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public class PlanJsonParser {
    private static final ObjectMapper MAPPER = new ObjectMapper();

    public PlanSummary parse(String json) throws IOException {
        JsonNode root = MAPPER.readTree(json);
        JsonNode resourceChanges = root.path("resource_changes");
        int create = 0;
        int update = 0;
        int replace = 0;
        int destroy = 0;
        int noOp = 0;
        List<ResourceChange> changes = new ArrayList<>();

        if (resourceChanges.isArray()) {
            for (JsonNode entry : resourceChanges) {
                String action = normalizeAction(entry.path("change").path("actions"));
                String resourceType = entry.path("type").asText();
                String resourceName = entry.path("name").asText();
                String address = entry.path("address").asText();
                String module = moduleName(address);
                String before = entry.path("change").path("before").toString();
                String after = entry.path("change").path("after").toString();

                ResourceChange resourceChange = new ResourceChange(action, resourceType, resourceName, module, before, after);
                changes.add(resourceChange);

                switch (action) {
                    case "create" -> create++;
                    case "update" -> update++;
                    case "replace" -> replace++;
                    case "destroy" -> destroy++;
                    default -> noOp++;
                }
            }
        }

        return new PlanSummary(create, update, replace, destroy, noOp, changes);
    }

    private String normalizeAction(JsonNode actionsNode) {
        if (actionsNode == null || !actionsNode.isArray() || actionsNode.isEmpty()) {
            return "no-op";
        }

        List<String> actions = new ArrayList<>();
        for (JsonNode actionNode : actionsNode) {
            actions.add(actionNode.asText());
        }

        boolean hasCreate = actions.contains("create");
        boolean hasDelete = actions.contains("delete");
        boolean hasUpdate = actions.contains("update");

        if (hasCreate && hasDelete) {
            return "replace";
        }
        if (hasCreate) {
            return "create";
        }
        if (hasDelete) {
            return "destroy";
        }
        if (hasUpdate) {
            return "update";
        }
        return "no-op";
    }

    private String moduleName(String address) {
        if (address == null || address.isBlank()) {
            return null;
        }
        int moduleIndex = address.indexOf("module.");
        if (moduleIndex < 0) {
            return null;
        }
        int lastDot = address.lastIndexOf('.');
        if (lastDot <= moduleIndex) {
            return null;
        }
        return address.substring(moduleIndex + 7, lastDot);
    }
}
