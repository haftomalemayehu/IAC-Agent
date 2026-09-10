package com.iacagent.iacagent;

import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.util.Optional;

public final class GitHubReviewCommentManager {
    private static final ObjectMapper MAPPER = new ObjectMapper();
    public static final String COMMENT_MARKER = "<!-- terraform-review -->";

    private GitHubReviewCommentManager() {
    }

    public static String findExistingCommentId(String responseJson) throws IOException {
        JsonNode comments = MAPPER.readTree(responseJson);
        if (comments == null || !comments.isArray()) {
            return null;
        }
        for (JsonNode comment : comments) {
            JsonNode body = comment.path("body");
            if (body != null && body.isTextual() && body.asText().contains(COMMENT_MARKER)) {
                JsonNode idNode = comment.path("id");
                if (idNode != null && !idNode.isMissingNode()) {
                    return String.valueOf(idNode.asLong());
                }
            }
        }
        return null;
    }

    public static String nextAction(String responseJson) {
        try {
            String existing = findExistingCommentId(responseJson);
            return existing == null ? "create" : "update";
        } catch (IOException e) {
            return "create";
        }
    }
}
