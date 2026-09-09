package com.iacagent.iacagent;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.List;

public class ApprovalEngine {
    public String hashPlan(Path planPath) throws IOException, NoSuchAlgorithmException {
        byte[] bytes = Files.readAllBytes(planPath);
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(bytes);
        StringBuilder hex = new StringBuilder();
        for (byte b : hash) {
            hex.append(String.format("%02x", b));
        }
        return "sha256:" + hex;
    }

    public ApprovalBinding bindApproval(String requestId, String environment, String planHash, String approvedBy, String reason) {
        return new ApprovalBinding(requestId, environment, planHash, approvedBy, Instant.now().toString(), reason, List.of(reason));
    }

    public boolean isPlanHashValid(String approvedPlanHash, String currentPlanHash) {
        return approvedPlanHash != null && approvedPlanHash.equals(currentPlanHash);
    }

    public record ApprovalBinding(
            String requestId,
            String environment,
            String planHash,
            String approvedBy,
            String approvedAt,
            String reason,
            List<String> reasons
    ) {
    }
}
