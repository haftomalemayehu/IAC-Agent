package com.iacagent.iacagent.model;

import java.util.List;

public record TerraformExecutionResult(String executionId, String planId, String status, String message, List<String> steps, String executedAt) {
}
