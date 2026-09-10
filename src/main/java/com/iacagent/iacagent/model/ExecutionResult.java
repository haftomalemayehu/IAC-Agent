package com.iacagent.iacagent.model;

import java.util.List;

public record ExecutionResult(String executionId, String planId, String status, String message, List<String> steps, String executedAt) {
}
