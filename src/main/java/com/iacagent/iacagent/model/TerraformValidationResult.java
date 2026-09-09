package com.iacagent.iacagent.model;

import java.util.List;

public record TerraformValidationResult(boolean valid, List<String> findings, List<GovernanceCheck> checks, String riskLevel) {
}
