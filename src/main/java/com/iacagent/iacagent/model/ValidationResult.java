package com.iacagent.iacagent.model;

import java.util.List;

public record ValidationResult(boolean valid, List<String> findings, List<GovernanceCheck> checks, String riskLevel) {
}
