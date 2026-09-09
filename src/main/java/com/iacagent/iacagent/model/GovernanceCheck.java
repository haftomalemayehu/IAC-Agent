package com.iacagent.iacagent.model;

public record GovernanceCheck(String name, String description, boolean passed, String severity) {
}
