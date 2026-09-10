package com.iacagent.iacagent.model;

public record TerraformChange(String action, String resourceType, String resourceName, String module, String before, String after) {
}
