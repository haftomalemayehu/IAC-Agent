package com.iacagent.iacagent;

public record ResourceChange(
        String action,
        String resourceType,
        String resourceName,
        String module,
        String before,
        String after
) {
}
