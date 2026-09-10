package com.iacagent.iacagent.approval;

import java.time.Duration;

/**
 * Determines how long a freshly issued approval remains valid, so {@code expiresAt} is derived
 * from policy rather than accepted as an arbitrary caller-supplied timestamp. Environment is
 * passed in so a future policy can grant shorter TTLs to more sensitive environments without
 * changing this interface.
 */
@FunctionalInterface
public interface ApprovalTtlPolicy {
    Duration ttlFor(String environment);

    static ApprovalTtlPolicy fixed(Duration ttl) {
        if (ttl == null || ttl.isZero() || ttl.isNegative()) {
            throw new IllegalArgumentException("ttl must be a positive duration");
        }
        return environment -> ttl;
    }
}
