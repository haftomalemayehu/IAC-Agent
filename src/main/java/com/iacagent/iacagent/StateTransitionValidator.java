package com.iacagent.iacagent;

import java.util.EnumMap;
import java.util.EnumSet;
import java.util.Map;
import java.util.Set;

public final class StateTransitionValidator {
    private static final Map<ExecutionState, Set<ExecutionState>> ALLOWED = new EnumMap<>(ExecutionState.class);

    static {
        ALLOWED.put(ExecutionState.RECEIVED, EnumSet.of(ExecutionState.DISCOVERING));
        ALLOWED.put(ExecutionState.DISCOVERING, EnumSet.of(ExecutionState.DESIGNING, ExecutionState.FAILED, ExecutionState.REJECTED));
        ALLOWED.put(ExecutionState.DESIGNING, EnumSet.of(ExecutionState.VERIFYING_SCHEMA, ExecutionState.FAILED, ExecutionState.REJECTED));
        ALLOWED.put(ExecutionState.VERIFYING_SCHEMA, EnumSet.of(ExecutionState.AUTHORING, ExecutionState.REJECTED));
        ALLOWED.put(ExecutionState.AUTHORING, EnumSet.of(ExecutionState.FORMATTING, ExecutionState.REJECTED));
        ALLOWED.put(ExecutionState.FORMATTING, EnumSet.of(ExecutionState.VALIDATING, ExecutionState.REJECTED));
        ALLOWED.put(ExecutionState.VALIDATING, EnumSet.of(ExecutionState.LINTING, ExecutionState.REPAIRING, ExecutionState.FAILED));
        ALLOWED.put(ExecutionState.LINTING, EnumSet.of(ExecutionState.SECURITY_SCANNING, ExecutionState.REJECTED));
        ALLOWED.put(ExecutionState.SECURITY_SCANNING, EnumSet.of(ExecutionState.POLICY_CHECKING, ExecutionState.REJECTED));
        ALLOWED.put(ExecutionState.POLICY_CHECKING, EnumSet.of(ExecutionState.TESTING, ExecutionState.REJECTED));
        ALLOWED.put(ExecutionState.TESTING, EnumSet.of(ExecutionState.PLANNING, ExecutionState.REJECTED));
        ALLOWED.put(ExecutionState.PLANNING, EnumSet.of(ExecutionState.ANALYZING_PLAN, ExecutionState.REJECTED));
        ALLOWED.put(ExecutionState.ANALYZING_PLAN, EnumSet.of(ExecutionState.ANALYZING_COST, ExecutionState.RISK_REVIEW, ExecutionState.REJECTED));
        ALLOWED.put(ExecutionState.ANALYZING_COST, EnumSet.of(ExecutionState.RISK_REVIEW, ExecutionState.REJECTED));
        ALLOWED.put(ExecutionState.RISK_REVIEW, EnumSet.of(ExecutionState.READY_FOR_REVIEW, ExecutionState.REJECTED));
        ALLOWED.put(ExecutionState.READY_FOR_REVIEW, EnumSet.of(ExecutionState.WAITING_FOR_APPROVAL, ExecutionState.REJECTED));
        ALLOWED.put(ExecutionState.WAITING_FOR_APPROVAL, EnumSet.of(ExecutionState.APPLYING, ExecutionState.REJECTED));
        ALLOWED.put(ExecutionState.APPLYING, EnumSet.of(ExecutionState.VERIFYING_DEPLOYMENT, ExecutionState.REJECTED));
        ALLOWED.put(ExecutionState.VERIFYING_DEPLOYMENT, EnumSet.of(ExecutionState.COMPLETED, ExecutionState.FAILED));
        ALLOWED.put(ExecutionState.FAILED, EnumSet.noneOf(ExecutionState.class));
        ALLOWED.put(ExecutionState.REJECTED, EnumSet.noneOf(ExecutionState.class));
        ALLOWED.put(ExecutionState.COMPLETED, EnumSet.noneOf(ExecutionState.class));
    }

    public static boolean isValidTransition(ExecutionState from, ExecutionState to) {
        if (from == null || to == null) {
            return false;
        }
        return ALLOWED.getOrDefault(from, EnumSet.noneOf(ExecutionState.class)).contains(to);
    }
}
