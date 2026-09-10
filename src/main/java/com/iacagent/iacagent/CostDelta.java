package com.iacagent.iacagent;

import java.math.BigDecimal;
import java.math.RoundingMode;

public record CostDelta(
        ValidationState status,
        double currentMonthly,
        double proposedMonthly,
        double deltaPercent,
        String message
) {
    public CostDelta {
        if (Double.isNaN(currentMonthly)) {
            currentMonthly = 0d;
        }
        if (Double.isNaN(proposedMonthly)) {
            proposedMonthly = 0d;
        }
        if (Double.isNaN(deltaPercent)) {
            deltaPercent = 0d;
        }
    }

    public double deltaAmount() {
        return proposedMonthly - currentMonthly;
    }

    public static CostDelta fromCurrentAndProposed(double currentMonthly, double proposedMonthly) {
        double delta = proposedMonthly - currentMonthly;
        double percent = currentMonthly <= 0 ? 0d : (delta / currentMonthly) * 100d;
        BigDecimal rounded = BigDecimal.valueOf(percent).setScale(1, RoundingMode.HALF_UP);
        return new CostDelta(ValidationState.PASS, currentMonthly, proposedMonthly, rounded.doubleValue(), "Cost delta computed");
    }

    public static CostDelta blocked(String message) {
        return new CostDelta(ValidationState.BLOCKED, 0d, 0d, 0d, message);
    }

    public static CostDelta notRun(String message) {
        return new CostDelta(ValidationState.NOT_RUN, 0d, 0d, 0d, message);
    }
}
