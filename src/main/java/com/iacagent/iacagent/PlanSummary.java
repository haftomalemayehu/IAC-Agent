package com.iacagent.iacagent;

import java.util.List;

public record PlanSummary(
        int create,
        int update,
        int replace,
        int destroy,
        int noOp,
        List<ResourceChange> changes
) {
}
