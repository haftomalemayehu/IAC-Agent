package com.iacagent.iacagent;

public final class GitHubPrCommentRenderer {
    private GitHubPrCommentRenderer() {
    }

    public static String render(PullRequestReview review) {
        return review.markdown();
    }

    public static String renderUpdate(String existingComment, PullRequestReview review) {
        if (existingComment == null || existingComment.isBlank()) {
            return render(review);
        }
        return render(review);
    }
}
