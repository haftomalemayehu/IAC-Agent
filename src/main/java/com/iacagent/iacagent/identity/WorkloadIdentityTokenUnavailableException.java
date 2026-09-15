package com.iacagent.iacagent.identity;

/** Thrown by {@link WorkloadIdentityTokenSource#currentToken} when no token could be obtained -
 * ambient endpoint missing/unreachable, malformed response, etc. Never carries the token value
 * (there isn't one) and never carries any bearer/authorization header value from the failed
 * attempt. */
public final class WorkloadIdentityTokenUnavailableException extends RuntimeException {
    public WorkloadIdentityTokenUnavailableException(String message) {
        super(message);
    }

    public WorkloadIdentityTokenUnavailableException(String message, Throwable cause) {
        super(message, cause);
    }
}
