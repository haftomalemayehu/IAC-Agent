package com.iacagent.iacagent.runner;

/**
 * Deterministic failure reasons. There is no generic "ERROR" value - every BLOCKED/FAILED outcome
 * this package produces carries one of these, never a bare exception message surfaced as if it
 * were the reason.
 */
public enum RunnerReasonCode {
    RUNNER_IDENTITY_UNTRUSTED,
    RUNNER_ENVIRONMENT_NOT_ALLOWED,
    APPROVAL_NOT_FOUND,
    APPROVAL_INVALID,
    APPROVAL_EXPIRED,
    APPROVAL_REVOKED,
    APPROVAL_SUPERSEDED,
    REPOSITORY_MISMATCH,
    COMMIT_SHA_MISMATCH,
    ENVIRONMENT_MISMATCH,
    PLAN_HASH_MISMATCH,
    ARTIFACT_NOT_FOUND,
    ARTIFACT_HASH_MISMATCH,
    /** Reused for two related but distinct checks: (pre-2B-3) the request's claimed
     * {@code terraformVersion} vs. {@link RunnerToolchainContext#observedTerraformVersion()}, and
     * (Phase 2B-3) the {@code TERRAFORM_VERSION} operation's binary-reported version vs. the
     * trusted executable's configured expected version - a binary whose SHA-256 is trusted but
     * whose reported version is unexpected still blocks. Both represent the same underlying
     * concern ("the Terraform version in play is not the one we expect"), just sourced differently. */
    TERRAFORM_VERSION_MISMATCH,
    PROVIDER_LOCK_HASH_MISMATCH,
    /** The requested operation cannot proceed as asked - operation authorization only. Never used
     * for request-id replay/collision; see {@link #DUPLICATE_RUNNER_REQUEST} and
     * {@link #RUNNER_REQUEST_FINGERPRINT_MISMATCH} for those. */
    OPERATION_NOT_ALLOWED,
    DURABLE_APPROVAL_STORE_UNAVAILABLE,
    /** A {@code runnerRequestId} was resubmitted with byte-for-byte identical request content.
     * The original evidence remains the authoritative historical record; this resubmission is
     * blocked rather than re-executed or replayed, because authorization state (approval validity,
     * expiry) can have changed since the original submission - see {@link ControlledRunner}. */
    DUPLICATE_RUNNER_REQUEST,
    /** A {@code runnerRequestId} was resubmitted with request content that differs from the
     * original submission under that same id - the same id must never represent two different
     * execution contexts. */
    RUNNER_REQUEST_FINGERPRINT_MISMATCH,
    /** The durable {@link RunnerLedgerRepository} could not be reached or threw an infrastructure
     * failure. Never converted into any other outcome - "ledger unavailable" always blocks. */
    RUNNER_LEDGER_UNAVAILABLE,
    /** A ledger row exists for this {@code runnerRequestId} in {@link RunnerClaimState#CLAIMED}
     * (never reached {@code COMPLETED}) with the same fingerprint - either a concurrent claim is
     * genuinely in progress right now, or a prior process crashed after claiming but before
     * recording terminal evidence. Both look identical in persisted state and get this same,
     * conservative response; retrying the same id automatically is never attempted. */
    RUNNER_REQUEST_INCOMPLETE,
    /** {@link RunnerIdentityProvider#currentIdentity()} returned no identity at all (host
     * attestation source missing, unreadable, or malformed) - distinct from
     * {@link #RUNNER_IDENTITY_UNTRUSTED}, which means an identity WAS resolved but is marked
     * untrusted. */
    RUNNER_IDENTITY_UNAVAILABLE,
    /** The resolved runner identity's {@code runnerClass} is not in this ControlledRunner
     * instance's configured allowlist for the requested operation. */
    RUNNER_CLASS_NOT_ALLOWED,
    /** Workspace creation or isolation verification failed (e.g. the computed path did not stay
     * under the configured root, or a filesystem error occurred while staging). */
    WORKSPACE_ISOLATION_FAILURE,
    /** Artifact staging into the workspace failed for a reason other than a hash mismatch (already
     * covered by {@link #ARTIFACT_HASH_MISMATCH}) - e.g. an I/O failure while writing the staged
     * file. */
    ARTIFACT_STAGING_FAILURE,

    // ---- Phase 2B-3: controlled Terraform process boundary ----

    /** {@link TerraformExecutableProvider#resolve()} found no file at all at the configured
     * executable path (missing, or an ancestor component is unresolvable). */
    TERRAFORM_EXECUTABLE_NOT_FOUND,
    /** The configured executable path failed a path-safety check - resolved outside the trusted
     * tool root, resolved inside a configured untrusted root, or the leaf path itself is a symlink.
     * Distinct from {@link #TERRAFORM_EXECUTABLE_NOT_EXECUTABLE}, which means the path IS safely
     * inside the trusted root but is not a runnable regular file. */
    TERRAFORM_EXECUTABLE_UNTRUSTED,
    /** The path-safety-verified executable's recomputed SHA-256 does not match the runner's
     * configured expected value. Never executed once this is detected. */
    TERRAFORM_EXECUTABLE_HASH_MISMATCH,
    /** The path-safety-verified executable exists but is not a regular, executable file (e.g. a
     * directory, or missing the executable permission bit). */
    TERRAFORM_EXECUTABLE_NOT_EXECUTABLE,
    /** {@code terraform version -json}'s stdout could not be parsed as the expected structured
     * output (missing/malformed {@code terraform_version} field), so no version comparison could
     * even be attempted. */
    TERRAFORM_VERSION_OUTPUT_INVALID,
    /** The OS-level process launch itself failed (e.g. the OS refused to exec the file) - an
     * infrastructure-level failure distinct from the process starting and then failing/timing out. */
    TERRAFORM_PROCESS_START_FAILED,
    /** The Terraform process did not exit within its configured timeout and was terminated
     * (best-effort, including its process tree) rather than awaited indefinitely. */
    TERRAFORM_PROCESS_TIMEOUT,
    /** The Terraform process exited with a code this operation does not treat as a legitimate
     * structured outcome (e.g. a nonzero exit from {@code version -json} or {@code show -json},
     * which - unlike {@code fmt -check} - have no "difference found" interpretation of a nonzero
     * exit code). */
    TERRAFORM_PROCESS_EXIT_FAILED,
    /** stdout or stderr exceeded its configured bound; the process was terminated rather than
     * allowed to accumulate output without limit, and the (necessarily incomplete) captured output
     * is never treated as valid. */
    TERRAFORM_OUTPUT_LIMIT_EXCEEDED,
    /** Captured stdout that was expected to be JSON (e.g. {@code version -json}, {@code show -json})
     * could not be parsed as valid JSON - never partially interpreted. */
    TERRAFORM_OUTPUT_INVALID_JSON,
    /** The computed Terraform process working directory failed isolation/containment verification
     * before launch (not under the trusted workspace root, or a symlink-based escape). */
    TERRAFORM_WORKING_DIRECTORY_UNSAFE,
    /** The staged plan artifact's SHA-256, recomputed immediately before launching
     * {@code terraform show -json} (the final TOCTOU check), no longer matches the hash verified
     * earlier in the pipeline - the process is never launched once this is detected. */
    TERRAFORM_PLAN_HASH_MISMATCH,
    /** The requested {@link RunnerOperation} is not one this coordinator implements a Terraform
     * process for - a defensive, should-never-happen code since {@link ControlledRunner} only
     * dispatches to the Terraform process boundary for the three closed operations that exist. */
    TERRAFORM_OPERATION_NOT_ALLOWED,
    /** {@link RunnerWorkspaceManager#stageTerraformConfigDirectory} found a symlink anywhere in the
     * untrusted source tree (a leaf {@code .tf} file, or a directory entry that would otherwise be
     * descended into), or a file whose real path resolves outside the configured source root - the
     * whole staging attempt is rejected, not just the offending entry. */
    TERRAFORM_CONFIG_SOURCE_UNSAFE,
    /** {@link RunnerWorkspaceManager#stageTerraformConfigDirectory} rejected the source tree because
     * one file's size, or the aggregate size of all staged files, exceeded the configured bound -
     * repository content must not be given an unbounded local resource-exhaustion path via
     * {@code fmt -recursive}. */
    TERRAFORM_CONFIG_SIZE_LIMIT_EXCEEDED
}
