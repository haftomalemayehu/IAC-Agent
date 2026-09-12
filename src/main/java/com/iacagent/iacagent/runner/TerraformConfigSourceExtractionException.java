package com.iacagent.iacagent.runner;

/**
 * Thrown by {@link TerraformConfigSourceExtractor}/{@link TerraformNativeSourceExtractor}/
 * {@link TerraformJsonSourceExtractor} whenever a provider or module {@code source} declaration
 * cannot be deterministically understood - malformed syntax, an unterminated string/heredoc, a
 * {@code source} value that is not an immediate string literal (a reference, interpolation, or
 * function call), or an unrecognized/ambiguous configuration shape that would otherwise make source
 * policy enforcement incomplete. {@link ControlledTerraformOperationCoordinator#executeInit} treats
 * this as a hard, fail-closed block ({@link RunnerReasonCode#TERRAFORM_SOURCE_EXTRACTION_FAILED}) -
 * {@code terraform init} is never launched when this is thrown, exactly as for a recognized-but-
 * disallowed source.
 */
final class TerraformConfigSourceExtractionException extends RuntimeException {
    TerraformConfigSourceExtractionException(String message) {
        super(message);
    }
}
