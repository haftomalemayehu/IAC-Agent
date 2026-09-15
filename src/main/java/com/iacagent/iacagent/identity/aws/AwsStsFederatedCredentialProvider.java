package com.iacagent.iacagent.identity.aws;

import com.iacagent.iacagent.identity.FederatedCredentialMaterial;
import com.iacagent.iacagent.identity.FederatedCredentialProvider;
import com.iacagent.iacagent.identity.TerraformCredentialProfile;
import com.iacagent.iacagent.identity.VerifiedWorkloadIdentity;
import com.iacagent.iacagent.identity.WorkloadIdentityFederationException;
import com.iacagent.iacagent.runner.RunnerReasonCode;
import software.amazon.awssdk.auth.credentials.AnonymousCredentialsProvider;
import software.amazon.awssdk.core.client.config.ClientOverrideConfiguration;
import software.amazon.awssdk.core.exception.SdkException;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.sts.StsClient;
import software.amazon.awssdk.services.sts.model.AssumeRoleWithWebIdentityRequest;
import software.amazon.awssdk.services.sts.model.AssumeRoleWithWebIdentityResponse;
import software.amazon.awssdk.services.sts.model.Credentials;

import java.time.Duration;
import java.time.Instant;
import java.util.Map;

/**
 * Real production {@link FederatedCredentialProvider}: AWS STS {@code AssumeRoleWithWebIdentity},
 * the standard OIDC-to-AWS federation call - never any other AWS API. The role ARN is resolved
 * exclusively via {@link TrustedCloudRoleResolver#resolve} - this class never accepts a caller-
 * supplied role ARN, session policy, external ID, duration, or STS endpoint override; the ONLY
 * caller-influenced STS request field is the presented {@code rawToken} itself (which AWS
 * independently verifies against its own configured OIDC provider trust policy).
 *
 * <p><b>No ambient AWS credentials.</b> The underlying {@link StsClient} is built with
 * {@link AnonymousCredentialsProvider} - {@code AssumeRoleWithWebIdentity} is, by AWS's own design,
 * an unauthenticated STS API authenticated instead by the presented web identity token, so this
 * class never touches {@code ~/.aws/credentials}, an EC2 instance profile, an ECS task role, or any
 * other ambient credential source the SDK's default provider chain would otherwise consult.
 *
 * <p>Session duration and the minimum acceptable remaining credential lifetime are both trusted,
 * control-plane-configured bounds - never derived from the request.
 */
public final class AwsStsFederatedCredentialProvider implements FederatedCredentialProvider {

    private final TrustedCloudRoleResolver roleResolver;
    private final StsClient stsClient;
    private final int requestedSessionDurationSeconds;
    private final Duration minimumRemainingLifetime;

    public AwsStsFederatedCredentialProvider(
            TrustedCloudRoleResolver roleResolver, String awsRegion, Duration requestedSessionDuration,
            Duration minimumRemainingLifetime, Duration apiCallTimeout) {
        if (roleResolver == null) {
            throw new IllegalArgumentException("roleResolver is required");
        }
        if (awsRegion == null || awsRegion.isBlank()) {
            throw new IllegalArgumentException("awsRegion is required");
        }
        if (requestedSessionDuration == null || requestedSessionDuration.toSeconds() < 900 || requestedSessionDuration.toSeconds() > 43_200) {
            throw new IllegalArgumentException("requestedSessionDuration must be between 15 minutes and 12 hours");
        }
        if (minimumRemainingLifetime == null || minimumRemainingLifetime.isNegative() || minimumRemainingLifetime.compareTo(requestedSessionDuration) >= 0) {
            throw new IllegalArgumentException("minimumRemainingLifetime must be positive and less than requestedSessionDuration");
        }
        if (apiCallTimeout == null || apiCallTimeout.isNegative() || apiCallTimeout.isZero()) {
            throw new IllegalArgumentException("apiCallTimeout must be positive");
        }
        this.roleResolver = roleResolver;
        this.requestedSessionDurationSeconds = (int) requestedSessionDuration.toSeconds();
        this.minimumRemainingLifetime = minimumRemainingLifetime;
        this.stsClient = StsClient.builder()
                .region(Region.of(awsRegion))
                .credentialsProvider(AnonymousCredentialsProvider.create())
                .overrideConfiguration(ClientOverrideConfiguration.builder().apiCallTimeout(apiCallTimeout).build())
                .build();
    }

    /** Test-only seam: substitutes the real {@link StsClient} with a mock/fake - never used by the
     * production constructor above, which always builds a real, anonymously-authenticated client
     * against a real AWS region. */
    AwsStsFederatedCredentialProvider(TrustedCloudRoleResolver roleResolver, StsClient stsClient, Duration requestedSessionDuration, Duration minimumRemainingLifetime) {
        if (roleResolver == null) {
            throw new IllegalArgumentException("roleResolver is required");
        }
        if (stsClient == null) {
            throw new IllegalArgumentException("stsClient is required");
        }
        this.roleResolver = roleResolver;
        this.stsClient = stsClient;
        this.requestedSessionDurationSeconds = (int) requestedSessionDuration.toSeconds();
        this.minimumRemainingLifetime = minimumRemainingLifetime;
    }

    @Override
    public FederatedCredentialMaterial federate(
            String rawToken, VerifiedWorkloadIdentity identity, String repository, String environment, TerraformCredentialProfile profile) {
        if (rawToken == null || rawToken.isBlank()) {
            throw new WorkloadIdentityFederationException(RunnerReasonCode.CREDENTIAL_FEDERATION_FAILED, "no token available to present to AWS STS");
        }
        CloudRoleResolution resolution = roleResolver.resolve(repository, environment, identity, profile);
        if (!resolution.authorized()) {
            throw new WorkloadIdentityFederationException(
                    RunnerReasonCode.CLOUD_ROLE_NOT_AUTHORIZED, "no trusted AWS role is configured for " + repository + "/" + environment);
        }

        AssumeRoleWithWebIdentityRequest request = AssumeRoleWithWebIdentityRequest.builder()
                .roleArn(resolution.roleArn())
                .roleSessionName(sessionName(identity, profile))
                .webIdentityToken(rawToken)
                .durationSeconds(requestedSessionDurationSeconds)
                .build();

        AssumeRoleWithWebIdentityResponse response;
        try {
            response = stsClient.assumeRoleWithWebIdentity(request);
        } catch (SdkException e) {
            // e's own message may echo request details (never the token itself, which the SDK does
            // not echo back) - safe to attach as a cause for local diagnostics, but callers must
            // never persist getCause() into evidence, only reasonCode()/getMessage().
            throw new WorkloadIdentityFederationException(
                    RunnerReasonCode.CREDENTIAL_FEDERATION_FAILED, "AWS STS AssumeRoleWithWebIdentity failed", (Throwable) e);
        }

        Credentials credentials = response.credentials();
        Instant expiresAt = credentials.expiration();
        if (expiresAt == null || Duration.between(Instant.now(), expiresAt).compareTo(minimumRemainingLifetime) < 0) {
            throw new WorkloadIdentityFederationException(
                    RunnerReasonCode.CREDENTIAL_LIFETIME_INSUFFICIENT,
                    "federated AWS credentials do not meet the configured minimum remaining lifetime");
        }

        Map<String, String> environmentVariables = Map.of(
                "AWS_ACCESS_KEY_ID", credentials.accessKeyId(),
                "AWS_SECRET_ACCESS_KEY", credentials.secretAccessKey(),
                "AWS_SESSION_TOKEN", credentials.sessionToken());
        return new FederatedCredentialMaterial(environmentVariables, resolution.roleArn(), expiresAt);
    }

    /** A deterministic, non-secret AWS role session name - AWS constrains this to
     * {@code [\w+=,.@-]{2,64}}, so this is built entirely from already-non-secret, already-
     * length-bounded identity fields (never the raw subject, never any credential value). */
    private static String sessionName(VerifiedWorkloadIdentity identity, TerraformCredentialProfile profile) {
        String prefix = "iac-agent-" + profile.name().toLowerCase(java.util.Locale.ROOT) + "-";
        String suffix = identity.subjectSha256().substring(0, Math.min(40, identity.subjectSha256().length()));
        return prefix + suffix;
    }
}
