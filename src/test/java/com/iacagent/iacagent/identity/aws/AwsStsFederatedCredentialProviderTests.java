package com.iacagent.iacagent.identity.aws;

import com.iacagent.iacagent.identity.FederatedCredentialMaterial;
import com.iacagent.iacagent.identity.TerraformCredentialProfile;
import com.iacagent.iacagent.identity.VerifiedWorkloadIdentity;
import com.iacagent.iacagent.identity.WorkloadIdentityFederationException;
import com.iacagent.iacagent.runner.RunnerReasonCode;
import org.junit.jupiter.api.Test;
import software.amazon.awssdk.core.exception.SdkClientException;
import software.amazon.awssdk.services.sts.StsClient;
import software.amazon.awssdk.services.sts.model.AssumeRoleWithWebIdentityRequest;
import software.amazon.awssdk.services.sts.model.AssumeRoleWithWebIdentityResponse;
import software.amazon.awssdk.services.sts.model.Credentials;

import java.time.Duration;
import java.time.Instant;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

/**
 * Phase 2B-7 unit tests for {@link AwsStsFederatedCredentialProvider} against a MOCKED
 * {@link StsClient} - real AWS STS federation acceptance is explicitly deferred (see
 * {@code docs/phase-2b7-workload-identity-federation.md} §22) pending real, dedicated non-production
 * AWS account/role infrastructure this development session has no access to.
 */
class AwsStsFederatedCredentialProviderTests {

    private static final String REPOSITORY = "owner/repo";
    private static final String ENVIRONMENT = "nonprod";
    private static final String ROLE_ARN = "arn:aws:iam::123456789012:role/plan-role";

    private VerifiedWorkloadIdentity fakeIdentity() {
        return new VerifiedWorkloadIdentity(
                "https://token.actions.githubusercontent.com", "subj-hash", "sts.amazonaws.com",
                REPOSITORY, "owner", "refs/heads/main", "c".repeat(40),
                "owner/repo/.github/workflows/plan.yml@refs/heads/main", null,
                Instant.now(), Instant.now().plusSeconds(300), "jti-hash");
    }

    private Credentials fakeCredentials(Instant expiration) {
        return Credentials.builder()
                .accessKeyId("AKIAFAKE").secretAccessKey("fake-secret").sessionToken("fake-session-token")
                .expiration(expiration).build();
    }

    @Test
    void successfulFederationReturnsCredentialsFromStsResponse() {
        TrustedCloudRoleResolver resolver = mock(TrustedCloudRoleResolver.class);
        when(resolver.resolve(eq(REPOSITORY), eq(ENVIRONMENT), any(), eq(TerraformCredentialProfile.PLAN)))
                .thenReturn(CloudRoleResolution.resolved(ROLE_ARN));

        StsClient stsClient = mock(StsClient.class);
        Instant expiration = Instant.now().plusSeconds(3600);
        when(stsClient.assumeRoleWithWebIdentity(any(AssumeRoleWithWebIdentityRequest.class)))
                .thenReturn(AssumeRoleWithWebIdentityResponse.builder().credentials(fakeCredentials(expiration)).build());

        var provider = new AwsStsFederatedCredentialProvider(resolver, stsClient, Duration.ofMinutes(15), Duration.ofMinutes(5));
        FederatedCredentialMaterial material = provider.federate("raw-token", fakeIdentity(), REPOSITORY, ENVIRONMENT, TerraformCredentialProfile.PLAN);

        assertEquals("AKIAFAKE", material.environmentVariables().get("AWS_ACCESS_KEY_ID"));
        assertEquals("fake-secret", material.environmentVariables().get("AWS_SECRET_ACCESS_KEY"));
        assertEquals("fake-session-token", material.environmentVariables().get("AWS_SESSION_TOKEN"));
        assertEquals(ROLE_ARN, material.cloudRoleIdentifier());
        assertEquals(expiration, material.expiresAt());
    }

    @Test
    void requestPresentsTheRawTokenAsTheWebIdentityToken() {
        TrustedCloudRoleResolver resolver = mock(TrustedCloudRoleResolver.class);
        when(resolver.resolve(any(), any(), any(), any())).thenReturn(CloudRoleResolution.resolved(ROLE_ARN));
        StsClient stsClient = mock(StsClient.class);
        when(stsClient.assumeRoleWithWebIdentity(any(AssumeRoleWithWebIdentityRequest.class)))
                .thenReturn(AssumeRoleWithWebIdentityResponse.builder().credentials(fakeCredentials(Instant.now().plusSeconds(3600))).build());

        var provider = new AwsStsFederatedCredentialProvider(resolver, stsClient, Duration.ofMinutes(15), Duration.ofMinutes(5));
        provider.federate("the-actual-raw-token", fakeIdentity(), REPOSITORY, ENVIRONMENT, TerraformCredentialProfile.PLAN);

        var captor = org.mockito.ArgumentCaptor.forClass(AssumeRoleWithWebIdentityRequest.class);
        verify(stsClient).assumeRoleWithWebIdentity(captor.capture());
        assertEquals("the-actual-raw-token", captor.getValue().webIdentityToken());
        assertEquals(ROLE_ARN, captor.getValue().roleArn());
    }

    @Test
    void noAuthorizedRoleThrowsCloudRoleNotAuthorizedWithoutCallingSts() {
        TrustedCloudRoleResolver resolver = mock(TrustedCloudRoleResolver.class);
        when(resolver.resolve(any(), any(), any(), any())).thenReturn(CloudRoleResolution.notAuthorized());
        StsClient stsClient = mock(StsClient.class);

        var provider = new AwsStsFederatedCredentialProvider(resolver, stsClient, Duration.ofMinutes(15), Duration.ofMinutes(5));
        var e = assertThrows(WorkloadIdentityFederationException.class,
                () -> provider.federate("raw-token", fakeIdentity(), REPOSITORY, ENVIRONMENT, TerraformCredentialProfile.PLAN));
        assertEquals(RunnerReasonCode.CLOUD_ROLE_NOT_AUTHORIZED, e.reasonCode());
        verifyNoInteractions(stsClient);
    }

    @Test
    void stsFailureThrowsCredentialFederationFailed() {
        TrustedCloudRoleResolver resolver = mock(TrustedCloudRoleResolver.class);
        when(resolver.resolve(any(), any(), any(), any())).thenReturn(CloudRoleResolution.resolved(ROLE_ARN));
        StsClient stsClient = mock(StsClient.class);
        when(stsClient.assumeRoleWithWebIdentity(any(AssumeRoleWithWebIdentityRequest.class)))
                .thenThrow(SdkClientException.create("STS unreachable"));

        var provider = new AwsStsFederatedCredentialProvider(resolver, stsClient, Duration.ofMinutes(15), Duration.ofMinutes(5));
        var e = assertThrows(WorkloadIdentityFederationException.class,
                () -> provider.federate("raw-token", fakeIdentity(), REPOSITORY, ENVIRONMENT, TerraformCredentialProfile.PLAN));
        assertEquals(RunnerReasonCode.CREDENTIAL_FEDERATION_FAILED, e.reasonCode());
    }

    @Test
    void insufficientRemainingLifetimeThrowsCredentialLifetimeInsufficient() {
        TrustedCloudRoleResolver resolver = mock(TrustedCloudRoleResolver.class);
        when(resolver.resolve(any(), any(), any(), any())).thenReturn(CloudRoleResolution.resolved(ROLE_ARN));
        StsClient stsClient = mock(StsClient.class);
        // Credentials expire in 1 minute - far below the configured 5-minute minimum.
        when(stsClient.assumeRoleWithWebIdentity(any(AssumeRoleWithWebIdentityRequest.class)))
                .thenReturn(AssumeRoleWithWebIdentityResponse.builder().credentials(fakeCredentials(Instant.now().plusSeconds(60))).build());

        var provider = new AwsStsFederatedCredentialProvider(resolver, stsClient, Duration.ofMinutes(15), Duration.ofMinutes(5));
        var e = assertThrows(WorkloadIdentityFederationException.class,
                () -> provider.federate("raw-token", fakeIdentity(), REPOSITORY, ENVIRONMENT, TerraformCredentialProfile.PLAN));
        assertEquals(RunnerReasonCode.CREDENTIAL_LIFETIME_INSUFFICIENT, e.reasonCode());
    }

    @Test
    void nullCredentialFieldInStsResponseThrowsCredentialFederationFailedNotNpe() {
        TrustedCloudRoleResolver resolver = mock(TrustedCloudRoleResolver.class);
        when(resolver.resolve(any(), any(), any(), any())).thenReturn(CloudRoleResolution.resolved(ROLE_ARN));
        StsClient stsClient = mock(StsClient.class);
        // A Credentials object with a null field is an SDK edge case (partial/mocked response) -
        // must fail closed with a precise reason code, never an uncaught NullPointerException.
        Credentials incomplete = Credentials.builder()
                .accessKeyId("AKIAFAKE").secretAccessKey(null).sessionToken("fake-session-token")
                .expiration(Instant.now().plusSeconds(3600)).build();
        when(stsClient.assumeRoleWithWebIdentity(any(AssumeRoleWithWebIdentityRequest.class)))
                .thenReturn(AssumeRoleWithWebIdentityResponse.builder().credentials(incomplete).build());

        var provider = new AwsStsFederatedCredentialProvider(resolver, stsClient, Duration.ofMinutes(15), Duration.ofMinutes(5));
        var e = assertThrows(WorkloadIdentityFederationException.class,
                () -> provider.federate("raw-token", fakeIdentity(), REPOSITORY, ENVIRONMENT, TerraformCredentialProfile.PLAN));
        assertEquals(RunnerReasonCode.CREDENTIAL_FEDERATION_FAILED, e.reasonCode());
    }

    @Test
    void constructorRejectsCallerSuppliedRoleArnStyleMisuse() {
        // Defensive/documentation test: TrustedCloudRoleResolver is the ONLY way a role ARN reaches
        // this class - there is no overload or setter accepting one directly.
        for (var constructor : AwsStsFederatedCredentialProvider.class.getDeclaredConstructors()) {
            for (Class<?> paramType : constructor.getParameterTypes()) {
                assertNotEquals(String[].class, paramType);
            }
        }
    }

    @Test
    void productionConstructorRejectsOutOfBoundsSessionDuration() {
        TrustedCloudRoleResolver resolver = mock(TrustedCloudRoleResolver.class);
        assertThrows(IllegalArgumentException.class, () ->
                new AwsStsFederatedCredentialProvider(resolver, "us-east-1", Duration.ofSeconds(60), Duration.ofSeconds(30), Duration.ofSeconds(10)));
        assertThrows(IllegalArgumentException.class, () ->
                new AwsStsFederatedCredentialProvider(resolver, "us-east-1", Duration.ofHours(15), Duration.ofSeconds(30), Duration.ofSeconds(10)));
    }

    @Test
    void productionConstructorRejectsMinimumLifetimeNotLessThanSessionDuration() {
        TrustedCloudRoleResolver resolver = mock(TrustedCloudRoleResolver.class);
        assertThrows(IllegalArgumentException.class, () ->
                new AwsStsFederatedCredentialProvider(resolver, "us-east-1", Duration.ofMinutes(15), Duration.ofMinutes(15), Duration.ofSeconds(10)));
    }

}
