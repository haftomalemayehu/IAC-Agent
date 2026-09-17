# Phase 2B-7: Production Workload Identity & Credential Federation

**Status:** Implemented (`com.iacagent.iacagent.identity`, `com.iacagent.iacagent.identity.aws`, plus bridging classes in `com.iacagent.iacagent.runner`), local-commit-only ("do not push [main], do not tag, do not start another phase" per the authorization). Review round 1 found 2 blockers + 5 correctness/process defects (see §26); items 2-7 are fixed in this amendment, 441/441 tests green. **Item 1 (production wiring - the feature has zero callers in `src/main`) is confirmed to NOT be 2B-7-specific: nothing in the runner subsystem has been live-wired since Phase 2B-3 deliberately removed the only real execution endpoint. Deliberately left unwired here, documented as a standing characteristic - closing it is its own future, separately-authorized phase, not part of this amendment.** Targets **Gate C only** - real workload identity and credential federation for `TERRAFORM_PLAN`. Does not add, and structurally cannot represent, `APPLY`/`DESTROY`/`IMPORT`/`STATE`/`FORCE_UNLOCK`.

**Terraform capability surface: unchanged.** Exactly seven operations (`TERRAFORM_VERSION`/`TERRAFORM_FMT_CHECK`/`TERRAFORM_SHOW_PLAN_JSON`/`TERRAFORM_INIT`/`TERRAFORM_VALIDATE`/`TERRAFORM_PROVIDERS_SCHEMA`/`TERRAFORM_PLAN`). `ControlledTerraformProcess` remains the sole `ProcessBuilder`-constructing class in `src/main`; there is still no `Runtime.exec` anywhere.

---

## 1. Trust Model

```text
Who is this runner?
       |
cryptographically verified workload identity   <- WorkloadIdentityVerifier
       |
is this identity authorized for this repository/environment?   <- WorkloadAuthorizationPolicy
       |
short-lived federated credentials              <- FederatedCredentialProvider
       |
controlled Terraform PLAN provider/backend reads
```

Three deliberately separate steps, three deliberately separate interfaces:

- **Identity** (`WorkloadIdentityVerifier`) answers "who is executing?" - purely cryptographic: signature, issuer, audience, expiry, required claims. It never consults a repository/environment.
- **Authorization** (`WorkloadAuthorizationPolicy`) answers "may THIS verified identity act for THIS repository/commit/environment?" - a token merely originating from the trusted issuer is never, by itself, sufficient (the authorization docs' own words). This is where repository/commit/environment/owner/workflow binding happens.
- **Federation** (`FederatedCredentialProvider`) answers "which short-lived credentials may an authorized identity obtain?" - resolves a cloud role from trusted configuration only, then exchanges the presented token for temporary credentials.

`FederatedTerraformCredentialProvider` (in `com.iacagent.iacagent.runner`, implementing the existing Phase 2B-5 `TerraformCredentialProvider` interface unchanged) composes exactly these three steps, in exactly this order, for every `TERRAFORM_PLAN` credential request. `GitHubOidcRunnerIdentityProvider` (implementing the existing Phase 2B-2 `RunnerIdentityProvider` interface unchanged) uses only the identity step, for the coarser-grained "is the ambient workload identity real, current, and trusted at all" gate every operation already passes through.

## 2. Verified Workload Identity

`VerifiedWorkloadIdentity` is constructible ONLY by `WorkloadIdentityVerifier#verify` - there is no public constructor path a caller could use to fabricate one. Fields: `issuer`, `subjectSha256` (a hash of `sub`, never the raw claim), `audience`, `repository`, `repositoryOwner`, `ref`, `commitSha`, `workflowRef`, `environment` (nullable - many workflows never use GitHub's optional Environments feature), `issuedAt`, `expiresAt`, `tokenIdSha256` (a hash of `jti`, nullable if the issuer omits one). `RunnerRequest` fields may be COMPARED against these (see §4) but never used to construct one - `Phase2b7Tests#runnerRequestCarriesNoIdentityFederationSecurityRelevantField` proves `RunnerRequest` carries no issuer/JWKS-URL/role-ARN/credential/token/audience field at all.

## 3. JWT/JWKS Verification (`GitHubActionsOidcVerifier`)

Real production verifier for GitHub Actions' actual OIDC token format (issuer `https://token.actions.githubusercontent.com`) - not an invented generic shape. Uses `com.auth0:java-jwt:4.5.0` (signature verification, pinned) and `com.auth0:jwks-rsa:0.22.2` (JWKS caching/kid lookup, pinned) - no hand-rolled RSA/ECDSA primitive anywhere in this codebase.

Verification order, each step deterministic and independently reason-coded (never inferred from a library exception type beyond the initial "the header didn't even parse" / "the signature didn't verify" cases):

1. **Algorithm allowlist** - the header's `alg` is checked against `WorkloadIdentityVerifierConfig#allowedAlgorithms()` (fixed to `{"RS256"}` for GitHub) BEFORE any key lookup or verification attempt. `alg=none` and every algorithm outside the allowlist are rejected here, unconditionally - `Phase2b7Tests#unsupportedAlgorithmIsRejectedBeforeAnyKeyLookup` proves the key provider is never even called in this case.
2. **Signature** - the key is resolved via `kid` through the trusted JWKS provider (§4, never a key/URL the token itself supplies), then `com.auth0.jwt`'s `Algorithm.RSA256(publicKey, null)` verifies the signature. java-jwt's default verifier also enforces `exp`/`nbf`/`iat` internally even with no claim constraints added - these are explicitly neutralized here (`acceptExpiresAt`/`acceptNotBefore`/`acceptIssuedAt` with a ~100-year leeway) so this step is a PURE signature check; every time-based claim is re-implemented as its own deliberate, separately reason-coded manual comparison in steps 5-6 below - the library's job here is exactly one thing (cryptography), never claim orchestration.
3. **Issuer** - `verified.getIssuer()` must equal `WorkloadIdentityVerifierConfig#trustedIssuer()` exactly. Never caller-selected.
4. **Audience** - `verified.getAudience()` must contain `WorkloadIdentityVerifierConfig#expectedAudience()`. Never caller-selected.
5. **Expiration/not-before** - manual `Instant` comparison against `now`, with `WorkloadIdentityVerifierConfig#clockSkewTolerance()` (30s default) applied symmetrically.
6. **Issued-at sanity** - `iat` must be present and not implausibly in the future beyond the same tolerance.
7. **Required claims** - `repository`, `repository_owner`, `sha`, `sub`, and a workflow reference (`job_workflow_ref` preferred, falling back to `workflow`) must all be present; `ref`/`environment`/`jti` are legitimately optional.

Every one of the negative acceptance cases the authorization's §24 requires is proven in `Phase2b7Tests` against a LOCALLY signed token and a fake `JwkProvider` (no real network call needed for these): unsigned/garbage token, wrong signing key, unsupported algorithm, expired, future `nbf`, wrong issuer, wrong audience, missing required claim, unknown `kid` with a failing key-lookup.

## 4. JWKS Handling

`jwksUri` is fixed, trusted, control-plane configuration (`WorkloadIdentityVerifierConfig#jwksUri()`, defaulting to GitHub's real `https://token.actions.githubusercontent.com/.well-known/jwks` via `githubActionsDefaults`) - **never** derived from a token's own claims (no `jku` header is ever consulted), a `RunnerRequest` field, or repository content. This is the specific design choice that closes the SSRF surface a "trust the token's own key-location claim" design would otherwise open.

- **HTTPS only** - `BoundedHttpsJwkProvider` refuses a non-HTTPS `jwksUri` at the scheme level.
- **Bounded connect/read timeout** - `WorkloadIdentityVerifierConfig#jwksConnectTimeout()`/`jwksReadTimeout()` (5s default each), applied to the underlying `HttpURLConnection`.
- **Bounded response size** - `jwksMaxResponseBytes` (256 KiB default); `com.auth0:jwks-rsa`'s own `UrlJwkProvider` does not bound response size at all, so `BoundedHttpsJwkProvider` is a small, purpose-built fetcher specifically to add this bound - a plain network-I/O concern, not cryptography, so writing it does not conflict with "do not write custom signature verification primitives."
- **No redirects** - `setInstanceFollowRedirects(false)`; a redirect response is treated as a fetch failure, never followed to a possibly-untrusted host.
- **Key cache with expiration** - `com.auth0.jwk.GuavaCachedJwkProvider` wraps `BoundedHttpsJwkProvider`, keyed by `kid`, with `jwksCacheSize`/`jwksCacheTtl` (10 entries / 10 minutes default).
- **Unknown `kid` → refresh once → fail closed** - a cache miss triggers exactly one fresh fetch (`GuavaCachedJwkProvider`'s own cache-loader semantics); if the fetched document still has no matching key, `SigningKeyNotFoundException` propagates and this verifier maps it to `WORKLOAD_IDENTITY_VERIFIER_UNAVAILABLE` - never a retry loop, never a fallback to an unverified identity.

## 5. GitHub Actions OIDC Reference Implementation

`GitHubActionsIdTokenSource implements WorkloadIdentityTokenSource` performs the real token-minting call a GitHub Actions job with `id-token: write` permission is entitled to make: `GET {ACTIONS_ID_TOKEN_REQUEST_URL}&audience={audience}` with `Authorization: bearer {ACTIONS_ID_TOKEN_REQUEST_TOKEN}` - both environment variables are ambient, populated only by the GitHub Actions runtime itself, never accepted from a `RunnerRequest` field. This is the same request GitHub's own `@actions/core.getIDToken()` helper makes - not an invented protocol.

Minimum claims bound, per the authorization's explicit list: `repository`, `repository_owner`, `ref` (best-effort - present when meaningful), `job_workflow_ref`/`workflow`, `sha`, `aud`. A token merely originating from GitHub Actions is never, by itself, sufficient - see §6 for the separate authorization decision every request still requires.

## 6. Authorization Mapping (`TrustedWorkloadAuthorizationPolicy`)

```java
WorkloadAuthorizationResult authorize(VerifiedWorkloadIdentity identity, String repository, String commitSha, String environment)
```

Fails closed, in this fixed order, covering every mismatch the authorization requires:

1. `identity.repository()` != `repository` → `WORKLOAD_IDENTITY_REPOSITORY_MISMATCH`
2. `identity.commitSha()` != `commitSha` → `WORKLOAD_IDENTITY_COMMIT_MISMATCH`
3. the token DOES carry a GitHub Environment claim AND it disagrees with `environment` → `WORKLOAD_IDENTITY_ENVIRONMENT_MISMATCH` (a token that never uses that optional GitHub feature carries no claim at all, and that alone is never a rejection - only an active disagreement is)
4. no `AllowedWorkload` rule exists at all for `(repository, environment)` → `WORKLOAD_IDENTITY_WORKFLOW_NOT_AUTHORIZED`
5. the matching rule's `repositoryOwner` disagrees with the identity's → `WORKLOAD_IDENTITY_OWNER_MISMATCH`
6. the matching rule's `workflowRef` disagrees with the identity's → `WORKLOAD_IDENTITY_WORKFLOW_NOT_AUTHORIZED`

`AllowedWorkload(repository, repositoryOwner, environment, workflowRef)` rules are fixed, control-plane-supplied configuration (`ProductionWorkloadIdentityConfiguration`'s `runner.credentials.authorization.allowedWorkloads` property) - never derived from a request, a token, or repository content.

## 7. Production Identity Wiring - No Local Fallback

`GitHubOidcRunnerIdentityProvider implements RunnerIdentityProvider` (the EXISTING Phase 2B-2 interface, unchanged) mints a fresh token via `GitHubActionsIdTokenSource` and verifies it via `GitHubActionsOidcVerifier` on **every** `currentIdentity()` call - never cached, matching the "reflects changes on the next call without caching" discipline `HostAttestedRunnerIdentityProvider` already established for this interface. A missing token, an unreachable JWKS endpoint, or a token that fails ANY verification check all collapse to `Optional.empty()` - `ControlledRunner` already treats that as `RUNNER_IDENTITY_UNAVAILABLE` and blocks; there is no less-strict fallback path.

`RunnerIdentity#environmentScope()` here is FIXED, TRUSTED, control-plane configuration (which environments this deployment of verified-OIDC runners may generally act in) - not derived from the token's own optional Environment claim, since requiring that claim would incorrectly block the many workflows that never use GitHub's Environments feature at all. The FINE-GRAINED, per-request repository/commit/environment/workflow binding is a separate, deliberate decision made later during credential federation (§6), which - unlike `RunnerIdentityProvider#currentIdentity()` - has access to the actual `RunnerRequest`.

`HostAttestedRunnerIdentityProvider` remains fully constructible - it is simply never reachable through `ProductionWorkloadIdentityConfiguration#createIdentityProvider`, which requires `runner.identity.mode=oidc` exactly (any other value, including absent, throws `WorkloadIdentityConfigurationException`) and has no branch that could return it. `Phase2b7Tests#identityConfigRejectsMissingOrWrongMode` proves this structurally.

## 8. Credential Federation (`FederatedTerraformCredentialProvider`)

Composes verify → authorize → federate for every `TERRAFORM_PLAN` credential request:

1. `WorkloadIdentityTokenSource#currentToken` - no token → `WORKLOAD_IDENTITY_MISSING`.
2. `WorkloadIdentityVerifier#verify` - any failure → that failure's own precise reason code.
3. `WorkloadAuthorizationPolicy#authorize(identity, request.repository(), request.commitSha(), request.environment())` - any denial → that denial's own precise reason code.
4. `FederatedCredentialProvider#federate(rawToken, identity, repository, environment, TerraformCredentialProfile.PLAN)` - any failure → that failure's own reason code.

Every failure throws `WorkloadIdentityFederationException` (a new unchecked exception) carrying the precise `RunnerReasonCode` AND a sanitized `WorkloadIdentityEvidence` snapshot (§13) of whatever was known before the failure - never a generic exception, never a silently degraded result. `ControlledTerraformOperationCoordinator#executePlan` catches this exception specifically (alongside its existing generic `RuntimeException` catch for genuine infrastructure failures) and maps it to the exact reason code via `blockedPlan`, attaching the evidence via `TerraformPlanEvidence#withWorkloadIdentityEvidence`.

## 9. AWS STS Reference Federation (`AwsStsFederatedCredentialProvider`)

```text
verified GitHub OIDC identity
        |
TrustedCloudRoleResolver (repository, environment, identity, PLAN) -> role ARN
        |
AWS STS AssumeRoleWithWebIdentity(roleArn, sessionName, rawToken, durationSeconds)
        |
temporary credentials (AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY / AWS_SESSION_TOKEN)
```

The repository/request can never choose an arbitrary role ARN, session policy, external ID, duration, or STS endpoint - `TrustedCloudRoleResolver#resolve` is the ONLY path to a role ARN (`StaticTrustedCloudRoleResolver`, a fixed `(repository, environment, profile) -> roleArn` map supplied entirely at construction), and the `AssumeRoleWithWebIdentityRequest` this class builds has no field populated from anything else caller-supplied except the presented token itself (which AWS independently, cryptographically verifies against its own configured OIDC provider trust policy - this class's own verification in §3 does not somehow "vouch" for the token to AWS; AWS re-verifies it from scratch).

**No ambient AWS credentials.** The `StsClient` is built with `AnonymousCredentialsProvider` - `AssumeRoleWithWebIdentity` is, by AWS's own design, an unauthenticated STS API authenticated instead by the presented web identity token, so this class never touches `~/.aws/credentials`, an EC2 instance profile, an ECS task role, or any other entry in the SDK's default credential provider chain. `Phase2b7Tests`' AWS-mocked suite proves role resolution/STS-call/lifetime-check behavior without ever exercising a real AWS account.

## 10. PLAN-vs-Future-APPLY Credential Separation

`TerraformCredentialProfile` is its own enum with exactly ONE value, `PLAN`, specifically so a future mutation-capable profile can never be introduced by silently widening what `PLAN` already grants - adding `APPLY` requires its own explicit, separately-reviewed phase. `StaticTrustedCloudRoleResolver`'s lookup key is `(repository, environment, profile)`, not just `(repository, environment)` - a role mapping entry is scoped to exactly one profile, so a future `APPLY` profile would need its OWN, separately-configured role mappings; there is no way for a `PLAN`-scoped mapping to silently also apply to a hypothetical future `APPLY` lookup, because the key would not match. `AwsStsFederatedCredentialProvider`'s session-name derivation also embeds the profile name (`iac-agent-plan-<hash>`), so even AWS-side CloudTrail records make the intended authority level visible.

## 11. Credential Lifetime

`AwsStsFederatedCredentialProvider`'s production constructor validates, at construction: `requestedSessionDuration` is between AWS's own STS bounds (15 minutes - 12 hours), and `minimumRemainingLifetime` is positive and strictly less than `requestedSessionDuration`. At federation time, `expiresAt` from the STS response is checked against `Instant.now() + minimumRemainingLifetime`; if the remaining lifetime is insufficient, `CREDENTIAL_LIFETIME_INSUFFICIENT` is thrown and the credentials are discarded before ever reaching `TerraformCredentialMaterial`/the launched process. Credentials are never persisted for later reuse - a saved plan's later approval does NOT authorize reuse of the credentials that generated it; each `TERRAFORM_PLAN` attempt federates its own fresh credentials.

## 12. Credential Environment, Never Evidence

Federated credentials reach the Terraform process exclusively through the existing Phase 2B-2/2B-5 `environment().clear()` + trusted-allowlist-then-add discipline - `ControlledTerraformOperationCoordinator` adds `credentials.environmentVariables()` directly to the launched process's environment and never places them anywhere else. `TerraformCredentialMaterial`/`TerraformPlanEvidence`/`RunnerEvidence`/ledger JSON/artifact metadata/logs/exceptions never carry a credential value - only `sourceIdentifier` (a label like `"oidc:aws-sts:arn:aws:iam::...:role/plan-role"`) and the sanitized `WorkloadIdentityEvidence` (§13), neither of which can carry a secret by construction.

## 13. Token Handling and Secret Residual Limitation

The incoming OIDC token is treated as a bearer secret throughout: never logged, never persisted, never placed in any exception message this codebase constructs. `WorkloadIdentityFederationException` structurally cannot carry one (no field for it). `WorkloadIdentityEvidence` carries `subjectSha256`/`tokenIdSha256` - hashes, never the raw `sub`/`jti` claim values.

**Disclosed, not pretended away**, per the authorization's own instruction: `rawToken` and federated credential values are ordinary Java `String`s. The JVM provides no supported mechanism to force-clear a `String`'s backing storage, and neither `com.auth0:java-jwt` nor the AWS SDK expose a mutable-buffer alternative - `FederatedTerraformCredentialProvider`'s javadoc documents this residual limitation explicitly rather than claiming guaranteed secure erasure. What IS guaranteed: these values are local to the credential-resolution call stack only, never stored in any field, and the only value that escapes that call stack (`TerraformCredentialMaterial#environmentVariables()`) goes exclusively to the launched process's environment.

## 14. Replay Considerations - Independent of the Gate B Ledger

Workload identity verification is not a substitute for the Gate B execution ledger (Phase 2B-6) - both remain independent, both-required controls:

```text
verified identity  +  authorization policy  +  durable runner claim (Gate B)
```

A token's `jti` (if present) is recorded ONLY as `tokenIdSha256` - a non-secret hash, for audit/replay ANALYSIS, never as an invented uniqueness guarantee this codebase enforces itself (GitHub does not document `jti` as a strict single-use nonce, so this phase makes no such claim about it). The actual single-use guarantee for a given execution attempt remains entirely `PostgresRunnerLedgerRepository`'s atomic claim (Gate B, unchanged, still closed).

## 15. Workload Identity Evidence (`WorkloadIdentityEvidence`)

Embedded into `TerraformPlanEvidence` (a new nullable field, attached via `TerraformPlanEvidence#withWorkloadIdentityEvidence` - a post-construction wither chosen specifically to avoid touching the coordinator's already-large internal `planEvidence` helper's parameter list and its many existing call sites, since this concern only ever applies from the point credential resolution is attempted onward). Populated for BOTH a successful federation and a denied one, via three factory methods reflecting exactly how much was known when the attempt stopped:

- `WorkloadIdentityEvidence.success(...)` - full verified claims + credential provider type/role identifier/expiration.
- `WorkloadIdentityEvidence.deniedAfterVerification(...)` - full verified claims (so an operator can see WHICH identity was denied and why), `authorized=false`, no credential fields.
- `WorkloadIdentityEvidence.deniedBeforeVerification(...)` - no verified claims exist yet (no token at all, or the token failed cryptographic verification), only the verifier metadata and timestamp.

Never contains the raw token or any credential value - structurally, by field list (`Phase2b7Tests#workloadIdentityEvidenceNeverCarriesRawTokenOrCredentialValueFields`). Persisted through the existing `TerraformPlanEvidenceJson` hand-written (de)serializer, as a nested JSON object, using the exact same manual-JSON discipline (never Jackson POJO/record data binding) already established for every other evidence type in `com.iacagent.iacagent.runner.jdbc`.

## 16. SSRF / Endpoint Control

Three network-capable endpoints exist in this phase, and none may come from a request, repository content, LLM output, or a token's own claims:

- **JWKS endpoint** - `WorkloadIdentityVerifierConfig#jwksUri()`, fixed control-plane configuration (§4).
- **Issuer** - `WorkloadIdentityVerifierConfig#trustedIssuer()`, fixed control-plane configuration, used only for an equality check against the token's `iss` claim - never dereferenced as a URL to fetch anything from.
- **STS endpoint** - resolved by the AWS SDK from `awsRegion` (fixed control-plane configuration passed to `AwsStsFederatedCredentialProvider`'s constructor), never a caller-suppliable endpoint override.

`Phase2b7Tests#runnerRequestCarriesNoIdentityFederationSecurityRelevantField` proves `RunnerRequest` has no field through which any of these could be influenced.

## 17. Network Failure Behavior

```text
JWKS unavailable / key refresh fails  -> WORKLOAD_IDENTITY_VERIFIER_UNAVAILABLE (fails closed)
STS unavailable / SdkException        -> CREDENTIAL_FEDERATION_FAILED (fails closed)
credential federation exceeds apiCallTimeout -> CREDENTIAL_FEDERATION_FAILED (fails closed, bounded)
```

None of these ever fall back to a stale identity, a local identity, or static/ambient credentials - every failure path in `GitHubActionsOidcVerifier`/`AwsStsFederatedCredentialProvider`/`FederatedTerraformCredentialProvider` ends in a specific, thrown/returned failure, never a degraded-but-still-proceeding result. The JWKS cache's own TTL (`jwksCacheTtl`, 10 minutes default) is what keeps an ordinary brief JWKS outage from mattering in practice for already-cached keys - a NEW, previously-unseen `kid` during an outage still fails closed rather than being treated as trusted-by-default.

## 18. No Ambient AWS Credentials - Structural Guarantee

Covered in depth in §9. `AwsStsFederatedCredentialProvider`'s production constructor builds its own `StsClient` with `AnonymousCredentialsProvider.create()` - there is no code path in this class, or in `FederatedTerraformCredentialProvider`, that ever calls `DefaultCredentialsProvider`/consults `~/.aws/credentials`/an EC2 instance profile/an ECS task role/any other ambient AWS identity source. `AwsStsFederatedCredentialProviderTests` proves the actual `AssumeRoleWithWebIdentityRequest` sent to (a mocked) STS carries exactly the resolved role ARN and the presented raw token - nothing ambient.

## 19. Production Wiring - `ProductionWorkloadIdentityConfiguration`

Two sole production entry points, mirroring the Gate B `RunnerLedgerConfiguration` no-fallback discipline exactly:

- `createIdentityProvider(Map<String,String>)` - requires `runner.identity.mode=oidc` exactly.
- `createCredentialProvider(Map<String,String>)` - requires `runner.credentials.mode=federated` exactly, and `runner.credentials.federated.provider=aws` exactly (the only federation target this phase ships).

Neither method has a branch that could return `HostAttestedRunnerIdentityProvider`/`StaticRunnerIdentityProvider`/`NoOpTerraformCredentialProvider`/a static-credential provider - this is a structural property of the method bodies (no such branch exists to fall into), not a runtime check a future edit could accidentally weaken. Any missing/invalid configuration throws `WorkloadIdentityConfigurationException` immediately, before any verifier/token-source/federation client is constructed - a misconfigured deployment fails at startup, never silently degrading. `HostAttestedRunnerIdentityProvider`/`NoOpTerraformCredentialProvider` remain fully constructible directly by test/reference code - their own class javadoc already marks them non-production (from Phases 2B-2/2B-5), unchanged by this phase.

## 20. Reference/Test Implementations - Unmistakably Non-Production

`HostAttestedRunnerIdentityProvider` and `NoOpTerraformCredentialProvider` (both pre-existing) are unchanged; their class-level javadoc already states their non-production status, established in Phases 2B-2 and 2B-5 respectively. `StaticRunnerIdentityProvider` likewise remains test-only per its own pre-existing javadoc. No new reference/test-only production-shaped class was added by this phase that could be mistaken for a production implementation.

## 21. Libraries, Pinned

```text
com.auth0:java-jwt:4.5.0        - JWT parsing/signature verification
com.auth0:jwks-rsa:0.22.2       - JWKS fetching/caching/kid lookup
software.amazon.awssdk:bom:2.46.7 (managing software.amazon.awssdk:sts) - AWS STS client
```

No hand-rolled RSA/ECDSA signature verification anywhere in this codebase - `BoundedHttpsJwkProvider` (the one genuinely new network-facing class this phase adds) performs plain bounded HTTP I/O and JSON parsing only, never cryptography; all actual signature verification happens inside `com.auth0:java-jwt`.

## 22. Real Acceptance Procedure and Its Actual Result

Per the authorization: unit tests may use local signed JWTs, a fake JWKS provider, and mocked STS (all of which this phase's unit suite does extensively - see `Phase2b7Tests`/`AwsStsFederatedCredentialProviderTests`), but Gate C closure requires REAL target-system evidence, exactly the lesson Phase 2B-6 already established.

**GitHub OIDC identity: real evidence obtained and confirmed.** `src/identityAcceptanceTest/java/.../RealGitHubActionsOidcAcceptanceTest.java` (run via `./gradlew identityAcceptanceTest`, auto-skipping everywhere outside a real GitHub Actions job via `@EnabledIfEnvironmentVariable`) mints a REAL token through the ambient `ACTIONS_ID_TOKEN_REQUEST_URL`/`ACTIONS_ID_TOKEN_REQUEST_TOKEN` GitHub Actions populates, and verifies it against the REAL `https://token.actions.githubusercontent.com` issuer/JWKS - no mock, no fake JWKS server, no locally-signed token. Triggered via `.github/workflows/phase2b7-identity-acceptance.yml`, which fires on `push` to the disposable `phase2b7-identity-acceptance-check` ref (not `workflow_dispatch` - see the workflow file's own header comment for why: `workflow_dispatch` requires the workflow file to already exist on the default branch, which conflicts with this phase's "do not push to main before review" discipline). **Recorded result:** run [`34963417182`](https://github.com/haftomalemayehu/IAC-Agent/actions/runs/34963417182), `conclusion=success`, at commit `1f638b089f77b33ad6d3f180c8ddbe8b67e93739` (this phase's exact commit), completed 2026-09-15T11:27:53Z. The disposable branch was deleted after the run.

**AWS STS federation: explicitly deferred, per direct instruction from the user during this phase's authorization.** This development session has no AWS account, no AWS CLI, and no AWS credentials of any kind (`aws` is not even installed) - real `AssumeRoleWithWebIdentity` federation requires an actual AWS account with an IAM OIDC identity provider trusting `token.actions.githubusercontent.com` and a role with a trust policy scoped to this repository, which only an AWS account holder can provision. The user was asked directly and chose: *"Implement fully, defer real AWS evidence"* - the complete AWS federation code path is implemented and thoroughly unit-tested against a mocked `StsClient` (`AwsStsFederatedCredentialProviderTests`: successful federation, role-not-authorized, STS-unreachable, insufficient-remaining-lifetime, raw-token-presented-correctly), but its real-AWS execution has not happened and is not claimed as having happened. **This keeps the AWS-federation dimension of Gate C explicitly open pending real AWS role/account infrastructure**, to be verified in a follow-up once that infrastructure exists - see §23.

## 23. Gate C Closure Checklist

```text
[x] production OIDC verifier implemented              - GitHubActionsOidcVerifier
[x] cryptographic signature verified                   - com.auth0:java-jwt, RS256, real key material
[x] issuer pinned                                      - WorkloadIdentityVerifierConfig#trustedIssuer()
[x] audience pinned                                    - WorkloadIdentityVerifierConfig#expectedAudience()
[x] expiration/nbf enforced                             - manual checks, unit-tested
[x] required claims enforced                            - manual checks, unit-tested
[x] repository authorization enforced                   - TrustedWorkloadAuthorizationPolicy
[x] commit authorization enforced where required        - TrustedWorkloadAuthorizationPolicy
[x] environment/workflow authorization enforced         - TrustedWorkloadAuthorizationPolicy
[x] JWKS endpoint trusted/bounded                       - BoundedHttpsJwkProvider + GuavaCachedJwkProvider
[x] unknown-kid refresh fails closed                    - unit-tested (alwaysThrowingProvider case)
[x] production local-identity fallback impossible       - ProductionWorkloadIdentityConfiguration, unit-tested
[x] real cloud federation implemented                   - AwsStsFederatedCredentialProvider (AssumeRoleWithWebIdentity)
[x] role selection control-plane owned                  - TrustedCloudRoleResolver/StaticTrustedCloudRoleResolver
[x] temporary credentials only                          - STS-issued, bounded lifetime
[x] credential lifetime bounded                         - constructor validation + per-call remaining-lifetime check
[x] no ambient credential-chain fallback                - AnonymousCredentialsProvider, verified structurally + by test
[x] token/credentials absent from evidence/logging       - structural tests + design (§12, §13, §15)
[x] real provider-issued OIDC token tested              - run 34963417182, success, at commit 1f638b0
                                                           (see §22 for the full recorded result)
[ ] real STS federation tested                          - NOT DONE this session - no AWS account access;
                                                           explicitly deferred per direct user instruction (§22)
[ ] read authority proven (real AWS)                     - NOT DONE this session - blocked on the same AWS access gap
[ ] mutation denial proven (real AWS)                    - NOT DONE this session - blocked on the same AWS access gap
[x] negative identity cases proven                       - Phase2b7Tests, full §24 list, local signed JWTs
[x] all LOCAL suites green                               - 401/401 unit tests, 5/5 fresh reruns

GATE C: The GitHub OIDC identity-verification half is closed on real-issuer evidence (§22). The AWS
credential-federation half remains OPEN pending real AWS account/role infrastructure this session
could not access - per the same "implementation completeness is not acceptance completeness"
standard Phase 2B-6 established, this phase does not claim the AWS half closed on mocked-STS
evidence alone, regardless of how thorough that mocked coverage is.
```

## 24. Gates A/B/D/E/F - Unchanged

```text
Gate A: Approval persistence needs real PostgreSQL integration. Still open - untouched.
Gate B: Production runner ledger / concurrency. CLOSED (Phase 2B-6) - untouched by this phase.
Gate D: Production runner sandboxing - OS/container isolation, resource limits, network policy. Still open.
Gate E: Module/provider supply-chain governance. Still open.
Gate F: Production remote-state/backend hardening + plan-artifact-at-rest security. Still open.
```

## 25. No APPLY/DESTROY/State Mutation - Structural Confirmation

`ControlledTerraformOperation`/`RunnerOperation` are unchanged by this phase - still exactly seven Terraform operations, no `APPLY`, no `DESTROY`, no `IMPORT`, no `STATE`, no `FORCE_UNLOCK` (`Phase2b7Tests#terraformOperationSurfaceRemainsExactlySevenAfterPhase2b7`). `TerraformCommandFactory` is untouched by this phase. `ControlledTerraformProcess` remains the sole `ProcessBuilder`-constructing class (`Phase2b7Tests#soleProcessBuilderInvariantPreserved`). This phase's entire purpose is proving WHO is asking and WHAT it may read - it introduces no new capability to mutate anything, cloud-side or Terraform-state-side.

## 26. Review Round 1 (REVISE, 7 items) - Fixes Applied

A code review of this phase's local commit found 2 blockers and 5 correctness/process defects. Items 2-7 below are fixed in this amendment; item 1 (production wiring) was investigated and resolved as "leave unwired, documented" - see below and the standing status note at the top of this document.

1. **BLOCKER, resolved as "leave unwired, documented":** `ProductionWorkloadIdentityConfiguration.createIdentityProvider`/`createCredentialProvider` have zero callers in `src/main` - the entire feature is dead code in production. Investigation found this is NOT specific to this phase: there is no `@Configuration`/`@Bean` anywhere in `src/main`, `ControlledRunner` has zero construction sites outside tests, and `IacAgentController`/`IacAgentService` remain the pure-simulation Phase-1 stubs, unchanged since Phase 2B-3 deliberately removed the only real execution endpoint. Standing up a live composition root for the runner subsystem is its own separate, explicitly-scoped future phase - not part of this amendment. See the paragraph after this list for the full writeup.
2. **Fixed:** `TrustedWorkloadAuthorizationPolicy.authorize()` picked an arbitrary `AllowedWorkload` rule via `findFirst()` over a `Set` (unspecified iteration order) whenever more than one rule existed for the same `(repository, environment)` pair, risking a nondeterministic wrongful denial. Replaced with order-independent existence checks: grant if ANY candidate rule matches owner+workflowRef exactly; otherwise `OWNER_MISMATCH` only if NO candidate rule has the right owner, else `WORKFLOW_NOT_AUTHORIZED`. New tests: `secondMatchingRuleForSameRepositoryEnvironmentIsAuthorizedRegardlessOfSetIterationOrder`, `workflowMismatchAgainstAllRulesForRepositoryEnvironmentIsDeniedAsWorkflowNotAuthorized`, `ownerMismatchAgainstAllRulesForRepositoryEnvironmentIsDeniedAsOwnerMismatch`.
3. **Fixed:** `BoundedHttpsJwkProvider`/`GitHubActionsIdTokenSource` never closed/disconnected their `HttpURLConnection`/`InputStream` on any path. Both now wrap the connection in try/finally with `disconnect()`, and the input stream in try-with-resources.
4. **Fixed:** `GitHubActionsIdTokenSource.currentToken()` could throw unchecked `IllegalArgumentException` from `URI.create()`/`URLEncoder` on a malformed `ACTIONS_ID_TOKEN_REQUEST_URL`, escaping uncaught (only `IOException` was caught) and losing the precise `WORKLOAD_IDENTITY_*` reason-code classification downstream. Now caught alongside `IOException` and wrapped in `WorkloadIdentityTokenUnavailableException`, with the already-thrown `WorkloadIdentityTokenUnavailableException` cases passed through unchanged (not double-wrapped).
5. **Fixed:** `AwsStsFederatedCredentialProvider.federate()` built the credential environment map with `Map.of(...)`, which throws NPE on any null STS response field - an SDK edge case, not a call-site bug, but the NPE escaped uncaught and misreported as a generic infrastructure failure instead of `CREDENTIAL_FEDERATION_FAILED`. Now null-checked explicitly before `Map.of(...)`, failing closed with the correct reason code. New test: `nullCredentialFieldInStsResponseThrowsCredentialFederationFailedNotNpe`.
6. **Fixed:** `TerraformPlanEvidenceJson.workloadIdentityEvidenceFromJson` read `verifierType`/`verifierVersion` via raw `.path(...).asText()` instead of the file's own `textOrNull()` helper, silently coercing a persisted JSON `null` to `""` on reload - a round-trip fidelity bug for `verifierVersion` (legitimately nullable). Now uses `textOrNull()` for both, matching every other optional field in this file. New test: `workloadIdentityEvidenceWithNullVerifierVersionRoundTripsAsNullNotEmptyString`.
7. **Fixed:** §22 of this document asserted "real evidence obtained" as fact while §23's own checklist left the identical item unchecked pending a "final phase report" that didn't exist - violating this repo's own CLAUDE.md rule ("never claim validation succeeded unless the command ran successfully"). The claim happened to be true (independently confirmed via `gh run view 34963417182`: `conclusion=success` at this phase's exact commit SHA), but the document asserted it before that was substantiated in-document. §22/§23 now cite the actual run ID, SHA, and timestamp directly.

441/441 local tests green (up from 401/401), stable across 2 fresh reruns (`./gradlew test` then `./gradlew test --rerun`).

**Item 1 (production wiring) - resolved as: leave unwired, documented as expected, not a 2B-7-specific gap.** A repo-wide check confirms this isn't unique to this phase: there is no `@Configuration`/`@Bean` class anywhere in `src/main`, `ControlledRunner` itself has zero construction sites outside tests, and `IacAgentController`/`IacAgentService` remain the pure-simulation Phase-1 stubs (canned risk scores, textual step lists like `"terraform apply tfplan"`) with no reference to `ControlledRunner`, `ControlledTerraformOperationCoordinator`, the approval subsystem, or anything built since Phase 2B-1 - consistent with `IacAgentController`'s own class javadoc, which confirms the only real execution endpoint (`/pipeline`) was removed on purpose in Phase 2B-3. Every runner-subsystem safety-boundary piece since then has been built bottom-up but deliberately never exposed through a live entry point - this phase's identity/credential code is no exception, not a regression it introduced.

Standing up a live composition root that constructs `ControlledRunner` with real providers, reachable from anything, is its own separate, explicitly-scoped decision - the same "wait for the user's go-ahead before starting" discipline every prior phase boundary in this project has followed. It is intentionally NOT done as part of this amendment. Until that decision is made and scoped, `ProductionWorkloadIdentityConfiguration.createIdentityProvider`/`createCredentialProvider` remain constructible and unit-tested, but dead code from any real deployment's perspective - Gate C's OIDC-verification half should be read as "the verifier is correct and proven against a real issuer," not "this is live in any deployment."
