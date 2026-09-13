package com.iacagent.iacagent.runner;

import java.util.Optional;

/**
 * The trusted durable home for saved-plan binaries produced by {@code TERRAFORM_PLAN} - the ONLY
 * place a plan's bytes live once the ephemeral per-request {@link RunnerWorkspaceManager} workspace
 * that created it is cleaned up. A plan artifact must survive long enough for review, approval, and
 * eventual controlled apply - none of which happen inside the same runner request that created it.
 *
 * <p>{@code store} always derives {@code planArtifactId} from the plan's own content hash
 * (content-addressed, the same discipline established for staged artifacts elsewhere in this
 * package) - never from a caller-supplied id, so two different plans can never collide on identity
 * and the same plan bytes always resolve to the same artifact id.
 */
public interface TerraformPlanArtifactStore {

    TerraformPlanArtifactMetadata store(
            String repository, String commitSha, String environment, String stateIdentitySha256, String planInputSha256, byte[] planBytes);

    Optional<StoredTerraformPlanArtifact> resolve(String planArtifactId);

    Optional<TerraformPlanArtifactMetadata> metadata(String planArtifactId);
}
