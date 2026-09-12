# Phase 2B-4: Controlled Provider/Backend Initialization + Validation

**Status:** Implemented and amended after review, three revision rounds (`com.iacagent.iacagent.runner`, `com.iacagent.iacagent.runner.jdbc`). Adds `TERRAFORM_INIT`, `TERRAFORM_VALIDATE`, and `TERRAFORM_PROVIDERS_SCHEMA` to the closed Terraform operation surface established in Phase 2B-3. Still no `plan`/`apply`/`destroy`/`state`/`force-unlock`/`taint`/`untaint`/`refresh`/`workspace` (`import` blocks are parsed only for their provider reference, per §3.1 - never executed).

**Precise invariant (wording amended after review):** *No production runner/control-plane operation can represent or dispatch infrastructure or Terraform-state mutation.* This is deliberately narrower than "no mutation capability exists anywhere in the codebase" - `terraform init` genuinely DOES mutate the runner's own ephemeral workspace (`.terraform/` metadata, a plugin cache, a lockfile if the configuration requires one) even under `-backend=false`. What `init`/`validate`/`providers schema` can never do is mutate *infrastructure* or *Terraform state* - no operation, argv shape, or code path in this package can represent `plan`/`apply`/any remote-state or infrastructure-affecting action. `com.iacagent.iacagent.runner.ControlledTerraformProcess` remains the sole process-spawning class anywhere in `src/main` (verified by `ProductionExecutionSurfaceTests` and the narrower `Phase2b3Tests#processBuilderAppearsOnlyInControlledTerraformProcess`).

**Security amendment (second revision):** the initial Phase 2B-4 implementation's source-policy enforcement and configuration-identity binding were both found insufficient on review and have been replaced:
- The line/regex-based `TerraformConfigSourceScanner` (deleted) could not serve as an enforcement boundary against untrusted repository Terraform - it is replaced by a real, structure-aware parser (`TerraformNativeSourceExtractor` for `*.tf`, `TerraformJsonSourceExtractor` for `*.tf.json`, unified behind `TerraformConfigSourceExtractor`) that fails closed on anything it cannot deterministically understand, rather than silently omitting it. See §3.
- `TerraformConfigIdentity`'s content-sorted-only hash could let two directory layouts with content swapped between files (e.g. `main.tf`/`override.tf`) collapse to the same `configSha256`, since Terraform override-file semantics make filenames semantically significant. It now hashes canonical (relative path, content) tuples, sorted by path. See §8.

**Security amendment (third, final revision):** even with a real parser, review found the extracted manifest was not yet authoritative over everything `init` could actually discover - two gaps closed in this revision:
- Terraform can resolve a provider **implicitly** (a `resource`/`data` block's type prefix, or a bare `provider "x" {}` block) with no `required_providers` entry at all, falling back to `registry.terraform.io/hashicorp/<name>` - a source `TerraformSourcePolicy` never actually saw. Every provider dependency must now have an explicit `required_providers` entry, or `init` is blocked. See §3.1.
- A directly allowlisted **module** can itself download content that declares further, previously-unvetted providers/modules during the same `init` - the pre-init manifest only ever described the ROOT configuration, never a module's transitive contents. Module execution is deferred entirely: any `module` block blocks `init` unconditionally in this phase, regardless of source policy. See §3.2.

**Security amendment (fourth, final revision):** review found the implicit-provider check itself incomplete - a resource/data block's type prefix is not always the provider Terraform will actually use, because an explicit `provider = ...` meta-argument can override it. The prior revision's rule ("resource type prefix → implied provider") produced both a false rejection (a validly-aliased provider whose type prefix genuinely differs from its local name) and, more importantly, a real gap (an explicit `provider = unexpected.foo` reference naming an undeclared local name was never checked at all, since only the type prefix was ever inspected). This revision replaces "type prefix" with "the EFFECTIVE provider local name" - an explicit `provider` meta-argument's `localName`/`localName.alias` reference, when present, always wins over the type prefix; the type prefix is consulted only in its absence. `import` blocks (the only other Terraform 1.6.6 root-module construct found to carry an explicit provider reference) are covered the same way. See §3.1.

**Phase 2B-4's execution boundary, precisely:** *Phase 2B-4 supports root-module initialization only. Every provider dependency Terraform can discover from the supported root-module configuration surface must have an explicit, policy-approved `required_providers` declaration under its EFFECTIVE provider local name - not merely its resource-type prefix. Module blocks are parsed but are not initialization-eligible until transitive dependency governance is implemented.*

---

## 1. Why `init` Is a New Trust Boundary

Phase 2B-3's three operations (`version`, `fmt -check`, `show -json`) are read-only with respect to the outside world: none of them can access a network, write meaningful filesystem state, or execute third-party code. `terraform init` is categorically different - depending on the configuration it is pointed at, it can:

```text
access provider registries
access module registries
download and locally cache provider binaries (which are then themselves executable)
download modules (arbitrary third-party Terraform/HCL, and via submodules, more sources still)
initialize a remote backend (network access, potentially remote-state read/write)
create .terraform/ metadata in the working directory
create or modify .terraform.lock.hcl
```

None of these are "just running a command" in the sense Phase 2B-3's operations are - they introduce genuine supply-chain and network surface. Phase 2B-4 does not disable this capability; it constrains it with an explicit policy layer (backend mode, provider/module source allowlisting, lockfile integrity, a runner-owned CLI config) so that what `init` is allowed to reach is a trusted-bootstrap decision, never something a caller or a repository can influence merely by asking.

## 2. Backend Policy - Why `-backend=false`

`TerraformBackendMode` models three states: `LOCAL_ONLY`, `REMOTE_READONLY_INIT`, `REMOTE_ALLOWED`. **Only `LOCAL_ONLY` is implemented.** `ControlledTerraformOperationCoordinator#executeInit` rejects any other configured mode with `TERRAFORM_BACKEND_MODE_UNSAFE` before `init` is ever launched - this is a hard, structural refusal at the coordinator level, not merely a default nobody happens to have changed.

`TerraformCommandFactory#initCommand` always constructs `-backend=false` into the argv, unconditionally - there is no parameter through which a caller, a request field, or repository content could supply a backend-config argument, `-reconfigure`, `-migrate-state`, `-force-copy`, or `-upgrade`. `RunnerRequest` carries no field of any kind related to backend configuration (see `Phase2b4Tests#runnerRequestHasNoFieldThatCouldWidenOrSupplySourcePolicy`). This phase never involves remote state credentials, state locking, or state refresh in any form.

## 3. Provider/Module Source Policy - Parser-Backed Enforcement

`TerraformSourcePolicy` is a closed, trusted-bootstrap-configured record: `allowedProviderSourcePrefixes`, `allowedModuleSourcePrefixes`, `allowRegistryNetworkAccess`, `allowGitModuleSources`, `allowLocalModuleSources`. `TerraformSourcePolicy.restrictiveDefault()` allows only `registry.terraform.io/hashicorp/*` providers and no module sources of any kind - the Phase 2B-4 starting point. Like `TerraformExecutableDescriptor`, this is never constructed from a `RunnerRequest` field or repository content; it is something trusted code configures the coordinator with once.

**This is a genuine enforcement boundary, not a heuristic screen.** An earlier revision extracted `source` declarations with a line/regex-based scanner; review correctly rejected that as unsafe against untrusted repository content - Terraform configuration can be formatted in ways a line scanner misses (multiline structures, unusual whitespace, override files, JSON syntax), and "the only sources Terraform will interpret" is a claim a heuristic cannot make. That scanner has been deleted and replaced with a real parsing pipeline:

```text
staged configuration files (*.tf / *.tf.json)
        ↓
TerraformNativeSourceExtractor (real HCL-subset parser)   /   TerraformJsonSourceExtractor (real JSON parser)
        ↓
TerraformKeyedConfigSources (per-file, keyed by provider local name / module label)
        ↓
TerraformConfigSourceExtractor (merges files; override files applied last, so their
                                 redeclaration for the same key wins - Terraform's own precedence)
        ↓
TerraformConfigSourceManifest (canonical providerSources / moduleSources / declared+implied provider names)
        ↓
module-presence gate (§3.2) → implicit-provider gate (§3.1) → TerraformSourcePolicy (per declared provider source)
        ↓
INIT allowed, or BLOCKED (TERRAFORM_MODULE_DEPENDENCY_GRAPH_UNRESOLVED / TERRAFORM_PROVIDER_REQUIREMENT_IMPLICIT /
                           TERRAFORM_PROVIDER_SOURCE_UNTRUSTED / TERRAFORM_SOURCE_EXTRACTION_FAILED)
```

`TerraformNativeSourceExtractor` is a real, structure-aware parser: `HclLexer` tokenizes native syntax (identifiers, quoted strings with escape/`${...}`-interpolation awareness, heredocs, line/block comments, and brace/bracket/paren punctuation) as atomic, correctly-bounded tokens - a string or heredoc containing `{`, `}`, or `#` characters can never be misread as structural punctuation, which is exactly the class of mistake a line-based scan is vulnerable to. A recursive-descent body parser then walks the token stream tracking TRUE nesting depth for every block and object it encounters (not just the two shapes it specifically interprets), so it can never lose synchronization and silently skip past a `required_providers` or `module` block. `TerraformJsonSourceExtractor` parses `*.tf.json` via this codebase's established exact-JSON tree-parsing convention - JSON has no formatting ambiguity to begin with.

**Fail-closed contract:** the only value ever accepted for a `source` attribute (or a `required_providers` entry's shorthand string form) is an immediate, non-interpolated string literal. A reference, function call, string interpolation (`${...}`), heredoc, list, object, malformed/unterminated syntax, or an unrecognized file extension throws `TerraformConfigSourceExtractionException`, which `ControlledTerraformOperationCoordinator#executeInit` turns into a hard block (`TERRAFORM_SOURCE_EXTRACTION_FAILED`) **before `terraform init` is ever launched** - proven via marker-file tests (`Phase2b4Tests#interpolatedSourceValueFailsExtractionClosedBeforeInitEverRuns`, `#disallowedProviderSourceBlocksBeforeInitEverRuns`, `#disallowedHttpModuleSourceBlocksBeforeInitEverRuns`). A `required_providers` entry with no explicit `source` is not a failure - it resolves to Terraform's own documented default namespace, `registry.terraform.io/hashicorp/<local-name>`, which is then itself checked against policy like any other source.

**Genuinely out of scope, and named as such rather than left implicit:** the full HCL expression language (arbitrary functions, `for_each`/dynamic-block generated values, conditionals) is not implemented - none of that changes what this parser accepts as a valid `source` value, since anything other than an immediate string literal already fails closed. This is a deliberate, disclosed scope limit of the PARSER's expression support, not of the ENFORCEMENT property - the fail-closed contract holds regardless of how exotic the surrounding configuration is. This is a different, narrower kind of "not full HCL" than the retired scanner's: the retired scanner could silently miss a source it should have flagged; this parser cannot - it either extracts a source deterministically or refuses to proceed.

### 3.1 Explicit Provider Declaration Required - Effective Local Name, Not Just Type Prefix

A parser that correctly extracts every `required_providers` entry is still not a complete pre-`init` policy boundary, because **Terraform does not require a `required_providers` entry to resolve a provider at all.** Given:

```hcl
resource "tls_private_key" "key" {
  algorithm = "RSA"
}
```

Terraform infers the provider from the resource type's prefix (`tls_private_key` → provider local name `tls`) and falls back to `registry.terraform.io/hashicorp/tls` with NO explicit declaration anywhere in the configuration. Before the third revision, such a configuration produced an EMPTY `providerSources` list - `TerraformSourcePolicy` never saw anything to evaluate, `init` proceeded, and Terraform could still resolve and download a provider the policy was never asked about.

**Amended again (fourth revision): the type prefix is not always the provider Terraform will actually use.** An explicit `provider = ...` meta-argument on a `resource`/`data` block overrides it:

```hcl
terraform {
  required_providers {
    corpaws = {
      source = "hashicorp/aws"
    }
  }
}

resource "aws_s3_bucket" "example" {
  provider = corpaws.east
}
```

Here the resource type prefix is `aws`, but the EFFECTIVE provider local name - the one Terraform actually resolves - is `corpaws`. The prior revision's "type prefix implies the provider" rule got this backwards in two ways: it would have falsely required a `required_providers.aws` entry that does not need to exist (a false rejection), and - the more serious gap - it never inspected the `provider = corpaws.east` reference at all, so a reference to a genuinely UNDECLARED local name (`provider = unexpected.foo`, with no `required_providers.unexpected` anywhere) passed through completely unchecked.

**The rule is now stated in terms of the effective provider local name, not the type prefix:**

```text
for each resource/data block:
    if an explicit `provider = localName` or `provider = localName.alias` meta-argument exists:
        effective local name = localName          (the type prefix is NOT also required)
    otherwise:
        effective local name = <type prefix up to the first underscore>

for each provider "localName" { ... } block:
    effective local name = localName

for each import block with an explicit `provider = ...` meta-argument:
    effective local name = localName               (an import with no explicit provider relies on
                                                      its target resource block's own requirement,
                                                      already checked independently)
```

`TerraformConfigSourceManifest` tracks `declaredProviderLocalNames` (the keys of every `required_providers` entry) and `impliedProviderLocalNames` (every EFFECTIVE provider local name computed by the rule above). `ControlledTerraformOperationCoordinator#executeInit` blocks with `TERRAFORM_PROVIDER_REQUIREMENT_IMPLICIT` whenever `manifest.undeclaredImpliedProviderLocalNames()` is non-empty - **before `init` is ever launched**. Proven via marker-file tests (`Phase2b4Tests#resourceUsingAProviderAbsentFromRequiredProvidersBlocksBeforeInitEverRuns`, `#providerBlockAbsentFromRequiredProvidersBlocksBeforeInitEverRuns`, `#explicitProviderReferenceToAnUndeclaredLocalNameBlocksBeforeInit`, `#resourceTypePrefixIsNotAlsoRequiredWhenAnExplicitProviderOverridesIt`).

**Explicit provider references fail closed on anything not statically recognizable.** `TerraformNativeSourceExtractor` only ever captures a `provider` attribute's value as a usable reference when it is an immediate, clean `IDENT` or `IDENT '.' IDENT` token chain ending exactly at end-of-statement (a newline or the enclosing block's closing brace) - implemented via a new `HclToken.Type.DOT` token and a dedicated `tryParseReferenceChain` check inside the general `parseValue` path, added alongside (not replacing) the existing string/object/opaque handling. A reference with a third dotted segment, an index (`local.provider_map[var.env]`), a function call, or any other shape this parser does not specifically recognize is captured as `Opaque` instead of `Reference`, and `resolveProviderReference` throws `TerraformConfigSourceExtractionException` (→ `TERRAFORM_SOURCE_EXTRACTION_FAILED`) for anything that isn't a `Reference` of exactly one or two parts. Proven via `Phase2b4Tests#malformedOrDynamicProviderReferenceFailsExtractionClosedBeforeInit`. `TerraformJsonSourceExtractor` applies the equivalent rule to a `"provider": "localName"`/`"localName.alias"` JSON string, validating both dotted segments are legal identifiers.

**`import` blocks reviewed and covered.** Of Terraform 1.6.6's root-module configuration grammar, `import` is the only other construct found to carry an explicit provider reference (`import { ... provider = aws.alternate }`) - it is now parsed the same way, in both native and JSON syntax (`Phase2b4Tests#nativeImportBlockWithExplicitProviderIsIncludedInTheImpliedSet`, `#jsonImportBlockWithExplicitProviderIsIncludedInTheImpliedSet`). An `import` block with no explicit `provider` relies on its target resource's own `resource` block declaration, which is independently walked and checked - nothing is silently skipped.

**One narrow, deliberate, and safe exception:** the built-in `terraform` provider (the source of `terraform_data`/`terraform_remote_state`) is exempt. It ships inside the Terraform binary itself, real Terraform never requires (or even permits) declaring it in `required_providers`, and - critically for this policy's purpose - it cannot be redirected to an arbitrary or attacker-controlled source; "resolving" it involves no network fetch or third-party code at all. This is why the existing `PROVIDERLESS_CONFIG` test fixture (`resource "terraform_data" "x" {}`) continues to succeed unmodified (`Phase2b4Tests#builtinTerraformProviderResourceIsExemptFromTheExplicitDeclarationRequirement`).

**Disclosed simplification:** the resource-type-to-provider-local-name mapping (used only when no explicit `provider` meta-argument exists) uses Terraform's common "up to the first underscore" convention rather than its full longest-declared-prefix resolution algorithm (which would need to consult the very requirements this check exists to validate). A resource type using a non-conventional provider local name would cause this check to require a `required_providers` entry under the COMPUTED name - which fails closed (blocks) rather than silently under-enforcing. The simplification can only make this check MORE conservative, never less.

### 3.2 Module Execution Restriction - Not Yet Initialization-Eligible

A module source passing `TerraformSourcePolicy` only proves the DIRECT reference is trusted. It proves nothing about what that module's own downloaded contents might themselves declare:

```hcl
module "approved" {
  source = "registry.example/approved/network/aws"   # passes policy
}
```

The `approved` module's own `.tf` files - fetched and read by Terraform DURING the same `init` invocation, never staged or parsed by this runner first - could contain their own `terraform { required_providers { ... } }` block naming a provider source `TerraformSourcePolicy` was never asked about, or their own nested `module` block pointing anywhere at all (a different registry, a git host, an HTTP URL). The trust chain `root config → parser manifest → policy PASS → init` would then be followed by `init → downloads approved module → module introduces unseen dependencies → additional download`, entirely outside what the pre-init manifest described.

This runner does not yet implement a recursively-staged, recursively-parsed, recursively-policy-validated module dependency graph. Rather than allow a partial, unsound version of that (a module whose OWN top-level source passes policy, while its transitive contents remain completely unvetted), Phase 2B-4 makes module execution categorically out of scope: **any `module` block - registry, git, HTTP, or local, regardless of what `TerraformSourcePolicy` would say about its specific source - blocks `init` unconditionally** with `TERRAFORM_MODULE_DEPENDENCY_GRAPH_UNRESOLVED`. This check runs BEFORE the per-source module policy check (which remains defined and tested on `TerraformSourcePolicy` itself, for the later phase that implements real module-graph governance, but is currently unreachable from the coordinator - the module-presence gate always blocks first). Proven via marker-file tests across all four module-source shapes (`Phase2b4Tests#localModuleBlocksRegardlessOfSourcePolicy`, `#localModuleStillBlocksEvenWhenAPermissivePolicyWouldOtherwiseAllowIt`, `#disallowedGitModuleSourceBlocksBeforeInitEverRuns`, `#disallowedHttpModuleSourceBlocksBeforeInitEverRuns`, `#registryModuleSourceStillBlocksInitEvenWhenSourcePolicyWouldAllowIt`).

Module sources are still fully parsed and canonicalized into `TerraformConfigSourceManifest.moduleSources()` (and from there into `TerraformInitEvidence.moduleSourcesRequested()`) even though they can never reach `init` - this is intentional forward-compatibility, not leftover dead code: a later phase implementing real transitive module resolution (recursively staged/resolved module graphs, recursive source-policy evaluation, immutable module version/package binding, controlled mirror/retrieval policy, transitive provider discovery - all Gate E concerns, §16) can build directly on this parsing/canonicalization layer rather than re-deriving it.

**Conceptual distinction worth naming explicitly:** a module source can be **PARSED** (this extractor understood it), **POLICY_ALLOWED** (`TerraformSourcePolicy.isModuleSourceAllowed` would return true for it), and yet still be **EXECUTION_UNSUPPORTED_IN_THIS_PHASE** (the module-presence gate blocks it regardless) - these are three genuinely different properties, and Phase 2B-4 satisfying the first two must never be read as satisfying the third.

## 4. Lockfile Discipline

`.terraform.lock.hcl` is treated as a security-relevant artifact, not a convenience file. `ControlledTerraformOperationCoordinator#checkLockfile` runs BEFORE and AFTER every `init` attempt:

- A symlink (or any non-regular-file) at the lockfile path is rejected outright as `TERRAFORM_LOCKFILE_INVALID` - never read as a trusted lockfile, and `init` is never launched in this case.
- `-lockfile=readonly` is always part of the init argv, expressing the intent that this phase never lets `init` silently create or change a dependency lock.
- If a lockfile existed before `init` and its content differs afterward, this is `TERRAFORM_LOCKFILE_CHANGED` and the attempt is FAILED regardless of the process's own exit code - `-lockfile=readonly` should mean this never legitimately happens.
- If the configuration declares at least one provider source and `init` reports success but no lockfile exists afterward, that is treated as `TERRAFORM_LOCKFILE_MISSING` - a fail-closed check on a combination real Terraform should not produce.
- A provider-less configuration legitimately has no lockfile at all, before or after - this is not an error.

Tested in `Phase2b4Tests`: symlink rejection, unchanged-content success, unexpected-mutation block, missing-lockfile-after-provider-declaring-init block, and the provider-less no-lockfile-needed baseline.

## 5. Provider Plugin Execution Risk / Runner-Owned CLI Config

`terraform validate`/`terraform providers schema` can load provider plugins once `init` has installed them - those plugin binaries are themselves executable dependencies. This phase never lets plugin discovery fall back to an ambient host location:

- `TerraformInitProcessEnvironmentPolicy` (a sibling of Phase 2B-3's `TerraformProcessEnvironmentPolicy`, used only for the three init-family commands) sets `TF_CLI_CONFIG_FILE`, `TF_PLUGIN_CACHE_DIR`, and `TF_DATA_DIR`, all pointing at workspace-local paths.
- `RunnerWorkspaceManager#prepareTerraformCliConfig` (trusted runner code, called by the coordinator immediately before `init` launches) actually creates the plugin cache directory and writes a minimal `terraform.rc` declaring `plugin_cache_dir` and `disable_checkpoint = true` - never a `credentials`/`provider_installation` block naming any host or path outside the workspace.
- The base environment (inherited from `TerraformProcessEnvironmentPolicy`) still clears the process environment entirely and sets `HOME`/`TMPDIR` to workspace-local paths, so `~/.terraformrc` and any ambient host Terraform credentials are unreachable by construction, not merely unused.
- No caller/repository input can influence `TF_CLI_CONFIG_FILE`, the plugin cache path, or `TF_DATA_DIR` - all three are derived only from the internally-computed workspace path.

## 6. Environment

Building on the Phase 2B-3 base (`TerraformProcessEnvironmentPolicy`: `TF_IN_AUTOMATION=true`, `TF_INPUT=0`, `CHECKPOINT_DISABLE=1`, workspace-local `HOME`/`TMPDIR`), the init-family policy adds only `TF_CLI_CONFIG_FILE`/`TF_PLUGIN_CACHE_DIR`/`TF_DATA_DIR`. `ProcessBuilder.environment().clear()` (unchanged, in `ControlledTerraformProcess`) still runs before anything is added - no `AWS_*`/`AZURE_*`/`ARM_*`/`GOOGLE_*`/`TF_TOKEN_*`/`VAULT_TOKEN`/`GITHUB_TOKEN`/`GH_TOKEN` or any other ambient credential is ever inherited, because nothing in this package ever reads `System.getenv()` at all.

## 7. Network Policy - Explicit, Not Enforced

`TerraformNetworkRequirement` (`NONE`, `PROVIDER_REGISTRY_ONLY`) is a policy/evidence value, never an enforcement mechanism - nothing in this package opens or blocks a socket. `TERRAFORM_VERSION`/`TERRAFORM_FMT_CHECK`/`TERRAFORM_SHOW_PLAN_JSON` remain `NONE` (unchanged from Phase 2B-3, since they never invoke this new machinery). `TERRAFORM_INIT` records `PROVIDER_REGISTRY_ONLY` whenever the static source scan finds at least one provider source, `NONE` otherwise; `TERRAFORM_VALIDATE`/`TERRAFORM_PROVIDERS_SCHEMA` inherit whatever value their own internally-run init step recorded. **Gate D (production runner sandboxing - OS/container-level network policy) remains open**: this value is a statement of intent for an operator/observability layer to act on, not a claim that anything actually enforces it yet.

## 8. Configuration Identity - Filename-Bound, Not Just Content-Bound

**Amended after review.** The initial implementation computed `configSha256` from the multiset of staged file CONTENTS, sorted by their own bytes. Review correctly rejected this: Terraform filenames are semantically significant - `override.tf`/`*_override.tf` files have special merge-override behavior - so two directory layouts with the same two byte sequences assigned to DIFFERENT filenames are not equivalent configurations:

```text
A: main.tf = X, override.tf = Y
B: main.tf = Y, override.tf = X
```

A content-sorted hash collapses these to the same `configSha256` (same multiset of bytes), which breaks the central binding `configSha256 → init evidence → validate evidence → provider schema evidence`: two genuinely different configurations (init would apply `A`'s override semantics one way and `B`'s the opposite way, given §3's override-precedence merge) would appear identical to every consumer of that hash.

`TerraformConfigIdentity.computeSha256(List<NamedConfigFile>)` now hashes canonical **(relative path, content) tuples**, sorted by relative path (never by content, never by insertion order): version-prefixed, then for each entry length-prefixed relative-path UTF-8 bytes followed by length-prefixed content bytes - the same unambiguous, delimiter-free encoding discipline as `RunnerRequest#fingerprintSha256()`. `NamedConfigFile.relativePath` is validated to reject absolute paths and `..` components; only relative paths are ever hashed, so identical configurations staged under two different (e.g. differently-named temp-directory) runner workspace roots always produce the SAME identity (proven by `Phase2b4Tests#sameRelativePathsAndContentProduceTheSameIdentityRegardlessOfWorkspaceRoot`). The lockfile is folded into the SAME hash as one more entry, named `.terraform.lock.hcl`, rather than a separate parameter - so a lockfile content change alone changes `configSha256` too (proven by `Phase2b4Tests#lockfileContentChangeAffectsConfigurationIdentity`/`#initEvidenceConfigIdentityChangesWhenTheLockfileContentChanges`).

The main.tf/override.tf swap collision is directly tested and proven fixed: `Phase2b4Tests#swappingContentBetweenMainAndOverrideProducesADifferentIdentity`. Also proven: `foo.tf` vs `foo.tf.json` with identical bytes produce different identities (`#sameContentUnderDotTfVersusDotTfJsonProducesDifferentIdentities`), and adding/removing/renaming a file changes the identity (`#addingRemovingOrRenamingAFileChangesTheIdentity`).

**Consequence for today's production wiring:** `ControlledRunner`'s single-artifact staging model (§10) has no genuine "original filename" to preserve - it always stages exactly one blob under the fixed constant name `"config.tf"` (`ControlledRunner.SINGLE_ARTIFACT_CONFIG_FILE_NAME`, never a caller/repository-supplied name). The filename-collision scenario above is therefore not reachable through production `ControlledRunner` calls today (there is only ever one file), but the identity function itself is now correct and tested independently at the `TerraformConfigIdentity`/coordinator level - the same "safe, tested, general-purpose primitive; production wiring happens to be narrower today" pattern already established for `RunnerWorkspaceManager#stageTerraformConfigDirectory` in Phase 2B-3.

## 9. Sequencing and the Init-Then-Validate/Schema Design Decision

The Phase 2B-4 authorization describes a sequence ending in "`validate`/`providers schema` must not run if init evidence is missing or stale for the exact same config identity." This implementation satisfies that property by **always running a full, fresh `init` internally, within the same single coordinator call**, immediately before `validate`/`providers schema` ever launch their own command - rather than looking up a separate, previously-recorded init evidence row from an earlier, independent request.

This is a deliberate design choice, not a shortcut:

- Each `ControlledRunner#execute` call is already a fully self-contained, single-shot pipeline (identity → approval → artifact → workspace → process). Introducing a durable "reuse a prior init's evidence across requests" mechanism would require a new cross-request evidence store, staleness-invalidation triggers on that store, and coupling between otherwise-independent `RunnerRequest`s - real complexity this phase's authorization does not clearly require and that was judged out of proportion to the property actually needed.
- Always running `init` fresh gives a **strictly stronger** guarantee than cross-call evidence reuse would: there is no window in which a `validate`/`providers schema` call could be satisfied by a stale, previously-recorded init result for a configuration, executable, or lockfile state that has since changed on disk - "staleness" is structurally impossible rather than merely checked for.
- `TerraformValidateEvidence`/`TerraformProviderSchemaEvidence` each embed the `TerraformInitEvidence` from the internal init attempt that gated them, so "validate/schema evidence bound to init/config" is a structural property of the record shape itself, not a separate cross-reference id that could point at the wrong thing.
- The one staleness axis that genuinely spans calls - "is this still the trusted, unchanged Terraform executable?" - is already handled by the Phase 2B-3 `VerifiedTerraformExecutable` attestation cache, reused unchanged here: `obtainVerifiedExecutable` always rechecks the executable's hash fresh on every single call, invalidating its cached version attestation the moment the hash no longer matches.

The trade-off: a `TERRAFORM_VALIDATE`/`TERRAFORM_PROVIDERS_SCHEMA` request always pays the cost of a real `init` process launch, even if an identical configuration was just initialized moments ago by a different request. This is judged acceptable for this phase (init against a small, local, provider-less-or-few-providers configuration is cheap) and strictly safer than the alternative; a future phase could introduce genuine cross-request evidence caching if the cost becomes a real problem, at which point `TERRAFORM_CONFIG_IDENTITY_MISMATCH` (already reserved in `RunnerReasonCode`, currently unreachable) would become meaningful.

## 10. Configuration Staging - Reusing the Phase 2B-3 Single-Artifact Model

`TERRAFORM_INIT`/`TERRAFORM_VALIDATE`/`TERRAFORM_PROVIDERS_SCHEMA` resolve and stage their configuration content through the exact same path `TERRAFORM_FMT_CHECK` already established: a single `planArtifactId`-resolved, hash-verified blob staged as one `.tf` file (`ControlledRunner#isTerraformConfigOperation`). This phase does **not** introduce a "repository checkout root" request-contract concept, and does **not** wire in `RunnerWorkspaceManager#stageTerraformConfigDirectory` (the safe, fully-tested, symlink-resistant multi-file staging primitive built but left unwired in Phase 2B-3) - reusing the existing single-artifact model was judged the smallest safe change consistent with `TERRAFORM_FMT_CHECK`'s own precedent, and a genuine multi-file repository-checkout staging model remains future work requiring a request-contract change beyond this phase's scope.

One direct consequence: this phase's "lockfile before init" state can never come from a caller-supplied pre-existing lockfile artifact (there is no field for one) - it can only be whatever already happens to exist in the workspace directory at call time, which for a production `ControlledRunner`-driven call is always empty before the first `init`. The lockfile-mutation-detection tests in `Phase2b4Tests` exercise the coordinator directly (not through `ControlledRunner`) and pre-populate the workspace's lockfile file directly, which is a legitimate way to test the coordinator's own lockfile-safety logic without requiring a request-contract change to do so.

## 11. Evidence Model

Three new records, each embedded as a new nullable `RunnerEvidence` field (`terraformInitEvidence`, `terraformValidateEvidence`, `terraformProviderSchemaEvidence`) - the same "embedded, not a separate ledger row" pattern `TerraformProcessEvidence` established in Phase 2B-3. Exactly one of the four Terraform evidence fields is ever non-null for a given `RunnerEvidence`.

- **`TerraformInitEvidence`**: `configSha256`, executable expected/observed hash and version, `backendMode`, `networkRequirement`, `providerSourcesRequested`/`moduleSourcesRequested` (from the static scan), `lockfileHashBefore`/`lockfileHashAfter` (null = absent), exit code, process state, reason codes, output sizes/hashes, timestamps.
- **`TerraformValidateEvidence`**: embeds the gating `initEvidence`; `valid`/`errorCount`/`warningCount`; `diagnosticFingerprints` - a SHA-256 over each diagnostic's `severity|summary|detail`, never the raw diagnostic text (which may reference repository paths/content), matching this package's established caution about not persisting tool output that could someday be sensitive.
- **`TerraformProviderSchemaEvidence`**: embeds the gating `initEvidence`; `lockfileHash` bound to the init step's own `lockfileHashAfter` (the exact lockfile state schema output was produced under); `providerSourceIdentities` (extracted from the schema JSON's own top-level keys); `schemaJsonSha256`/`schemaJsonSize` (never the raw schema content itself).

All three are durably persisted via new, additive, nullable columns (`V3__add_terraform_init_validate_schema_evidence.sql`) with hand-written JSON (de)serialization (`TerraformInitEvidenceJson`/`TerraformValidateEvidenceJson`/`TerraformProviderSchemaEvidenceJson`, the latter two reusing the first for their embedded `initEvidence` field) - the same convention as `TerraformProcessEvidenceJson`, chosen for the same reason (a fixed, small, fully-known field set; this codebase's Jackson variant is used only for tree parsing, never POJO/record binding). Round-trip persistence through a real H2 database is proven in `Phase2b4JdbcTests`.

## 12. Failure Taxonomy

New `RunnerReasonCode` values: `TERRAFORM_INIT_NOT_ALLOWED`, `TERRAFORM_INIT_FAILED`, `TERRAFORM_BACKEND_MODE_UNSAFE`, `TERRAFORM_PROVIDER_SOURCE_UNTRUSTED`, `TERRAFORM_MODULE_SOURCE_UNTRUSTED` (defined/tested on `TerraformSourcePolicy`, currently unreachable from the coordinator - see §3.2), `TERRAFORM_SOURCE_EXTRACTION_FAILED`, `TERRAFORM_PROVIDER_REQUIREMENT_IMPLICIT` (§3.1), `TERRAFORM_MODULE_DEPENDENCY_GRAPH_UNRESOLVED` (§3.2), `TERRAFORM_LOCKFILE_MISSING`, `TERRAFORM_LOCKFILE_CHANGED`, `TERRAFORM_LOCKFILE_INVALID`, `TERRAFORM_INIT_REQUIRED` (validate/schema requested without a successful internal init - not in the authorization's own list, added because the internally-run-init design needs a name for this outcome), `TERRAFORM_VALIDATE_FAILED`, `TERRAFORM_VALIDATE_OUTPUT_INVALID`, `TERRAFORM_PROVIDER_SCHEMA_FAILED`, `TERRAFORM_PROVIDER_SCHEMA_OUTPUT_INVALID`, `TERRAFORM_CONFIG_IDENTITY_MISMATCH` (reserved, unreachable under this phase's always-fresh-init design - see §9), `TERRAFORM_NETWORK_POLICY_VIOLATION` (reserved, unreachable - see §7, no enforcement exists yet to violate). No failure collapses into a generic error value.

## 13. Sole Process-Spawning Class - Preserved

`ControlledTerraformProcess` is unchanged by this phase and remains the only class in `src/main` that constructs a `ProcessBuilder` - `ProductionExecutionSurfaceTests` (whole-`src/main` scope, from the Phase 2B-3 final amendment) and the narrower, comment-stripped `Phase2b3Tests#processBuilderAppearsOnlyInControlledTerraformProcess` both still pass unmodified in substance (the latter's literal-phrase scan was extended to strip comments, since this phase's own javadoc explains "terraform init"/"terraform validate" by name in prose - no actual argv-building code ever concatenates those two words into one string; `TerraformCommandFactory` always builds `"init"`/`"validate"` as separate `List.of(...)` elements).

## 14. Test Coverage Summary

65 tests in `Phase2b4Tests`, including everything from the prior three revisions (backend-mode enforcement and argv structure; lockfile discipline; wrong-version blocks init before it runs; init failure interpretation; validate/providers-schema sequencing and outcome interpretation; configuration-identity determinism and the main.tf/override.tf collision fix; parser-backed native/JSON extraction, malformed-input and interpolated-source fail-closed behavior, override precedence; explicit-provider-declaration-required for the simple type-prefix case; unconditional module execution restriction across all four module-source shapes; full `ControlledRunner` end-to-end integration including duplicate-request replay protection) PLUS, new in this (fourth) revision, **effective provider-name resolution**: a resource with no explicit provider and a matching/missing `required_providers` entry (allowed/blocked respectively); a resource with an explicit `provider = corpaws`/`provider = corpaws.east` reference matching a `required_providers.corpaws` entry (allowed); confirmation that the resource TYPE prefix (`aws`) is NOT also required once an explicit `provider` meta-argument overrides it (`#resourceTypePrefixIsNotAlsoRequiredWhenAnExplicitProviderOverridesIt`); an explicit provider reference to a genuinely undeclared local name blocking (`#explicitProviderReferenceToAnUndeclaredLocalNameBlocksBeforeInit`); a dynamic/indexed/malformed provider reference failing extraction closed (`#malformedOrDynamicProviderReferenceFailsExtractionClosedBeforeInit`); equivalent native-syntax and JSON-syntax `import`-block provider-reference coverage (`#nativeImportBlockWithExplicitProviderIsIncludedInTheImpliedSet`, `#jsonImportBlockWithExplicitProviderIsIncludedInTheImpliedSet`); and equivalent JSON resource/data provider-override and undeclared-provider cases (`#jsonResourceWithExplicitProviderAliasIsHandledEquivalently`, `#jsonResourceWithoutExplicitProviderAndUndeclaredRequiredProviderIsFlaggedAsImplied`). Plus 2 tests in `Phase2b4JdbcTests` (real-database round-trip persistence for `TerraformValidateEvidence` and `TerraformInitEvidence`, including their embedded/nested evidence). 287 tests total across the full suite, stable across 5 fresh `--rerun-tasks` reruns.

## 15. Why `plan`/`apply` Remain Excluded

Nothing added in this phase changes the closed-enum argument from Phase 2B-3: `ControlledTerraformOperation` and `RunnerOperation` are still fixed enums with no `PLAN`/`APPLY`/`DESTROY`/etc. value, `TerraformCommandFactory` has exactly six public command-building methods (verified structurally by `Phase2b4Tests#terraformCommandFactoryBuildsExactlyTheSixAuthorizedCommandsAndNothingElse`), and there is no generic `execute(List<String>)`/`run(String...)`/`terraform(String...)` anywhere in `src/main`. `init`/`validate`/`providers schema` prepare and inspect a configuration; none of the three can generate a new plan, and none can apply, refresh, or otherwise mutate infrastructure or state. That capability boundary is unchanged by this phase.

## 16. Production Hard Gates

```text
Gate A: Approval persistence needs real PostgreSQL integration + concurrency verification. Still open.
Gate B: Runner ledger needs real PostgreSQL integration + concurrency verification. Still open.
Gate C: Runner identity needs real workload identity/OIDC, not local/reference file attestation. Still open.
Gate D: Production runner sandbox - OS/container-level isolation, resource controls, and network
policy - before infrastructure mutation authority. This phase adds an explicit network-requirement
EVIDENCE model (§7) but still implements no actual OS/container-level network enforcement. Still open.
Gate E (new): Production provider/module supply-chain GOVERNANCE, now explicitly including:
  - Recursive module dependency resolution: staging, parsing, and policy-validating a module's OWN
    downloaded contents (further modules, further providers) - the reason module blocks are entirely
    execution-deferred in this phase (§3.2), not merely a stricter policy default.
  - Immutable module version/package binding and a controlled mirror/retrieval policy for modules.
  - Provider/module signature/checksum verification beyond the lockfile-hash-before/after check this
    phase already implements.
  - Enterprise/private registry mirror allowlisting and attestation.
  - Any governance process for expanding TerraformSourcePolicy's allowlist itself.
This is explicitly NOT the same problem Phase 2B-4's source-policy enforcement (§3, §3.1) solves:
given a configuration, TerraformConfigSourceExtractor/TerraformSourcePolicy deterministically and
correctly either extracts and validates every ROOT-MODULE provider/module source (with no implicit-
resolution gap, §3.1) or fails closed - a real, mechanically-authoritative boundary for the root
module alone. What Gate E leaves open is everything a root-module boundary cannot by itself cover:
transitive dependencies introduced by a module's own contents, and supply-chain trust beyond
recognizing which source string was declared.
```
None of A/B/C/D/E is satisfied by this phase. Gate E remaining open is not a statement that root-module
source-policy enforcement is incomplete - it is a statement that (a) transitive module dependency
governance and (b) supply-chain trust beyond a source-string allowlist both remain future work, and
Phase 2B-4 deliberately keeps module blocks out of the trusted execution path rather than allowing a
partial, unsound version of that governance.

## 17. Deferred / Out of Scope

- `terraform plan`/`terraform apply` and all infrastructure/state mutation (unchanged from Phase 2B-3's own exclusions).
- Real backend initialization of any kind (`REMOTE_READONLY_INIT`/`REMOTE_ALLOWED` are modeled but not implemented).
- The full HCL expression language (functions, `for_each`/dynamic-block-generated values, conditionals) in `TerraformNativeSourceExtractor` - not needed, since anything other than an immediate string literal for a `source` attribute already fails closed regardless (§3).
- Gate E's supply-chain governance (mirrors, signature/checksum verification beyond the lockfile hash, enterprise registry allowlisting) - distinct from, and not weakened by, §3's now-authoritative root-module source-policy enforcement.
- Module execution of any kind - registry, git, HTTP, or local (§3.2). Module sources are parsed/canonicalized into evidence but any `module` block blocks `init` unconditionally until a later phase implements recursively-staged, recursively-parsed, recursively-policy-validated module dependency resolution, immutable module version/package binding, and a controlled mirror/retrieval policy (all Gate E).
- Cross-request init-evidence caching/staleness invalidation (§9's disclosed design decision - always-fresh-init is used instead, which is safer, not merely simpler).
- `RunnerWorkspaceManager#stageTerraformConfigDirectory`-based multi-file repository-checkout staging for the init family (§10 - same disclosed scope-limit as Phase 2B-3's `TERRAFORM_FMT_CHECK`).
- OS/container-level network enforcement of `TerraformNetworkRequirement` (Gate D).
- Real cloud workload identity/OIDC (Gate C, carried over unchanged).
- A production-grade durable backend (PostgreSQL) for approval and runner-ledger persistence with real concurrency validation (Gates A/B, carried over unchanged).
