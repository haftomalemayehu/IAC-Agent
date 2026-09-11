package com.iacagent.iacagent.runner;

import java.nio.file.Path;

/**
 * Builds the {@link ProcessEnvironment} a future controlled process would receive for a given
 * request and workspace. Implementations MUST start from nothing and add only explicitly
 * permitted entries - never read {@code System.getenv()} and filter it down. The difference
 * matters: a filter-down approach silently propagates whatever the host process happened to have,
 * including anything a future host environment change adds; a build-up-from-empty approach can
 * only ever contain what this code explicitly wrote.
 */
public interface ProcessEnvironmentPolicy {
    ProcessEnvironment buildFor(RunnerRequest request, Path workspace);
}
