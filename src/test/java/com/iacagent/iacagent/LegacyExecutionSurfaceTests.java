package com.iacagent.iacagent;

import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertFalse;

/**
 * Phase 2B-3 amendment history: {@code IacAgentController} used to expose a {@code /pipeline}/
 * {@code /execute-pipeline} endpoint that wired {@code TerraformExecutionService} - and,
 * transitively, {@code CommandRunner}'s unrestricted {@code String... command} + denylist-guarded
 * {@link ProcessBuilder} - into the running Spring application. That was the only reachable path
 * from the actual running control plane into a generic (non-allowlisted) execution surface,
 * directly conflicting with the invariant {@code com.iacagent.iacagent.runner}'s
 * {@code ControlledTerraformProcess} exists to establish. The endpoint was removed first (this
 * test class's original purpose); the final amendment then went further and deleted
 * {@code TerraformCliAdapter}/{@code TerraformExecutionService} from {@code src/main} entirely
 * (nothing else depended on them) and moved {@code CommandRunner} to {@code src/test} (still
 * unit-tested directly by {@code Phase1bTests}, but no longer part of {@code src/main} at all).
 *
 * <p>This class is kept even though the legacy classes no longer exist under {@code src/main}: it
 * remains a real regression test against reintroduction of a Spring-reachable reference to any of
 * these names. {@code ProductionExecutionSurfaceTests} is the broader, package-agnostic proof that
 * {@code com.iacagent.iacagent.runner.ControlledTerraformProcess} is the sole production
 * process-spawning class across all of {@code src/main}.
 */
class LegacyExecutionSurfaceTests {

    private static final List<String> SPRING_ENTRY_POINT_MARKERS = List.of(
            "@RestController", "@Controller", "@Service", "@Component", "@Configuration", "@Bean", "@SpringBootApplication");

    private static final List<String> LEGACY_EXECUTION_CLASSES = List.of("CommandRunner", "TerraformCliAdapter", "TerraformExecutionService");

    @Test
    void noSpringWiredClassReferencesTheLegacyExecutionEngine() throws IOException {
        Path sourceDir = Path.of("src/main/java/com/iacagent/iacagent");
        if (!Files.isDirectory(sourceDir)) {
            return; // not available in this execution context - best-effort, matches the runner package's own scans
        }
        // depth 1: only this package's own classes, not the runner subsystem or the model package.
        try (var files = Files.walk(sourceDir, 1)) {
            for (Path file : files.filter(p -> p.toString().endsWith(".java")).toList()) {
                // Comments stripped before scanning - this class's own javadoc explains the legacy
                // classes BY NAME (clearer documentation than avoiding the name), which would
                // otherwise trip a naive scan of raw file content; same lesson already recorded in
                // the runner package's Phase 2B-2 System.getenv() source scan.
                String content = stripJavaComments(Files.readString(file));
                boolean isSpringEntryPoint = SPRING_ENTRY_POINT_MARKERS.stream().anyMatch(content::contains);
                if (!isSpringEntryPoint) {
                    continue;
                }
                for (String legacyClass : LEGACY_EXECUTION_CLASSES) {
                    assertFalse(content.contains(legacyClass),
                            file + " is a Spring-registered entry point and must not reference " + legacyClass
                                    + " - that would reopen a path from the running application into the legacy execution engine");
                }
            }
        }
    }

    @Test
    void theApplicationMainClassAndItsOnlyRestControllerDoNotReferenceTheLegacyExecutionEngine() throws IOException {
        for (String entryPointFile : List.of("IacAgentApplication.java", "IacAgentController.java")) {
            Path path = Path.of("src/main/java/com/iacagent/iacagent", entryPointFile);
            if (!Files.exists(path)) {
                continue;
            }
            String content = stripJavaComments(Files.readString(path));
            for (String legacyClass : LEGACY_EXECUTION_CLASSES) {
                assertFalse(content.contains(legacyClass), entryPointFile + " must not reference " + legacyClass);
            }
        }
    }

    private static String stripJavaComments(String source) {
        String noBlockComments = source.replaceAll("(?s)/\\*.*?\\*/", "");
        return noBlockComments.replaceAll("(?m)//.*$", "");
    }
}
