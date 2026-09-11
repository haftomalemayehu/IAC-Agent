package com.iacagent.iacagent;

import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Phase 2B-3 final amendment: the prior amendment eliminated the only Spring-reachable path into
 * the legacy generic execution engine, but left the capability itself sitting in {@code src/main}
 * (a {@code ProcessBuilder} inside {@code CommandRunner}, wired by {@code TerraformCliAdapter} and
 * {@code TerraformExecutionService}). "No live code path reaches it" is a dependency-graph property,
 * not a capability boundary - the classes could still be constructed and invoked by any future
 * production code with no compiler or structural test stopping it. That legacy stack has since been
 * deleted from {@code src/main} outright (nothing else in production code depended on it), and
 * {@code CommandRunner} was moved to {@code src/test} for {@code Phase1bTests} to keep exercising it
 * directly without it ever being part of the running application.
 *
 * <p>Unlike {@link LegacyExecutionSurfaceTests} (which scans only Spring-annotated classes in a
 * single package for references to specific legacy class names, and remains useful as a targeted
 * regression test), these tests scan the entirety of {@code src/main/java} - every package, not just
 * {@code com.iacagent.iacagent} or {@code com.iacagent.iacagent.runner} - and assert the structural
 * invariant directly: exactly one class may reference {@link ProcessBuilder}, no code may invoke
 * {@code Runtime.exec}/{@code Runtime.getRuntime().exec}, and no production method may accept a
 * generic "arbitrary executable plus argv" shape ({@code String...}, or {@code String[]}, varargs/
 * array command parameters - the exact shape the deleted {@code CommandRunner.run(String, String...)}
 * had). This is the property Phase 2B-3 actually requires:
 *
 * <pre>
 * src/main
 * └── ControlledTerraformProcess
 *         └── ProcessBuilder
 * </pre>
 */
class ProductionExecutionSurfaceTests {

    private static final Path SOURCE_ROOT = Path.of("src/main/java");
    private static final String SOLE_PROCESS_BOUNDARY_CLASS = "ControlledTerraformProcess.java";

    /** Matches a method parameter list shaped like the deleted {@code CommandRunner.run(String
     * workingDirectory, String... command)}: a leading {@code String} parameter (e.g. a working
     * directory) followed later by a {@code String...}/{@code String[]} parameter (e.g. a command
     * line) - the shape a generic "arbitrary executable plus argv" API takes. Deliberately requires
     * a leading String parameter (not just any varargs/array String parameter) so it does not flag
     * unrelated methods such as {@code main(String[] args)} (no preceding parameter) or a varargs
     * helper used for something other than a command line (e.g. trying several JSON field name
     * candidates) whose first parameter is not itself a String. This is a textual heuristic, not a
     * parser, so it errs toward flagging suspicious signatures for human review rather than silently
     * missing a reintroduced generic command surface. */
    private static final Pattern GENERIC_COMMAND_PARAMETER =
            Pattern.compile("\\(\\s*String\\s+\\w+[^)]*,\\s*(String\\.\\.\\.|String\\[])\\s+\\w+\\s*\\)");

    @Test
    void onlyTheControlledTerraformProcessClassReferencesProcessBuilder() throws IOException {
        List<Path> javaFiles = allProductionJavaFiles();
        assertFalse(javaFiles.isEmpty(), "expected to find production source under " + SOURCE_ROOT);

        for (Path file : javaFiles) {
            String content = stripJavaComments(Files.readString(file));
            boolean isTheOneAllowedProcessBoundaryClass = file.getFileName().toString().equals(SOLE_PROCESS_BOUNDARY_CLASS);
            if (isTheOneAllowedProcessBoundaryClass) {
                assertTrue(content.contains("ProcessBuilder"),
                        SOLE_PROCESS_BOUNDARY_CLASS + " is expected to be the actual process boundary and should reference ProcessBuilder");
            } else {
                assertFalse(content.contains("ProcessBuilder"),
                        file + " must not reference ProcessBuilder - " + SOLE_PROCESS_BOUNDARY_CLASS
                                + " is the sole authorized production process-spawning class");
            }
        }
    }

    @Test
    void noProductionSourceInvokesRuntimeExec() throws IOException {
        for (Path file : allProductionJavaFiles()) {
            String content = stripJavaComments(Files.readString(file));
            assertFalse(content.contains("Runtime.getRuntime().exec") || content.contains(".exec("),
                    file + " must not invoke Runtime.exec - all process spawning must go through ControlledTerraformProcess");
        }
    }

    @Test
    void noProductionMethodAcceptsAGenericExecutableAndArgvParameter() throws IOException {
        for (Path file : allProductionJavaFiles()) {
            String content = stripJavaComments(Files.readString(file));
            var matcher = GENERIC_COMMAND_PARAMETER.matcher(content);
            assertFalse(matcher.find(),
                    file + " declares a method accepting a String... / String[] parameter - a generic "
                            + "\"arbitrary executable plus argv\" surface is not permitted anywhere in src/main; "
                            + "found: " + (matcher.reset().find() ? matcher.group() : ""));
        }
    }

    @Test
    void theLegacyGenericExecutionClassesNoLongerExistUnderSrcMain() {
        for (String legacyFile : List.of("CommandRunner.java", "TerraformCliAdapter.java", "TerraformExecutionService.java")) {
            Path path = Path.of("src/main/java/com/iacagent/iacagent", legacyFile);
            assertFalse(Files.exists(path), legacyFile + " must not exist under src/main - it was deleted/moved in the Phase 2B-3 final amendment");
        }
    }

    @Test
    void exactlyOneProductionJavaFileReferencesProcessBuilder() throws IOException {
        long count = allProductionJavaFiles().stream()
                .filter(file -> {
                    try {
                        return stripJavaComments(Files.readString(file)).contains("ProcessBuilder");
                    } catch (IOException e) {
                        throw new java.io.UncheckedIOException(e);
                    }
                })
                .count();
        assertEquals(1, count, "expected exactly one production source file to reference ProcessBuilder");
    }

    private static List<Path> allProductionJavaFiles() throws IOException {
        if (!Files.isDirectory(SOURCE_ROOT)) {
            return List.of(); // not available in this execution context (e.g. packaged jar) - best-effort check
        }
        try (var files = Files.walk(SOURCE_ROOT)) {
            return files.filter(p -> p.toString().endsWith(".java")).toList();
        }
    }

    private static String stripJavaComments(String source) {
        String noBlockComments = source.replaceAll("(?s)/\\*.*?\\*/", "");
        return noBlockComments.replaceAll("(?m)//.*$", "");
    }
}
