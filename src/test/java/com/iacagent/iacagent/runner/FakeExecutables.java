package com.iacagent.iacagent.runner;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.Set;

/**
 * Test-only fake executables for Phase 2B-3 process-boundary tests - small POSIX shell scripts
 * with a shebang line, written to disk and marked executable. Invoking one of these via
 * {@code ProcessBuilder(List.of(scriptPath))} (never {@code ProcessBuilder(List.of("/bin/sh", "-c", ...))})
 * is NOT "this codebase invokes a shell": the OS kernel itself reads the shebang and execs the
 * interpreter, exactly as it would for a real compiled Terraform binary - our code never
 * constructs or passes a shell command string anywhere. Scripts are written using ONLY POSIX shell
 * builtins ({@code echo}, {@code read}, {@code exit}, arithmetic/`[` test expressions) wherever a
 * test needs to run under a deliberately-empty (no PATH) process environment, so a missing PATH
 * cannot cause a fixture itself to fail for the wrong reason.
 */
final class FakeExecutables {

    private FakeExecutables() {
    }

    /** Writes {@code script} (a full POSIX shell script body, including its own shebang line) to
     * {@code dir}/{@code name}, makes it executable, and returns its path. */
    static Path write(Path dir, String name, String script) throws IOException {
        Path path = dir.resolve(name);
        Files.writeString(path, script, StandardCharsets.UTF_8);
        Set<PosixFilePermission> perms = PosixFilePermissions.fromString("rwxr-xr-x");
        try {
            Files.setPosixFilePermissions(path, perms);
        } catch (UnsupportedOperationException e) {
            // non-POSIX filesystem - best effort, matches the rest of this codebase's convention
        }
        return path;
    }

    /** Emits {@code terraform version -json}-shaped output and exits with {@code exitCode}. */
    static Path versionJson(Path dir, String name, String terraformVersion, int exitCode) throws IOException {
        String script = "#!/bin/sh\n"
                + "echo '{\"terraform_version\":\"" + terraformVersion + "\",\"platform\":\"test\"}'\n"
                + "exit " + exitCode + "\n";
        return write(dir, name, script);
    }

    /**
     * A fake "terraform" that responds to {@code version -json} (checked by inspecting {@code $1})
     * with a fixed reported version and exit code, and responds to any OTHER invocation with an
     * arbitrary caller-supplied shell script body. Needed because {@code TERRAFORM_FMT_CHECK}/
     * {@code TERRAFORM_SHOW_PLAN_JSON} must now pass a version-attestation check (which internally
     * launches {@code version -json} against this same binary) before their own requested command
     * ever runs - a fixture that behaves identically regardless of argv can no longer stand in for
     * "terraform" in tests of those two operations.
     */
    static Path terraformStub(Path dir, String name, String reportedVersion, int versionExitCode, String otherwiseScriptBody) throws IOException {
        String script = "#!/bin/sh\n"
                + "if [ \"$1\" = \"version\" ]; then\n"
                + "  echo '{\"terraform_version\":\"" + reportedVersion + "\"}'\n"
                + "  exit " + versionExitCode + "\n"
                + "fi\n"
                + otherwiseScriptBody;
        return write(dir, name, script);
    }

    /** Emits deliberately-malformed JSON on stdout and exits 0. */
    static Path malformedJson(Path dir, String name) throws IOException {
        return write(dir, name, "#!/bin/sh\necho '{ not valid json'\nexit 0\n");
    }

    /** Emits arbitrary valid JSON (not necessarily {@code version -json} shaped) - used for
     * {@code show -json}-style success tests. */
    static Path validJson(Path dir, String name, String json, int exitCode) throws IOException {
        String script = "#!/bin/sh\n" + "echo '" + json.replace("'", "'\\''") + "'\n" + "exit " + exitCode + "\n";
        return write(dir, name, script);
    }

    /** Exits immediately with {@code exitCode}, no output - for exit-code interpretation tests. */
    static Path exitWith(Path dir, String name, int exitCode) throws IOException {
        return write(dir, name, "#!/bin/sh\nexit " + exitCode + "\n");
    }

    /** Busy-waits (pure shell arithmetic - no external {@code sleep}, so no PATH is required) for
     * approximately {@code iterations} loop cycles - used for timeout tests, where the exact
     * wall-clock duration doesn't matter as long as it reliably exceeds the configured timeout. */
    static Path busyWait(Path dir, String name, long iterations) throws IOException {
        String script = "#!/bin/sh\n"
                + "i=0\n"
                + "while [ $i -lt " + iterations + " ]; do\n"
                + "  i=$((i+1))\n"
                + "done\n"
                + "exit 0\n";
        return write(dir, name, script);
    }

    /** Writes {@code lineCount} copies of {@code line} to stdout (if {@code toStderr} is false) or
     * stderr (if true) using only the {@code echo} builtin - no external {@code yes}/{@code head}. */
    static Path largeOutput(Path dir, String name, String line, int lineCount, boolean toStderr) throws IOException {
        String redirect = toStderr ? " 1>&2" : "";
        String script = "#!/bin/sh\n"
                + "i=0\n"
                + "while [ $i -lt " + lineCount + " ]; do\n"
                + "  echo '" + line + "'" + redirect + "\n"
                + "  i=$((i+1))\n"
                + "done\n"
                + "exit 0\n";
        return write(dir, name, script);
    }

    /** Reads one line from stdin with the {@code read} builtin; if it gets EOF immediately (no
     * data at all), prints {@code STDIN_EOF}; otherwise prints {@code STDIN_GOT_DATA}. Used to
     * prove stdin is closed/EOF rather than inherited. */
    static Path stdinProbe(Path dir, String name) throws IOException {
        String script = "#!/bin/sh\n"
                + "if read line; then\n"
                + "  echo STDIN_GOT_DATA\n"
                + "else\n"
                + "  echo STDIN_EOF\n"
                + "fi\n"
                + "exit 0\n";
        return write(dir, name, script);
    }

    /** Prints a fixed, known set of environment variable references (via shell variable expansion,
     * never an external {@code env}/{@code printenv} command that would itself need PATH) - one
     * per line, as {@code NAME=value} (empty string if unset). Used to prove exactly which
     * variables actually reached the process. */
    static Path envDump(Path dir, String name, String... variableNames) throws IOException {
        StringBuilder script = new StringBuilder("#!/bin/sh\n");
        for (String variable : variableNames) {
            script.append("echo \"").append(variable).append("=${").append(variable).append("}\"\n");
        }
        script.append("exit 0\n");
        return write(dir, name, script.toString());
    }

    /**
     * A fake "terraform" that dispatches on {@code $1}/{@code $2} across the full Phase 2B-4
     * operation set: {@code version}, {@code init}, {@code validate}, and {@code providers schema} -
     * each given its own caller-supplied script body (which must include its own {@code exit N}).
     * Any other invocation exits 1. Needed because {@code TERRAFORM_INIT}/{@code TERRAFORM_VALIDATE}/
     * {@code TERRAFORM_PROVIDERS_SCHEMA} must pass the same version-attestation gate as
     * {@code TERRAFORM_FMT_CHECK}/{@code TERRAFORM_SHOW_PLAN_JSON} before their own requested
     * command ever runs, and validate/providers-schema additionally run a real internal
     * {@code init} step first.
     */
    static Path terraformInitStub(Path dir, String name, String reportedVersion,
                                   String initScriptBody, String validateScriptBody, String providersSchemaScriptBody) throws IOException {
        String script = "#!/bin/sh\n"
                + "if [ \"$1\" = \"version\" ]; then\n"
                + "  echo '{\"terraform_version\":\"" + reportedVersion + "\"}'\n"
                + "  exit 0\n"
                + "fi\n"
                + "if [ \"$1\" = \"init\" ]; then\n"
                + initScriptBody + "\n"
                + "fi\n"
                + "if [ \"$1\" = \"validate\" ]; then\n"
                + validateScriptBody + "\n"
                + "fi\n"
                + "if [ \"$1\" = \"providers\" ] && [ \"$2\" = \"schema\" ]; then\n"
                + providersSchemaScriptBody + "\n"
                + "fi\n"
                + "exit 1\n";
        return write(dir, name, script);
    }

    /**
     * A fake "terraform" covering the Phase 2B-5 {@code TERRAFORM_PLAN} operation set: {@code version},
     * {@code init} (against a real backend - the fixture does not care whether {@code -backend=false}
     * was passed, since it never actually touches a backend), {@code plan}, and {@code show}. The
     * {@code plan} branch parses {@code -out=<path>} out of its own argv (exactly as real Terraform
     * would receive it) and exposes it to {@code planScriptBody} as the shell variable
     * {@code $outpath}, so a test's script body can write (or deliberately not write) plan bytes
     * there before exiting with whatever code it needs to simulate
     * ({@code -detailed-exitcode}'s {@code 0}/{@code 2}, or a real failure).
     */
    static Path terraformPlanStub(Path dir, String name, String reportedVersion,
                                   String initScriptBody, String planScriptBody, String showScriptBody) throws IOException {
        String script = "#!/bin/sh\n"
                + "if [ \"$1\" = \"version\" ]; then\n"
                + "  echo '{\"terraform_version\":\"" + reportedVersion + "\"}'\n"
                + "  exit 0\n"
                + "fi\n"
                + "if [ \"$1\" = \"init\" ]; then\n"
                + initScriptBody + "\n"
                + "fi\n"
                + "if [ \"$1\" = \"plan\" ]; then\n"
                + "  outpath=\"\"\n"
                + "  for arg in \"$@\"; do\n"
                + "    case \"$arg\" in\n"
                + "      -out=*) outpath=\"${arg#-out=}\" ;;\n"
                + "    esac\n"
                + "  done\n"
                + planScriptBody + "\n"
                + "fi\n"
                + "if [ \"$1\" = \"show\" ]; then\n"
                + showScriptBody + "\n"
                + "fi\n"
                + "exit 1\n";
        return write(dir, name, script);
    }

    static String sha256Hex(Path file) throws IOException {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return HexFormat.of().formatHex(digest.digest(Files.readAllBytes(file)));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 must be available on any supported JVM", e);
        }
    }
}
