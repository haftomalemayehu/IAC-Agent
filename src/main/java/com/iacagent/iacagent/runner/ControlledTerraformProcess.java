package com.iacagent.iacagent.runner;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.HexFormat;
import java.util.concurrent.TimeUnit;

/**
 * The ONLY class in this codebase that constructs a {@link ProcessBuilder} or launches an OS
 * process - verified by a source scan across the whole {@code runner} package
 * ({@code Phase2b3Tests#processBuilderAppearsOnlyInControlledTerraformProcess}). {@link #execute}
 * takes an already fully-constructed, already-validated {@link ControlledTerraformCommand}; nothing
 * here accepts a caller-supplied executable string, argument list, working directory string, or
 * environment map.
 *
 * <p>Enforces, for every launch:
 * <ul>
 *   <li>{@code pb.environment().clear()} before adding only {@code command.environment()}'s
 *       entries - {@link ProcessBuilder} starts a NEW environment map pre-populated with the
 *       current process's own environment; clearing it first is what makes "empty by default"
 *       actually true rather than aspirational.
 *   <li>stdin closed immediately after the process starts - the child sees EOF, never an inherited
 *       terminal/parent input stream, so nothing can prompt for interactive input.
 *   <li>stdout/stderr each read on a dedicated daemon thread into a bounded buffer; the process is
 *       terminated the moment either bound is exceeded rather than accumulating output without
 *       limit.
 *   <li>a finite timeout, polled alongside the output-bound check, past which the process (and its
 *       descendants, best-effort via {@link ProcessHandle}) are terminated rather than awaited
 *       indefinitely.
 * </ul>
 */
public final class ControlledTerraformProcess {

    public static final long DEFAULT_STDOUT_MAX_BYTES = 10L * 1024 * 1024; // 10 MiB
    public static final long DEFAULT_STDERR_MAX_BYTES = 2L * 1024 * 1024;  // 2 MiB

    private static final long POLL_INTERVAL_MILLIS = 20;
    private static final long DESTROY_GRACE_MILLIS = 1_000;
    private static final long READER_JOIN_GRACE_MILLIS = 2_000;

    private final long stdoutMaxBytes;
    private final long stderrMaxBytes;

    public ControlledTerraformProcess() {
        this(DEFAULT_STDOUT_MAX_BYTES, DEFAULT_STDERR_MAX_BYTES);
    }

    public ControlledTerraformProcess(long stdoutMaxBytes, long stderrMaxBytes) {
        if (stdoutMaxBytes <= 0) {
            throw new IllegalArgumentException("stdoutMaxBytes must be positive");
        }
        if (stderrMaxBytes <= 0) {
            throw new IllegalArgumentException("stderrMaxBytes must be positive");
        }
        this.stdoutMaxBytes = stdoutMaxBytes;
        this.stderrMaxBytes = stderrMaxBytes;
    }

    public TerraformProcessResult execute(ControlledTerraformCommand command) {
        Instant startedAt = Instant.now();
        ProcessBuilder builder = new ProcessBuilder(command.argv());
        builder.directory(command.workingDirectory().toFile());
        builder.environment().clear();
        builder.environment().putAll(command.environment().variables());

        Process process;
        try {
            process = builder.start();
        } catch (IOException e) {
            return new TerraformProcessResult(true, false, false, null,
                    new byte[0], 0, emptyHash(), 0, emptyHash(), startedAt, Instant.now());
        }

        try {
            process.getOutputStream().close(); // stdin: EOF immediately, never inherited input
        } catch (IOException ignored) {
            // best-effort - a process that never reads stdin may already have nothing meaningful to close
        }

        BoundedStreamReader stdoutReader = new BoundedStreamReader(process.getInputStream(), stdoutMaxBytes);
        BoundedStreamReader stderrReader = new BoundedStreamReader(process.getErrorStream(), stderrMaxBytes);
        Thread stdoutThread = startDaemon(stdoutReader);
        Thread stderrThread = startDaemon(stderrReader);

        long deadlineNanos = System.nanoTime() + command.timeout().toNanos();
        Integer exitCode = null;
        boolean timedOut = false;
        boolean outputLimitExceeded = false;
        try {
            while (true) {
                if (process.waitFor(POLL_INTERVAL_MILLIS, TimeUnit.MILLISECONDS)) {
                    exitCode = process.exitValue();
                    break;
                }
                if (stdoutReader.isOverflowed() || stderrReader.isOverflowed()) {
                    outputLimitExceeded = true;
                    break;
                }
                if (System.nanoTime() >= deadlineNanos) {
                    timedOut = true;
                    break;
                }
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            timedOut = true; // never hang on an interrupted wait - treat it as a bounded failure
        }

        if (exitCode == null) {
            destroyProcessTree(process);
            exitCode = awaitExitCodeBestEffort(process);
        }

        joinQuietly(stdoutThread);
        joinQuietly(stderrThread);

        Instant completedAt = Instant.now();
        return new TerraformProcessResult(
                false, timedOut, outputLimitExceeded, exitCode,
                stdoutReader.capturedBytes(), stdoutReader.totalBytesRead(), stdoutReader.sha256Hex(),
                stderrReader.totalBytesRead(), stderrReader.sha256Hex(),
                startedAt, completedAt);
    }

    private static Integer awaitExitCodeBestEffort(Process process) {
        try {
            process.waitFor(DESTROY_GRACE_MILLIS, TimeUnit.MILLISECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
        return process.isAlive() ? null : process.exitValue();
    }

    /**
     * Best-effort process-tree termination: descendants first (gentle, then forceful if still
     * alive after a brief grace period), then the process itself. {@link ProcessHandle} is used
     * rather than assuming the direct {@link Process} handle alone accounts for everything a
     * launched program might have spawned.
     */
    private static void destroyProcessTree(Process process) {
        ProcessHandle handle = process.toHandle();
        handle.descendants().forEach(ProcessHandle::destroy);
        handle.destroy();
        try {
            if (!process.waitFor(DESTROY_GRACE_MILLIS, TimeUnit.MILLISECONDS)) {
                handle.descendants().forEach(ProcessHandle::destroyForcibly);
                handle.destroyForcibly();
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            handle.descendants().forEach(ProcessHandle::destroyForcibly);
            handle.destroyForcibly();
        }
    }

    private static Thread startDaemon(Runnable runnable) {
        Thread thread = new Thread(runnable, "controlled-terraform-process-stream-reader");
        thread.setDaemon(true);
        thread.start();
        return thread;
    }

    private static void joinQuietly(Thread thread) {
        try {
            thread.join(READER_JOIN_GRACE_MILLIS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    private static String emptyHash() {
        return sha256Hex(new byte[0]);
    }

    private static String sha256Hex(byte[] content) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return HexFormat.of().formatHex(digest.digest(content));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 must be available on any supported JVM", e);
        }
    }

    /**
     * Reads one stream into a bounded buffer on its own thread. Once the buffer would exceed
     * {@code maxBytes}, sets {@link #isOverflowed()} and stops reading - the caller (the polling
     * loop in {@link #execute}) is responsible for terminating the process once it observes the
     * overflow flag; this reader does not terminate the process itself. {@code capturedBytes()}/
     * {@code sha256Hex()} are only safe to call after this reader's thread has terminated (enforced
     * by the {@link #execute} flow always joining before reading them - {@link Thread#join}
     * establishes the necessary happens-before edge).
     */
    private static final class BoundedStreamReader implements Runnable {
        private final InputStream in;
        private final long maxBytes;
        private final ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        private volatile boolean overflowed = false;
        private volatile long totalBytesRead = 0;

        BoundedStreamReader(InputStream in, long maxBytes) {
            this.in = in;
            this.maxBytes = maxBytes;
        }

        @Override
        public void run() {
            byte[] chunk = new byte[8192];
            try {
                int n;
                while ((n = in.read(chunk)) != -1) {
                    totalBytesRead += n;
                    if (buffer.size() + n > maxBytes) {
                        overflowed = true;
                        break;
                    }
                    buffer.write(chunk, 0, n);
                }
            } catch (IOException ignored) {
                // stream closed/broken - typically because the process was just destroyed
            }
        }

        boolean isOverflowed() {
            return overflowed;
        }

        long totalBytesRead() {
            return totalBytesRead;
        }

        byte[] capturedBytes() {
            return buffer.toByteArray();
        }

        String sha256Hex() {
            return ControlledTerraformProcess.sha256Hex(buffer.toByteArray());
        }
    }
}
