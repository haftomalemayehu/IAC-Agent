package com.iacagent.iacagent;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

public class CommandRunner {
    private static final Pattern SECRET_PATTERN = Pattern.compile("(?i)(aws_access_key_id|aws_secret_access_key|secret|token|password|private[_ -]?key|api[_ -]?key)\\s*[:=]\\s*([^\\s\"']+)");

    public CommandResult run(String workingDirectory, String... command) {
        if (command == null || command.length == 0) {
            String time = Instant.now().toString();
            return new CommandResult("", 127, "", "", time, time, ValidationState.BLOCKED, "No command supplied");
        }

        String startedAt = Instant.now().toString();
        try {
            ProcessBuilder processBuilder = new ProcessBuilder(command);
            if (workingDirectory != null && !workingDirectory.isBlank()) {
                processBuilder.directory(Path.of(workingDirectory).toFile());
            }

            Process process = processBuilder.start();
            String stdout = readStream(process.getInputStream());
            String stderr = readStream(process.getErrorStream());
            int exitCode = process.waitFor();

            String finishedAt = Instant.now().toString();
            ValidationState status = exitCode == 0 ? ValidationState.PASS : ValidationState.FAIL;
            return new CommandResult(String.join(" ", command), exitCode, redact(stdout), redact(stderr), startedAt, finishedAt, status, null);
        } catch (IOException e) {
            String finishedAt = Instant.now().toString();
            return new CommandResult(String.join(" ", command), 127, "", redact(e.getMessage()), startedAt, finishedAt, ValidationState.BLOCKED, e.getMessage());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            String finishedAt = Instant.now().toString();
            return new CommandResult(String.join(" ", command), 1, "", redact(e.getMessage()), startedAt, finishedAt, ValidationState.FAIL, e.getMessage());
        }
    }

    public String redact(String raw) {
        if (raw == null || raw.isBlank()) {
            return raw;
        }
        return SECRET_PATTERN.matcher(raw).replaceAll("$1=[REDACTED]");
    }

    public boolean isForbidden(String command) {
        if (command == null) {
            return false;
        }
        String lower = command.toLowerCase();
        return lower.contains("terraform destroy")
                || lower.contains("terraform apply -auto-approve")
                || lower.contains("terraform state rm")
                || lower.contains("terraform state mv")
                || lower.contains("terraform force-unlock")
                || lower.contains("terraform import");
    }

    public CommandResult guard(String workingDirectory, String... command) {
        String commandText = String.join(" ", command);
        if (isForbidden(commandText)) {
            String time = Instant.now().toString();
            return new CommandResult(commandText, 1, "", "Forbidden command rejected by policy.", time, time, ValidationState.BLOCKED, "Forbidden command rejected by policy.");
        }
        return run(workingDirectory, command);
    }

    private String readStream(java.io.InputStream inputStream) throws IOException {
        StringBuilder output = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream, StandardCharsets.UTF_8))) {
            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line).append(System.lineSeparator());
            }
        }
        return output.toString();
    }
}
