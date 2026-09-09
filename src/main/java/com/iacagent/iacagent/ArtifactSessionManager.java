package com.iacagent.iacagent;

import tools.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

public class ArtifactSessionManager {
    private static final ObjectMapper MAPPER = new ObjectMapper();

    public Path createSessionDirectory(String requestId) throws IOException {
        Path path = Path.of(".agent", "sessions", requestId);
        Files.createDirectories(path);
        return path;
    }

    public void saveJson(Path sessionDirectory, String fileName, Object value) throws IOException {
        Files.writeString(sessionDirectory.resolve(fileName), MAPPER.writeValueAsString(value));
    }

    public void saveText(Path sessionDirectory, String fileName, String content) throws IOException {
        Files.writeString(sessionDirectory.resolve(fileName), content);
    }
}
