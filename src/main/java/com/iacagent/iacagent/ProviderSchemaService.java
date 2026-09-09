package com.iacagent.iacagent;

import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

public class ProviderSchemaService {
    private static final ObjectMapper MAPPER = new ObjectMapper();

    private final Path cachePath;

    public ProviderSchemaService(String workingDirectory) {
        this.cachePath = Path.of(workingDirectory, ".agent", "cache", "provider-schema.json");
    }

    public void cache(String schemaJson) throws IOException {
        Files.createDirectories(cachePath.getParent());
        Files.writeString(cachePath, schemaJson);
    }

    public JsonNode readSchema() throws IOException {
        if (!Files.exists(cachePath)) {
            throw new IOException("Provider schema not cached at " + cachePath);
        }
        return MAPPER.readTree(cachePath.toFile());
    }

    public boolean resourceExists(String provider, String resourceType) {
        try {
            JsonNode schema = readSchema();
            JsonNode providerSchemas = schema.path("provider_schemas");
            JsonNode providerSchema = providerSchemas.path(provider);
            JsonNode resourceSchemas = providerSchema.path("resource_schemas");
            return resourceSchemas.has(resourceType);
        } catch (IOException e) {
            return false;
        }
    }

    public boolean attributeExists(String resourceType, String attributeName) {
        try {
            JsonNode schema = readSchema();
            JsonNode providerSchemas = schema.path("provider_schemas");

            for (JsonNode providerSchema : providerSchemas) {
                JsonNode resourceSchemas = providerSchema.path("resource_schemas");
                JsonNode resourceSchema = resourceSchemas.path(resourceType);
                JsonNode block = resourceSchema.path("block");
                JsonNode attrs = block.path("attributes");
                if (attrs.has(attributeName)) {
                    return true;
                }
            }
        } catch (IOException e) {
            return false;
        }
        return false;
    }

    public boolean isSchemaVerified() {
        try {
            JsonNode schema = readSchema();
            return schema.has("provider_schemas") && !schema.path("provider_schemas").isMissingNode();
        } catch (IOException e) {
            return false;
        }
    }

    public String schemaVerificationReason(String provider, String resourceType, String attributeName) {
        if (!isSchemaVerified()) {
            return "SCHEMA_UNVERIFIED";
        }
        if (provider != null && !resourceExists(provider, resourceType)) {
            return "UNKNOWN_RESOURCE_TYPE";
        }
        if (attributeName != null && !attributeExists(resourceType, attributeName)) {
            return "UNKNOWN_RESOURCE_ATTRIBUTE";
        }
        return "SCHEMA_VERIFIED";
    }
}
