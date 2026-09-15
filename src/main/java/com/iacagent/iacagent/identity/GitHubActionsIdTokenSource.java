package com.iacagent.iacagent.identity;

import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.time.Duration;

/**
 * Real production {@link WorkloadIdentityTokenSource} for a runner executing inside a GitHub
 * Actions job with {@code id-token: write} permission granted. Reads the two ambient environment
 * variables GitHub's own Actions runtime populates for exactly this purpose -
 * {@code ACTIONS_ID_TOKEN_REQUEST_URL} (where to ask) and {@code ACTIONS_ID_TOKEN_REQUEST_TOKEN}
 * (a short-lived bearer credential authorizing the ask, scoped to this specific job) - and performs
 * the same HTTPS request GitHub's own {@code @actions/core.getIDToken()} helper makes. This class
 * never invents the request; it never accepts these values from a {@link com.iacagent.iacagent.runner.RunnerRequest}
 * field or any other caller-supplied source; both env vars come only from the ambient GitHub Actions
 * runtime.
 *
 * <p>Neither the request token nor the minted ID token is ever logged, persisted, or included in any
 * exception message this class throws.
 */
public final class GitHubActionsIdTokenSource implements WorkloadIdentityTokenSource {

    private static final String REQUEST_URL_ENV = "ACTIONS_ID_TOKEN_REQUEST_URL";
    private static final String REQUEST_TOKEN_ENV = "ACTIONS_ID_TOKEN_REQUEST_TOKEN";
    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final long MAX_RESPONSE_BYTES = 64 * 1024;

    private final Duration connectTimeout;
    private final Duration readTimeout;

    public GitHubActionsIdTokenSource() {
        this(Duration.ofSeconds(10), Duration.ofSeconds(10));
    }

    public GitHubActionsIdTokenSource(Duration connectTimeout, Duration readTimeout) {
        if (connectTimeout == null || connectTimeout.isNegative() || connectTimeout.isZero()) {
            throw new IllegalArgumentException("connectTimeout must be positive");
        }
        if (readTimeout == null || readTimeout.isNegative() || readTimeout.isZero()) {
            throw new IllegalArgumentException("readTimeout must be positive");
        }
        this.connectTimeout = connectTimeout;
        this.readTimeout = readTimeout;
    }

    @Override
    public String currentToken(String audience) {
        if (audience == null || audience.isBlank()) {
            throw new IllegalArgumentException("audience is required");
        }
        String requestUrl = System.getenv(REQUEST_URL_ENV);
        String requestToken = System.getenv(REQUEST_TOKEN_ENV);
        if (requestUrl == null || requestUrl.isBlank() || requestToken == null || requestToken.isBlank()) {
            throw new WorkloadIdentityTokenUnavailableException(
                    "GitHub Actions OIDC environment is not present (missing " + REQUEST_URL_ENV + "/" + REQUEST_TOKEN_ENV
                            + ") - this job likely lacks 'id-token: write' permission, or is not running inside GitHub Actions at all");
        }
        try {
            URI uri = URI.create(requestUrl + (requestUrl.contains("?") ? "&" : "?") + "audience=" + java.net.URLEncoder.encode(audience, StandardCharsets.UTF_8));
            if (!"https".equalsIgnoreCase(uri.getScheme())) {
                throw new WorkloadIdentityTokenUnavailableException("ACTIONS_ID_TOKEN_REQUEST_URL is not HTTPS");
            }
            URL url = uri.toURL();
            HttpURLConnection connection = (HttpURLConnection) url.openConnection();
            connection.setRequestMethod("GET");
            connection.setInstanceFollowRedirects(false);
            connection.setConnectTimeout((int) connectTimeout.toMillis());
            connection.setReadTimeout((int) readTimeout.toMillis());
            connection.setRequestProperty("Authorization", "bearer " + requestToken);
            connection.setRequestProperty("Accept", "application/json");
            int status = connection.getResponseCode();
            if (status != 200) {
                throw new WorkloadIdentityTokenUnavailableException("GitHub Actions OIDC token endpoint returned HTTP " + status);
            }
            byte[] body = readBounded(connection.getInputStream(), MAX_RESPONSE_BYTES);
            JsonNode root = MAPPER.readTree(body);
            JsonNode value = root.path("value");
            if (!value.isTextual() || value.asString().isBlank()) {
                throw new WorkloadIdentityTokenUnavailableException("GitHub Actions OIDC token endpoint response had no usable 'value' field");
            }
            return value.asString();
        } catch (IOException e) {
            throw new WorkloadIdentityTokenUnavailableException("failed to obtain a GitHub Actions OIDC token", e);
        }
    }

    private static byte[] readBounded(InputStream in, long maxBytes) throws IOException {
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        byte[] chunk = new byte[8192];
        long total = 0;
        int n;
        while ((n = in.read(chunk)) != -1) {
            total += n;
            if (total > maxBytes) {
                throw new IOException("GitHub Actions OIDC token response exceeded the maximum of " + maxBytes + " bytes");
            }
            buffer.write(chunk, 0, n);
        }
        return buffer.toByteArray();
    }
}
