package com.iacagent.iacagent.identity;

import com.auth0.jwk.Jwk;
import com.auth0.jwk.JwkException;
import com.auth0.jwk.JwkProvider;
import com.auth0.jwk.SigningKeyNotFoundException;
import tools.jackson.databind.ObjectMapper;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URL;
import java.util.List;
import java.util.Map;

/**
 * Fetches a JWKS document over HTTPS from the ONE fixed, trusted URI configured in
 * {@link WorkloadIdentityVerifierConfig#jwksUri()} - never a URI derived from a token's own claims
 * or any caller-supplied value, which is what closes the SSRF surface a "trust the token's own
 * {@code jku}/issuer-metadata-URL" design would otherwise open.
 *
 * <p>{@code com.auth0:jwks-rsa}'s own {@code UrlJwkProvider} does not bound response size, so this
 * class exists specifically to add that bound (a plain network-I/O concern, not cryptography - the
 * actual signature verification stays entirely inside the mature library, per the "do not write
 * custom RSA/ECDSA signature verification primitives" directive). Every other bound (connect/read
 * timeout, key caching, kid lookup, unknown-kid-refresh-once-then-fail-closed) comes from wrapping
 * this class in {@code com.auth0.jwk.GuavaCachedJwkProvider} - see {@link GitHubActionsOidcVerifier}.
 *
 * <p>Redirects are explicitly refused (never followed) - a compromised or misbehaving JWKS endpoint
 * must not be able to redirect this fetch to an untrusted host/scheme.
 */
final class BoundedHttpsJwkProvider implements JwkProvider {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private final WorkloadIdentityVerifierConfig config;

    BoundedHttpsJwkProvider(WorkloadIdentityVerifierConfig config) {
        if (config == null) {
            throw new IllegalArgumentException("config is required");
        }
        this.config = config;
    }

    @Override
    public Jwk get(String keyId) throws JwkException {
        Map<String, Object> document = fetchDocument();
        Object keysRaw = document.get("keys");
        if (!(keysRaw instanceof List<?> keys)) {
            throw new SigningKeyNotFoundException("JWKS document at " + config.jwksUri() + " has no 'keys' array", null);
        }
        for (Object entry : keys) {
            if (entry instanceof Map<?, ?> rawKey) {
                @SuppressWarnings("unchecked")
                Map<String, Object> keyMap = (Map<String, Object>) rawKey;
                Object kid = keyMap.get("kid");
                if (kid != null && kid.toString().equals(keyId)) {
                    return Jwk.fromValues(keyMap);
                }
            }
        }
        throw new SigningKeyNotFoundException("No key found in JWKS at " + config.jwksUri() + " for kid=" + keyId, null);
    }

    private Map<String, Object> fetchDocument() throws JwkException {
        HttpURLConnection connection = null;
        try {
            URI uri = URI.create(config.jwksUri());
            if (!"https".equalsIgnoreCase(uri.getScheme())) {
                throw new SigningKeyNotFoundException("jwksUri is not HTTPS: " + config.jwksUri(), null);
            }
            URL url = uri.toURL();
            connection = (HttpURLConnection) url.openConnection();
            connection.setRequestMethod("GET");
            connection.setInstanceFollowRedirects(false); // never follow a redirect to an untrusted host/scheme
            connection.setConnectTimeout((int) config.jwksConnectTimeout().toMillis());
            connection.setReadTimeout((int) config.jwksReadTimeout().toMillis());
            connection.setRequestProperty("Accept", "application/json");
            int status = connection.getResponseCode();
            if (status != 200) {
                throw new SigningKeyNotFoundException("JWKS endpoint returned HTTP " + status + " for " + config.jwksUri(), null);
            }
            byte[] body;
            try (InputStream in = connection.getInputStream()) {
                body = readBounded(in, config.jwksMaxResponseBytes());
            }
            @SuppressWarnings("unchecked")
            Map<String, Object> parsed = MAPPER.readValue(body, Map.class);
            return parsed;
        } catch (IOException | RuntimeException e) {
            throw new SigningKeyNotFoundException("failed to fetch JWKS from " + config.jwksUri(), e);
        } finally {
            if (connection != null) {
                connection.disconnect();
            }
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
                throw new IOException("JWKS response exceeded the configured maximum of " + maxBytes + " bytes");
            }
            buffer.write(chunk, 0, n);
        }
        return buffer.toByteArray();
    }
}
