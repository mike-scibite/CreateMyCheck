package com.example.github;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Minimal GitHub App REST client for posting a normal PR timeline comment.
 *
 * <p>The authentication chain is:</p>
 * <ol>
 *   <li>Sign a short-lived app JWT with the app's RSA private key.</li>
 *   <li>Resolve the app installation for the target repository.</li>
 *   <li>Exchange the JWT for a repository-scoped installation token.</li>
 *   <li>POST an issue comment (GitHub models PR timeline comments as issue comments).</li>
 * </ol>
 *
 * <p>Neither the JWT nor installation token is printed.</p>
 */
public final class GitHubAppCommenter {
    private static final ObjectMapper JSON = new ObjectMapper();
    private static final Base64.Encoder BASE64_URL = Base64.getUrlEncoder().withoutPadding();

    private final HttpClient http = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(15))
            .build();
    private final URI apiBase;

    private GitHubAppCommenter(URI apiBase) {
        this.apiBase = apiBase;
    }

    public static void main(String[] rawArgs) throws Exception {
        Config config = Config.parse(rawArgs);
        GitHubAppCommenter client = new GitHubAppCommenter(config.apiBase());

        System.out.printf("Repository: %s/%s, PR: #%d%n", config.owner(), config.repo(), config.prNumber());
        System.out.printf("App ID: %s; token permission requested: %s:write%n",
                config.appId(), config.tokenPermission());

        PrivateKey privateKey = readPrivateKey(config.privateKey());
        String jwt = createJwt(config.appId(), privateKey);
        System.out.println("1/4 App JWT signed locally (value intentionally hidden).");

        JsonNode installation = client.get(
                "/repos/%s/%s/installation".formatted(config.owner(), config.repo()), jwt);
        long installationId = requiredLong(installation, "id");
        System.out.printf("2/4 Installation %d found; granted permissions: %s%n",
                installationId, installation.path("permissions"));

        ObjectNode tokenRequest = JSON.createObjectNode();
        tokenRequest.putArray("repositories").add(config.repo());
        tokenRequest.putObject("permissions").put(config.tokenPermission(), "write");
        JsonNode tokenResponse = client.post(
                "/app/installations/%d/access_tokens".formatted(installationId), jwt, tokenRequest);
        String installationToken = requiredText(tokenResponse, "token");
        System.out.printf("3/4 Installation token created; effective permissions: %s; expires: %s%n",
                tokenResponse.path("permissions"), tokenResponse.path("expires_at").asText("unknown"));

        if (config.dryRun()) {
            System.out.println("4/4 Dry run requested; no PR comment was created.");
            return;
        }

        ObjectNode commentRequest = JSON.createObjectNode().put("body", config.body());
        JsonNode comment = client.post(
                "/repos/%s/%s/issues/%d/comments".formatted(
                        config.owner(), config.repo(), config.prNumber()),
                installationToken,
                commentRequest);
        System.out.printf("4/4 Comment created: %s%n", requiredText(comment, "html_url"));
    }

    private JsonNode get(String path, String bearerToken) throws IOException, InterruptedException {
        HttpRequest request = request(path, bearerToken).GET().build();
        return send(request);
    }

    private JsonNode post(String path, String bearerToken, JsonNode body)
            throws IOException, InterruptedException {
        HttpRequest request = request(path, bearerToken)
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(JSON.writeValueAsString(body)))
                .build();
        return send(request);
    }

    private HttpRequest.Builder request(String path, String bearerToken) {
        URI endpoint = URI.create(apiBase.toString().replaceFirst("/+$", "") + path);
        return HttpRequest.newBuilder(endpoint)
                .timeout(Duration.ofSeconds(30))
                .header("Accept", "application/vnd.github+json")
                .header("Authorization", "Bearer " + bearerToken)
                .header("X-GitHub-Api-Version", "2026-03-10")
                .header("User-Agent", "CreateMyCheck-local-debugger");
    }

    private JsonNode send(HttpRequest request) throws IOException, InterruptedException {
        HttpResponse<String> response = http.send(request, HttpResponse.BodyHandlers.ofString());
        JsonNode body = response.body().isBlank()
                ? JSON.createObjectNode()
                : JSON.readTree(response.body());
        if (response.statusCode() < 200 || response.statusCode() >= 300) {
            String acceptedPermissions = response.headers()
                    .firstValue("x-accepted-github-permissions")
                    .orElse("not supplied");
            throw new IOException("GitHub API %s %s returned HTTP %d%n"
                    .formatted(request.method(), request.uri(), response.statusCode())
                    + "x-accepted-github-permissions: " + acceptedPermissions + System.lineSeparator()
                    + "response: " + body.toPrettyString());
        }
        return body;
    }

    private static String createJwt(String appId, PrivateKey privateKey) throws Exception {
        long now = Instant.now().getEpochSecond();
        ObjectNode header = JSON.createObjectNode().put("alg", "RS256").put("typ", "JWT");
        ObjectNode claims = JSON.createObjectNode()
                .put("iat", now - 60)
                .put("exp", now + 540)
                .put("iss", appId);
        String unsigned = encodeJson(header) + "." + encodeJson(claims);

        Signature signer = Signature.getInstance("SHA256withRSA");
        signer.initSign(privateKey);
        signer.update(unsigned.getBytes(StandardCharsets.US_ASCII));
        return unsigned + "." + BASE64_URL.encodeToString(signer.sign());
    }

    private static String encodeJson(JsonNode value) throws IOException {
        return BASE64_URL.encodeToString(JSON.writeValueAsBytes(value));
    }

    private static PrivateKey readPrivateKey(Path path) throws Exception {
        String pem = Files.readString(path, StandardCharsets.US_ASCII);
        byte[] der;
        if (pem.contains("-----BEGIN RSA PRIVATE KEY-----")) {
            der = decodePem(pem, "RSA PRIVATE KEY");
            der = wrapPkcs1AsPkcs8(der);
        } else if (pem.contains("-----BEGIN PRIVATE KEY-----")) {
            der = decodePem(pem, "PRIVATE KEY");
        } else {
            throw new IllegalArgumentException("Unsupported PEM format in " + path
                    + "; expected RSA PRIVATE KEY or PRIVATE KEY");
        }
        return KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(der));
    }

    private static byte[] decodePem(String pem, String label) {
        String encoded = pem
                .replace("-----BEGIN " + label + "-----", "")
                .replace("-----END " + label + "-----", "")
                .replaceAll("\\s", "");
        return Base64.getDecoder().decode(encoded);
    }

    /** Wraps a PKCS#1 RSAPrivateKey in the PKCS#8 PrivateKeyInfo structure Java expects. */
    private static byte[] wrapPkcs1AsPkcs8(byte[] pkcs1) throws IOException {
        byte[] version = {0x02, 0x01, 0x00};
        byte[] rsaAlgorithmIdentifier = {
                0x30, 0x0d,
                0x06, 0x09, 0x2a, (byte) 0x86, 0x48, (byte) 0x86, (byte) 0xf7, 0x0d, 0x01, 0x01, 0x01,
                0x05, 0x00
        };
        return der(0x30, concatenate(version, rsaAlgorithmIdentifier, der(0x04, pkcs1)));
    }

    private static byte[] der(int tag, byte[] value) throws IOException {
        ByteArrayOutputStream result = new ByteArrayOutputStream();
        result.write(tag);
        writeDerLength(result, value.length);
        result.write(value);
        return result.toByteArray();
    }

    private static void writeDerLength(ByteArrayOutputStream output, int length) {
        if (length < 128) {
            output.write(length);
            return;
        }
        int bytes = 0;
        for (int remaining = length; remaining > 0; remaining >>>= 8) {
            bytes++;
        }
        output.write(0x80 | bytes);
        for (int shift = (bytes - 1) * 8; shift >= 0; shift -= 8) {
            output.write((length >>> shift) & 0xff);
        }
    }

    private static byte[] concatenate(byte[]... values) throws IOException {
        ByteArrayOutputStream result = new ByteArrayOutputStream();
        for (byte[] value : values) {
            result.write(value);
        }
        return result.toByteArray();
    }

    private static long requiredLong(JsonNode object, String field) {
        if (!object.has(field) || !object.get(field).canConvertToLong()) {
            throw new IllegalArgumentException("GitHub response has no numeric '" + field + "': " + object);
        }
        return object.get(field).longValue();
    }

    private static String requiredText(JsonNode object, String field) {
        if (!object.hasNonNull(field) || !object.get(field).isTextual()) {
            throw new IllegalArgumentException("GitHub response has no text '" + field + "': " + object);
        }
        return object.get(field).textValue();
    }

    private record Config(
            String appId,
            Path privateKey,
            String owner,
            String repo,
            int prNumber,
            String body,
            String tokenPermission,
            URI apiBase,
            boolean dryRun) {

        private static Config parse(String[] args) {
            Map<String, String> options = new LinkedHashMap<>();
            boolean dryRun = false;
            for (int i = 0; i < args.length; i++) {
                if ("--dry-run".equals(args[i])) {
                    dryRun = true;
                } else if (args[i].startsWith("--") && i + 1 < args.length) {
                    options.put(args[i], args[++i]);
                } else {
                    throw usage("Unexpected or incomplete argument: " + args[i]);
                }
            }

            String repository = options.getOrDefault("--repo", "mike-scibite/CreateMyCheck");
            String[] parts = repository.split("/", -1);
            if (parts.length != 2 || parts[0].isBlank() || parts[1].isBlank()) {
                throw usage("--repo must be OWNER/REPO");
            }
            int prNumber;
            try {
                prNumber = Integer.parseInt(options.getOrDefault("--pr", "1"));
            } catch (NumberFormatException e) {
                throw usage("--pr must be an integer");
            }
            String permission = options.getOrDefault("--token-permission", "pull_requests");
            if (!permission.equals("issues") && !permission.equals("pull_requests")) {
                throw usage("--token-permission must be issues or pull_requests");
            }

            return new Config(
                    options.getOrDefault("--app-id", "4909825"),
                    Path.of(options.getOrDefault("--private-key",
                            ".secret/create-my-check.2026-09-11.private-key.pem")),
                    parts[0],
                    parts[1],
                    prNumber,
                    options.getOrDefault("--body",
                            "Local Java GitHub App API test (safe to delete)."),
                    permission,
                    URI.create(options.getOrDefault("--api-url", "https://api.github.com")),
                    dryRun);
        }

        private static IllegalArgumentException usage(String message) {
            return new IllegalArgumentException(message + System.lineSeparator()
                    + "Usage: mvn exec:java -Dexec.args='[--app-id ID] [--private-key PATH] "
                    + "[--repo OWNER/REPO] [--pr NUMBER] [--body TEXT] "
                    + "[--token-permission issues|pull_requests] [--dry-run]'");
        }
    }
}
