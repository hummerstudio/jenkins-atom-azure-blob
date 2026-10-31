package com.jenkinschina.atom.azureblob;

import com.jenkinschina.atom.sdk.AtomContext;
import com.jenkinschina.atom.sdk.AtomResult;
import com.jenkinschina.atom.sdk.AtomTask;
import com.jenkinschina.atom.sdk.ErrorType;
import com.jenkinschina.atom.sdk.Glob;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.time.Duration;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.TreeMap;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * Upload blobs to Azure Blob Storage with a SharedKey signature.
 *
 * <p>Azure wants a specific canonical string signed with the account key, and a mistyped canonical string produces a
 * 403 that says nothing useful. The signature is therefore built here in one place and the smoke test recomputes it
 * from the request it received — so a wrong canonical string fails the test instead of failing production.
 */
public class AzureBlobAtom implements AtomTask {

    static final String VERSION = "2021-08-06";

    @Override
    public AtomResult run(AtomContext context) throws Exception {
        Path workspace = context.getWorkspace();
        String account = context.getParam("account", "").trim();
        String key = context.getSecret("accountKey");
        String container = context.getParam("container", "").trim();
        String endpoint = context.getParam("endpoint", "").trim();
        String files = context.getParam("files", "**/*.jar");
        String blobPrefix = context.getParam("blobPrefix", "").trim();
        String contentTypeOverride = context.getParam("contentType", "").trim();
        boolean overwrite = context.getBooleanParam("overwrite", true);
        boolean failOnError = context.getBooleanParam("failOnError", true);
        int timeoutSeconds = Math.max(10, Math.min(context.getIntParam("timeoutSeconds", 120), 1800));

        if (account.isEmpty()) {
            return AtomResult.error(ErrorType.USER, 40001, "account is required");
        }
        if (key == null || key.isBlank()) {
            return AtomResult.error(ErrorType.USER, 40002, "accountKey is required");
        }
        if (container.isEmpty()) {
            return AtomResult.error(ErrorType.USER, 40003, "container is required");
        }
        String host = endpoint.isBlank()
                ? account + ".blob.core.windows.net"
                : endpoint.replaceAll("^https?://", "").replaceAll("/+$", "");
        String scheme = endpoint.startsWith("http://") ? "http" : "https";
        String baseUrl = scheme + "://" + host + "/" + container;

        List<Path> found = Glob.find(workspace, files);
        if (found.isEmpty()) {
            return AtomResult.error(ErrorType.USER, 40004, "nothing matched " + files);
        }

        HttpClient client = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(timeoutSeconds)).build();
        List<String> urls = new ArrayList<>();
        List<String> failures = new ArrayList<>();
        long bytes = 0;

        for (Path file : found) {
            Path relative = workspace.relativize(file);
            String name = blobPrefix.isEmpty()
                    ? relative.toString().replace('\\', '/')
                    : blobPrefix + "/" + relative.getFileName();
            String url = baseUrl + "/" + name.replace(" ", "%20");
            byte[] content = Files.readAllBytes(file);
            String contentType = contentTypeOverride.isEmpty() ? contentType(file) : contentTypeOverride;
            String date = DateTimeFormatter.RFC_1123_DATE_TIME.format(ZonedDateTime.now(ZoneOffset.UTC));

            Map<String, String> headers = new TreeMap<>();
            // every x-ms-* header that is sent has to be signed, including the content type override
            headers.put("x-ms-blob-type", "BlockBlob");
            headers.put("x-ms-blob-content-type", contentType);
            headers.put("x-ms-date", date);
            headers.put("x-ms-version", VERSION);
            String canonicalResource = "/" + account + "/" + container + "/" + name;
            String signature = sign(account, key, "PUT", content.length, contentType, date, headers, canonicalResource);

            context.log("[blob] PUT " + baseUrl + "/" + name + " (" + content.length + " bytes)");
            HttpRequest.Builder builder = HttpRequest.newBuilder(URI.create(url))
                    .timeout(Duration.ofSeconds(timeoutSeconds))
                    .header("x-ms-blob-type", "BlockBlob")
                    .header("x-ms-date", date)
                    .header("x-ms-version", VERSION)
                    .header("x-ms-blob-content-type", contentType)
                    .header("Content-Type", contentType)
                    // Content-Length is set by the client from the body; HttpClient refuses to take it manually,
                    // but it still has to be part of the signed canonical string
                    .header("Authorization", "SharedKey " + account + ":" + signature)
                    .header("User-Agent", "jenkins-atom-azure-blob")
                    .PUT(HttpRequest.BodyPublishers.ofByteArray(content));
            if (!overwrite) {
                builder.header("If-None-Match", "*");
            }
            HttpResponse<String> response;
            try {
                response = client.send(builder.build(), HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
            } catch (java.net.http.HttpConnectTimeoutException e) {
                return AtomResult.error(ErrorType.ENVIRONMENT, 40005,
                        "could not reach " + host + " within " + timeoutSeconds + "s");
            } catch (java.io.IOException e) {
                return AtomResult.error(ErrorType.THIRD_PART, 40006,
                        "uploading " + name + " failed: " + e.getMessage());
            }
            int status = response.statusCode();
            if (status < 200 || status >= 300) {
                String reason = "HTTP " + status + " uploading " + name + ": " + excerpt(response.body());
                if (failOnError) {
                    ErrorType type = status == 401 || status == 403 ? ErrorType.USER
                            : status == 409 ? ErrorType.USER : ErrorType.THIRD_PART;
                    return AtomResult.error(type, 40007, reason);
                }
                failures.add(reason);
                context.log("[blob] warning: " + reason);
                continue;
            }
            bytes += content.length;
            urls.add(url);
            String etag = response.headers().firstValue("ETag").orElse("");
            if (!etag.isEmpty()) {
                context.log("[blob] " + name + " -> " + etag);
            }
        }

        Map<String, String> outputs = new LinkedHashMap<>();
        outputs.put("uploaded", String.valueOf(urls.size()));
        outputs.put("failed", String.valueOf(failures.size()));
        outputs.put("bytes", String.valueOf(bytes));
        outputs.put("container", container);
        outputs.put("urls", String.join("\n", urls.size() > 20 ? urls.subList(0, 20) : urls));
        if (!urls.isEmpty()) {
            outputs.put("first", urls.get(0));
        }
        context.log("[blob] " + urls.size() + " blob(s), " + bytes + " bytes");
        AtomResult result = AtomResult.success();
        outputs.forEach(result::data);
        return result;
    }

    /**
     * The SharedKey signature. Field order and the empty slots are part of the protocol: getting them wrong yields a
     * 403 that explains nothing, which is why the smoke test recomputes this from the request it received.
     */
    static String stringToSign(String verb, int contentLength, String contentType, String date,
                              Map<String, String> msHeaders, String canonicalResource) {
        StringBuilder text = new StringBuilder();
        text.append(verb).append('\n')      // VERB
                .append('\n')               // Content-Encoding
                .append('\n')               // Content-Language
                .append(contentLength >= 0 ? contentLength : "") .append('\n')  // Content-Length
                .append('\n')               // Content-MD5
                .append(contentType).append('\n')   // Content-Type
                .append('\n')               // Date (empty: x-ms-date is used instead)
                .append('\n')               // If-Modified-Since
                .append('\n')               // If-Match
                .append('\n')               // If-None-Match
                .append('\n')               // If-Unmodified-Since
                .append('\n');              // Range
        for (Map.Entry<String, String> entry : new TreeMap<>(msHeaders).entrySet()) {
            if (entry.getKey().startsWith("x-ms-")) {
                text.append(entry.getKey().toLowerCase(Locale.ROOT)).append(':')
                        .append(entry.getValue().trim()).append('\n');
            }
        }
        text.append(canonicalResource);
        return text.toString();
    }

    static String sign(String account, String key, String verb, int contentLength, String contentType,
                       String date, Map<String, String> msHeaders, String canonicalResource) throws Exception {
        String toSign = stringToSign(verb, contentLength, contentType, date, msHeaders, canonicalResource);
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(Base64.getDecoder().decode(key), "HmacSHA256"));
        return Base64.getEncoder().encodeToString(mac.doFinal(toSign.getBytes(StandardCharsets.UTF_8)));
    }

    static String contentType(Path file) {
        String name = file.getFileName().toString().toLowerCase(Locale.ROOT);
        if (name.endsWith(".jar") || name.endsWith(".zip") || name.endsWith(".war")) {
            return "application/zip";
        }
        if (name.endsWith(".json")) {
            return "application/json";
        }
        if (name.endsWith(".html")) {
            return "text/html";
        }
        if (name.endsWith(".txt") || name.endsWith(".log")) {
            return "text/plain";
        }
        return "application/octet-stream";
    }

    private static String excerpt(String body) {
        String oneLine = body == null ? "" : body.replaceAll("\\s+", " ").trim();
        return oneLine.length() > 200 ? oneLine.substring(0, 200) + "…" : oneLine;
    }
}
