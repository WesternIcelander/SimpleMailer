package io.siggi.simplemailer.api;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import io.siggi.simplemailer.Main;
import io.siggi.simplemailer.config.Config;
import io.siggi.simplemailer.model.Job;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.ArrayList;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class MessagesApiTest {
    private static final String KEY = "sender-key";

    @TempDir
    Path dataDir;

    private Main main;
    private final List<Job> enqueued = new CopyOnWriteArrayList<>();
    private final List<Job> preparing = new CopyOnWriteArrayList<>();
    private final HttpClient client = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).build();

    @BeforeEach
    void start() throws Exception {
        Config config = Config.fromJson("{\"dataDir\": \"" + dataDir.toString().replace("\\", "\\\\") + "\","
                + "\"apiKeys\": [\"" + KEY + "\"], \"bounces\": {\"apiKeys\": [\"bounce-key\"]}, \"publicBaseUrl\": \"https://mail.example.com/\","
                + "\"maxMessageBytes\": 4096, \"maxAttachmentBytes\": 1024}");
        ServerSocket socket = new ServerSocket(0, 50, InetAddress.getLoopbackAddress());
        main = Main.start(config, socket);
        main.setDeliveryQueue(enqueued::add);
        // URL attachments are not fetched here (see AttachmentFetcherTest / JobPreparerTest)
        main.setPreparationQueue(preparing::add);
    }

    @AfterEach
    void stop() throws Exception {
        main.close();
    }

    private HttpResponse<String> post(String body, String contentType, String key) throws Exception {
        HttpRequest.Builder b = HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + main.port() + "/v1/messages"))
                .timeout(Duration.ofSeconds(5))
                .POST(HttpRequest.BodyPublishers.ofString(body));
        if (contentType != null) b.header("Content-Type", contentType);
        if (key != null) b.header("Authorization", "Bearer " + key);
        return client.send(b.build(), HttpResponse.BodyHandlers.ofString());
    }

    private HttpResponse<String> post(String body) throws Exception {
        return post(body, "application/json", KEY);
    }

    private HttpResponse<String> get(String path, String key) throws Exception {
        HttpRequest.Builder b = HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + main.port() + path))
                .timeout(Duration.ofSeconds(5)).GET();
        if (key != null) b.header("Authorization", "Bearer " + key);
        return client.send(b.build(), HttpResponse.BodyHandlers.ofString());
    }

    private static String message(String id, String subject) {
        return "{\"id\":\"" + id + "\",\"from\":\"sender@example.com\",\"to\":[\"a@x.com\"],"
                + "\"bcc\":[\"b@y.org\"],\"subject\":\"" + subject + "\",\"text\":\"hello\"}";
    }

    private static JsonObject json(HttpResponse<String> response) {
        return JsonParser.parseString(response.body()).getAsJsonObject();
    }

    @Test
    void newMessageIsAcceptedPersistedAndEnqueued() throws Exception {
        String id = UUID.randomUUID().toString();
        HttpResponse<String> response = post(message(id, "Hi"));
        assertEquals(202, response.statusCode(), response.body());
        JsonObject body = json(response);
        String statusUrl = "https://mail.example.com/v1/messages/" + id;
        assertEquals(id, body.get("id").getAsString());
        assertEquals("queued", body.get("status").getAsString());
        assertEquals(statusUrl, body.get("statusUrl").getAsString());
        assertEquals(statusUrl, response.headers().firstValue("Location").orElse(null));
        assertTrue(Files.exists(dataDir.resolve("jobs").resolve(id + ".json")));
        assertEquals(1, enqueued.size());
        assertEquals(id, enqueued.get(0).id);
        assertEquals(2, enqueued.get(0).recipients.size());
    }

    @Test
    void statusEndpointReturnsJob() throws Exception {
        String id = UUID.randomUUID().toString();
        assertEquals(202, post(message(id, "Hi")).statusCode());
        HttpResponse<String> response = get("/v1/messages/" + id, KEY);
        assertEquals(200, response.statusCode());
        JsonObject body = json(response);
        assertEquals(id, body.get("id").getAsString());
        assertEquals("queued", body.get("status").getAsString());
        assertEquals("https://mail.example.com/v1/messages/" + id, body.get("statusUrl").getAsString());
        assertEquals(2, body.getAsJsonArray("recipients").size());
        assertEquals("pending", body.getAsJsonArray("recipients").get(0).getAsJsonObject().get("status").getAsString());
        assertFalse(body.has("request"));
        assertFalse(body.has("payloadHash"));
    }

    @Test
    void identicalReplayReturns200WithoutEnqueueing() throws Exception {
        String id = UUID.randomUUID().toString();
        assertEquals(202, post(message(id, "Hi")).statusCode());
        HttpResponse<String> replay = post(message(id.toUpperCase(), "Hi"));
        assertEquals(200, replay.statusCode(), replay.body());
        assertEquals(id, json(replay).get("id").getAsString());
        assertEquals("queued", json(replay).get("status").getAsString());
        assertEquals(1, enqueued.size());
    }

    @Test
    void differentPayloadWithSameIdIs409() throws Exception {
        String id = UUID.randomUUID().toString();
        assertEquals(202, post(message(id, "Hi")).statusCode());
        HttpResponse<String> conflict = post(message(id, "Different"));
        assertEquals(409, conflict.statusCode());
        assertEquals("conflict", json(conflict).get("error").getAsString());
        assertEquals(1, enqueued.size());
    }

    @Test
    void unknownOrInvalidIdIs404() throws Exception {
        assertEquals(404, get("/v1/messages/" + UUID.randomUUID(), KEY).statusCode());
        assertEquals(404, get("/v1/messages/not-a-uuid", KEY).statusCode());
        assertEquals(404, get("/v1/messages/../jobs", KEY).statusCode());
    }

    @Test
    void missingOrWrongKeyIs401() throws Exception {
        String id = UUID.randomUUID().toString();
        assertEquals(401, post(message(id, "Hi"), "application/json", null).statusCode());
        assertEquals(401, post(message(id, "Hi"), "application/json", "wrong").statusCode());
        assertEquals(401, get("/v1/messages/" + id, null).statusCode());
        assertTrue(enqueued.isEmpty());
    }

    @Test
    void validationErrorsAre400() throws Exception {
        HttpResponse<String> bad = post("{\"id\":\"nope\",\"from\":\"x\",\"to\":[\"bad\"],\"text\":\"t\"}");
        assertEquals(400, bad.statusCode());
        JsonObject body = json(bad);
        assertEquals("validation_failed", body.get("error").getAsString());
        assertTrue(body.getAsJsonArray("errors").size() >= 3, bad.body());

        assertEquals(400, post("not json").statusCode());
        assertEquals(400, post("[1,2]").statusCode());
        assertEquals(400, post("").statusCode());
        assertEquals(400, post("{\"id\":\"" + UUID.randomUUID() + "\",\"from\":\"s@example.com\","
                + "\"to\":[\"a@x.com\"],\"text\":\"t\",\"attachments\":[{\"part\":\"f\",\"filename\":\"a.txt\"}]}")
                .statusCode());
        assertTrue(enqueued.isEmpty());
    }

    @Test
    void oversizeBodyIs413() throws Exception {
        String big = "x".repeat(5000);
        HttpResponse<String> response = post(message(UUID.randomUUID().toString(), big));
        assertEquals(413, response.statusCode());
    }

    @Test
    void nonJsonContentTypeIs415() throws Exception {
        assertEquals(415, post(message(UUID.randomUUID().toString(), "Hi"), "text/plain", KEY).statusCode());
    }

    @Test
    void wrongMethodsAre405() throws Exception {
        assertEquals(405, get("/v1/messages", KEY).statusCode());
        String id = UUID.randomUUID().toString();
        HttpRequest req = HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + main.port() + "/v1/messages/" + id))
                .header("Authorization", "Bearer " + KEY)
                .DELETE().build();
        assertEquals(405, client.send(req, HttpResponse.BodyHandlers.ofString()).statusCode());
    }

    @Test
    void concurrentIdenticalPostsCreateOneJob() throws Exception {
        String id = UUID.randomUUID().toString();
        int n = 16;
        CountDownLatch go = new CountDownLatch(1);
        List<Future<Integer>> codes = new ArrayList<>();
        try (ExecutorService pool = Executors.newVirtualThreadPerTaskExecutor()) {
            for (int i = 0; i < n; i++) {
                codes.add(pool.submit(() -> {
                    go.await();
                    return post(message(id, "Hi")).statusCode();
                }));
            }
            go.countDown();
            int accepted = 0, replayed = 0;
            for (Future<Integer> f : codes) {
                int code = f.get();
                if (code == 202) accepted++;
                else if (code == 200) replayed++;
                else throw new AssertionError("unexpected status " + code);
            }
            assertEquals(1, accepted);
            assertEquals(n - 1, replayed);
        }
        assertEquals(1, enqueued.size());
        assertEquals(id, enqueued.get(0).id);
    }

    @Test
    void concurrentDifferentPostsWithSameIdCreateOneJob() throws Exception {
        String id = UUID.randomUUID().toString();
        int n = 16;
        CountDownLatch go = new CountDownLatch(1);
        List<Future<HttpResponse<String>>> responses = new ArrayList<>();
        try (ExecutorService pool = Executors.newVirtualThreadPerTaskExecutor()) {
            for (int i = 0; i < n; i++) {
                String subject = "S" + (i % 2);
                responses.add(pool.submit(() -> {
                    go.await();
                    return post(message(id, subject));
                }));
            }
            go.countDown();
            int accepted = 0;
            for (Future<HttpResponse<String>> f : responses) {
                int code = f.get().statusCode();
                assertTrue(code == 202 || code == 200 || code == 409, "unexpected status " + code);
                if (code == 202) accepted++;
            }
            assertEquals(1, accepted);
        }
        assertEquals(1, enqueued.size());
    }

    @Test
    void rawMessageIsAccepted() throws Exception {
        String id = UUID.randomUUID().toString();
        HttpResponse<String> response = post("{\"id\":\"" + id + "\",\"from\":\"s@example.com\","
                + "\"recipients\":[\"a@x.com\"],\"raw\":\"Subject: hi\\r\\n\\r\\nbody\\r\\n\"}");
        assertEquals(202, response.statusCode(), response.body());
        assertEquals(1, enqueued.size());
        assertEquals("Subject: hi\r\n\r\nbody\r\n",
                Files.readString(dataDir.resolve("payloads").resolve(id + ".eml")));
    }

    @Test
    void rawMessageLineEndingsAreNormalised() throws Exception {
        String id = UUID.randomUUID().toString();
        HttpResponse<String> response = post("{\"id\":\"" + id + "\",\"from\":\"s@example.com\","
                + "\"recipients\":[\"a@x.com\"],\"raw\":\"Subject: hi\\nX-A: b\\r\\n\\nline1\\rline2\\n\\nend\"}");
        assertEquals(202, response.statusCode(), response.body());
        assertEquals("Subject: hi\r\nX-A: b\r\n\r\nline1\r\nline2\r\n\r\nend\r\n",
                Files.readString(dataDir.resolve("payloads").resolve(id + ".eml")));
    }

    @Test
    void moreValidationErrorsAre400() throws Exception {
        String id = UUID.randomUUID().toString();
        String base = "{\"id\":\"" + id + "\",\"from\":\"s@example.com\",";
        // both raw and structured
        assertValidationError(base + "\"to\":[\"a@x.com\"],\"text\":\"t\",\"raw\":\"x\"}", "either raw");
        // neither raw nor structured
        assertValidationError(base + "\"to\":[\"a@x.com\"]}", "required");
        // no recipients
        assertValidationError(base + "\"text\":\"t\"}", "at least one of to/cc/bcc");
        // raw without recipients
        assertValidationError(base + "\"raw\":\"Subject: x\\r\\n\\r\\nb\"}", "recipients");
        // missing id
        assertValidationError("{\"from\":\"s@example.com\",\"to\":[\"a@x.com\"],\"text\":\"t\"}", "id is required");
        // bad callback URL
        assertValidationError(base + "\"to\":[\"a@x.com\"],\"text\":\"t\",\"callbackUrl\":\"ftp://x\"}",
                "callbackUrl");
        // bad base64 attachment
        assertValidationError(base + "\"to\":[\"a@x.com\"],\"text\":\"t\","
                + "\"attachments\":[{\"content\":\"!!!\",\"filename\":\"a.bin\"}]}", "base64");
        // http attachment URL not allowed by default
        assertValidationError(base + "\"to\":[\"a@x.com\"],\"text\":\"t\","
                + "\"attachments\":[{\"url\":\"http://cdn.example.com/a.pdf\",\"filename\":\"a.pdf\"}]}",
                "https");
        // reserved header
        assertValidationError(base + "\"to\":[\"a@x.com\"],\"text\":\"t\",\"headers\":{\"Bcc\":\"z@z.com\"}}",
                "headers");
        assertTrue(enqueued.isEmpty());
        assertEquals(404, get("/v1/messages/" + id, KEY).statusCode());
    }

    private void assertValidationError(String body, String expectedFragment) throws Exception {
        HttpResponse<String> response = post(body);
        assertEquals(400, response.statusCode(), body + " -> " + response.body());
        JsonObject json = json(response);
        assertEquals("validation_failed", json.get("error").getAsString());
        boolean found = false;
        for (var e : json.getAsJsonArray("errors")) {
            if (e.getAsString().contains(expectedFragment)) found = true;
        }
        assertTrue(found, "expected an error containing '" + expectedFragment + "': " + response.body());
    }

    @Test
    void bounceKeyCannotSendOrReadStatus() throws Exception {
        String id = UUID.randomUUID().toString();
        assertEquals(202, post(message(id, "Hi")).statusCode());
        assertEquals(401, post(message(UUID.randomUUID().toString(), "Hi"), "application/json", "bounce-key")
                .statusCode());
        assertEquals(401, get("/v1/messages/" + id, "bounce-key").statusCode());
        assertEquals(1, enqueued.size());
    }

    // ---- multipart/form-data and base64 attachments ----

    /** A file part for {@link #multipart}: field name, filename (null = plain field), content type, bytes. */
    private record FormPart(String name, String filename, String contentType, byte[] data) {
        static FormPart field(String name, String value) {
            return new FormPart(name, null, null, value.getBytes(java.nio.charset.StandardCharsets.UTF_8));
        }

        static FormPart file(String name, String filename, String contentType, byte[] data) {
            return new FormPart(name, filename, contentType, data);
        }
    }

    private HttpResponse<String> multipart(String key, FormPart... parts) throws Exception {
        return multipart(key, false, parts);
    }

    private HttpResponse<String> multipart(String key, boolean expectContinue, FormPart... parts) throws Exception {
        String boundary = "----SimpleMailerTest" + UUID.randomUUID();
        java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
        for (FormPart p : parts) {
            StringBuilder h = new StringBuilder("--").append(boundary).append("\r\n")
                    .append("Content-Disposition: form-data; name=\"").append(p.name()).append('"');
            if (p.filename() != null) h.append("; filename=\"").append(p.filename()).append('"');
            h.append("\r\n");
            if (p.contentType() != null) h.append("Content-Type: ").append(p.contentType()).append("\r\n");
            h.append("\r\n");
            out.write(h.toString().getBytes(java.nio.charset.StandardCharsets.UTF_8));
            out.write(p.data());
            out.write("\r\n".getBytes(java.nio.charset.StandardCharsets.US_ASCII));
        }
        out.write(("--" + boundary + "--\r\n").getBytes(java.nio.charset.StandardCharsets.US_ASCII));
        HttpRequest.Builder b = HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + main.port() + "/v1/messages"))
                .timeout(Duration.ofSeconds(5))
                .header("Content-Type", "multipart/form-data; boundary=" + boundary)
                .expectContinue(expectContinue)
                .POST(HttpRequest.BodyPublishers.ofByteArray(out.toByteArray()));
        if (key != null) b.header("Authorization", "Bearer " + key);
        return client.send(b.build(), HttpResponse.BodyHandlers.ofString());
    }

    private static String withAttachments(String id, String attachmentsJson) {
        return "{\"id\":\"" + id + "\",\"from\":\"s@example.com\",\"to\":[\"a@x.com\"],\"subject\":\"Files\","
                + "\"text\":\"see attached\",\"attachments\":" + attachmentsJson + "}";
    }

    private String payload(String id) throws Exception {
        // unfolded, so assertions don't depend on where long headers are folded
        return Files.readString(dataDir.resolve("payloads").resolve(id + ".eml"), java.nio.charset.StandardCharsets.ISO_8859_1)
                .replace("\r\n ", " ");
    }

    @Test
    void structuredMessageIsBuiltIntoPayloadFile() throws Exception {
        String id = UUID.randomUUID().toString();
        assertEquals(202, post(message(id, "Hi")).statusCode());
        String eml = payload(id);
        assertTrue(eml.contains("Subject: Hi\r\n"), eml);
        assertTrue(eml.contains("Message-ID: <" + id + "@localhost>"), eml);
        assertFalse(eml.contains("b@y.org"), "Bcc must not be written: " + eml);
    }

    @Test
    void multipartUploadIsAcceptedStoredAndBuilt() throws Exception {
        String id = UUID.randomUUID().toString();
        byte[] pdf = new byte[300];
        for (int i = 0; i < pdf.length; i++) pdf[i] = (byte) i;
        HttpResponse<String> response = multipart(KEY,
                FormPart.field("message", withAttachments(id,
                        "[{\"part\":\"doc\",\"filename\":\"terms.pdf\",\"contentType\":\"application/pdf\"}]")),
                FormPart.file("doc", "upload.pdf", "application/octet-stream", pdf));
        assertEquals(202, response.statusCode(), response.body());
        assertEquals("queued", json(response).get("status").getAsString());
        assertEquals(1, enqueued.size());

        Path stored = dataDir.resolve("payloads").resolve(id).resolve("0");
        assertTrue(java.util.Arrays.equals(pdf, Files.readAllBytes(stored)));
        String eml = payload(id);
        assertTrue(eml.contains("multipart/mixed"), eml);
        assertTrue(eml.contains("Content-Type: application/pdf; name=terms.pdf"), eml);
        assertTrue(eml.contains("Content-Disposition: attachment; filename=terms.pdf"), eml);
        String b64 = Base64.getEncoder().encodeToString(pdf);
        assertTrue(eml.replace("\r\n", "").contains(b64), eml);
    }

    @Test
    void inlineCidAttachmentIsBuiltAsRelatedPart() throws Exception {
        String id = UUID.randomUUID().toString();
        byte[] png = {(byte) 0x89, 'P', 'N', 'G', 1, 2, 3};
        String message = "{\"id\":\"" + id + "\",\"from\":\"s@example.com\",\"to\":[\"a@x.com\"],"
                + "\"subject\":\"Logo\",\"text\":\"t\",\"html\":\"<img src=\\\"cid:companylogo.png\\\">\","
                + "\"attachments\":[{\"part\":\"logo\",\"filename\":\"companylogo.png\",\"inline\":true}]}";
        HttpResponse<String> response = multipart(KEY,
                FormPart.field("message", message),
                FormPart.file("logo", "companylogo.png", "image/png", png));
        assertEquals(202, response.statusCode(), response.body());
        String eml = payload(id);
        assertTrue(eml.contains("multipart/related"), eml);
        assertTrue(eml.contains("Content-ID: <companylogo.png>"), eml);
        assertTrue(eml.contains("Content-Disposition: inline; filename=companylogo.png"), eml);
        assertFalse(eml.contains("multipart/mixed"), eml);
    }

    @Test
    void unmatchedCidIs400() throws Exception {
        String id = UUID.randomUUID().toString();
        String base = "{\"id\":\"" + id + "\",\"from\":\"s@example.com\",\"to\":[\"a@x.com\"],"
                + "\"subject\":\"Logo\",\"html\":\"<img src=\\\"cid:logo.png\\\">\"";
        assertValidationError(base + "}", "cid:logo.png");
        assertValidationError(base + ",\"attachments\":[{\"content\":\"AAAA\",\"filename\":\"other.png\","
                + "\"inline\":true}]}", "cid:logo.png");
        assertValidationError(base + ",\"attachments\":[{\"content\":\"AAAA\",\"filename\":\"logo.png\"}]}",
                "cid:logo.png");
        assertTrue(enqueued.isEmpty());
        assertEquals(404, get("/v1/messages/" + id, KEY).statusCode());
    }

    @Test
    void multipartFilenameAndTypeDefaultToUpload() throws Exception {
        String id = UUID.randomUUID().toString();
        HttpResponse<String> response = multipart(KEY,
                FormPart.file("logo", "logo.png", "image/png", new byte[]{1, 2, 3}),
                FormPart.field("message", withAttachments(id, "[{\"part\":\"logo\"}]")));
        assertEquals(202, response.statusCode(), response.body());
        String eml = payload(id);
        assertTrue(eml.contains("Content-Type: image/png; name=logo.png"), eml);
        assertTrue(eml.contains("filename=logo.png"), eml);
    }

    @Test
    void multipartMessageMayBeAFilePart() throws Exception {
        String id = UUID.randomUUID().toString();
        HttpResponse<String> response = multipart(KEY,
                FormPart.file("message", "message.json", "application/json",
                        message(id, "Hi").getBytes(java.nio.charset.StandardCharsets.UTF_8)));
        assertEquals(202, response.statusCode(), response.body());
    }

    @Test
    void multipartReplayIsIdempotentAndFileContentCounts() throws Exception {
        String id = UUID.randomUUID().toString();
        String json = withAttachments(id, "[{\"part\":\"f\",\"filename\":\"a.txt\"}]");
        assertEquals(202, multipart(KEY, FormPart.field("message", json),
                FormPart.file("f", "a.txt", "text/plain", "one".getBytes())).statusCode());
        HttpResponse<String> replay = multipart(KEY, FormPart.field("message", json),
                FormPart.file("f", "a.txt", "text/plain", "one".getBytes()));
        assertEquals(200, replay.statusCode(), replay.body());
        HttpResponse<String> changed = multipart(KEY, FormPart.field("message", json),
                FormPart.file("f", "a.txt", "text/plain", "two".getBytes()));
        assertEquals(409, changed.statusCode(), changed.body());
        assertEquals(1, enqueued.size());
        assertEquals("one", Files.readString(dataDir.resolve("payloads").resolve(id).resolve("0")));
    }

    @Test
    void multipartValidationErrors() throws Exception {
        String id = UUID.randomUUID().toString();
        // no message field
        HttpResponse<String> r = multipart(KEY, FormPart.file("f", "a.txt", "text/plain", "x".getBytes()));
        assertEquals(400, r.statusCode(), r.body());
        assertTrue(r.body().contains("message"), r.body());
        // attachment refers to a missing part
        r = multipart(KEY, FormPart.field("message", withAttachments(id, "[{\"part\":\"nope\",\"filename\":\"a\"}]")));
        assertEquals(400, r.statusCode(), r.body());
        assertTrue(r.body().contains("no file part named 'nope'"), r.body());
        // uploaded file not used by any attachment
        r = multipart(KEY, FormPart.field("message", message(id, "Hi")),
                FormPart.file("extra", "a.txt", "text/plain", "x".getBytes()));
        assertEquals(400, r.statusCode(), r.body());
        assertTrue(r.body().contains("'extra' is not used"), r.body());
        // invalid JSON in the message field
        r = multipart(KEY, FormPart.field("message", "{nope"));
        assertEquals(400, r.statusCode(), r.body());
        // no key
        assertEquals(401, multipart(null, FormPart.field("message", message(id, "Hi"))).statusCode());
        assertTrue(enqueued.isEmpty());
        assertFalse(Files.exists(dataDir.resolve("payloads").resolve(id)));
    }

    @Test
    void multipartOverUploadLimitIsRejected() throws Exception {
        String id = UUID.randomUUID().toString();
        // SiggiHTTP 1.10 enforces the upload limit itself while parsing multipart bodies. Its 413 page is written
        // to a buffer that isn't flushed before the connection closes, so the client may see a closed connection
        // instead of the 413. Either way the request must be refused and nothing stored.
        try {
            HttpResponse<String> r = multipart(KEY, true,
                    FormPart.field("message", withAttachments(id, "[{\"part\":\"f\",\"filename\":\"a.bin\"}]")),
                    FormPart.file("f", "a.bin", "application/octet-stream", new byte[5000]));
            assertEquals(413, r.statusCode());
        } catch (java.io.IOException expected) {
            // connection closed without a response
        }
        assertTrue(enqueued.isEmpty());
        assertFalse(Files.exists(dataDir.resolve("jobs").resolve(id + ".json")));
    }

    @Test
    void attachmentOverMaxAttachmentBytesIs413() throws Exception {
        String id = UUID.randomUUID().toString();
        HttpResponse<String> r = multipart(KEY,
                FormPart.field("message", withAttachments(id, "[{\"part\":\"f\",\"filename\":\"a.bin\"}]")),
                FormPart.file("f", "a.bin", "application/octet-stream", new byte[2000]));
        assertEquals(413, r.statusCode(), r.body());
        assertTrue(r.body().contains("attachments[0]"), r.body());

        String b64 = Base64.getEncoder().encodeToString(new byte[1500]);
        r = post(withAttachments(id, "[{\"content\":\"" + b64 + "\",\"filename\":\"a.bin\"}]"));
        assertEquals(413, r.statusCode(), r.body());
        assertTrue(enqueued.isEmpty());
    }

    @Test
    void base64JsonAttachmentIsDecodedStoredAndBuilt() throws Exception {
        String id = UUID.randomUUID().toString();
        byte[] data = "%PDF-1.4 terms\n".getBytes(java.nio.charset.StandardCharsets.US_ASCII);
        // line-wrapped base64 is accepted
        String b64 = Base64.getMimeEncoder(8, "\n".getBytes()).encodeToString(data).replace("\n", "\\n");
        HttpResponse<String> response = post(withAttachments(id,
                "[{\"content\":\"" + b64 + "\",\"filename\":\"terms.pdf\"}]"));
        assertEquals(202, response.statusCode(), response.body());
        assertTrue(java.util.Arrays.equals(data,
                Files.readAllBytes(dataDir.resolve("payloads").resolve(id).resolve("0"))));
        String eml = payload(id);
        // content type guessed from the filename
        assertTrue(eml.contains("Content-Type: application/pdf; name=terms.pdf"), eml);
        assertTrue(eml.replace("\r\n", "").contains(Base64.getEncoder().encodeToString(data)), eml);
        // the base64 isn't kept in the job file
        String jobJson = Files.readString(dataDir.resolve("jobs").resolve(id + ".json"));
        assertFalse(jobJson.contains(Base64.getEncoder().encodeToString(data).substring(0, 8)), jobJson);
        // replay is still a duplicate, different content a conflict
        assertEquals(200, post(withAttachments(id,
                "[{\"content\":\"" + b64 + "\",\"filename\":\"terms.pdf\"}]")).statusCode());
        assertEquals(409, post(withAttachments(id,
                "[{\"content\":\"" + Base64.getEncoder().encodeToString("x".getBytes()) + "\",\"filename\":\"terms.pdf\"}]"))
                .statusCode());
    }

    @Test
    void urlAttachmentJobStartsPreparingWithoutPayload() throws Exception {
        String id = UUID.randomUUID().toString();
        HttpResponse<String> response = post(withAttachments(id,
                "[{\"url\":\"https://cdn.example.com/a.pdf\",\"filename\":\"a.pdf\"},"
                        + "{\"content\":\"AQID\",\"filename\":\"b.bin\"}]"));
        assertEquals(202, response.statusCode(), response.body());
        assertEquals("preparing", json(response).get("status").getAsString());
        assertFalse(Files.exists(dataDir.resolve("payloads").resolve(id + ".eml")));
        assertFalse(Files.exists(dataDir.resolve("payloads").resolve(id).resolve("0")));
        assertTrue(Files.exists(dataDir.resolve("payloads").resolve(id).resolve("1")));
        // handed to the preparer, not to delivery
        assertEquals(1, preparing.size());
        assertEquals(id, preparing.get(0).id);
        assertTrue(enqueued.isEmpty());
    }
}
