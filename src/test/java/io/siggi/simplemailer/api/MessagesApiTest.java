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
import java.util.List;
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
    private final HttpClient client = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).build();

    @BeforeEach
    void start() throws Exception {
        Config config = Config.fromJson("{\"dataDir\": \"" + dataDir.toString().replace("\\", "\\\\") + "\","
                + "\"apiKeys\": [\"" + KEY + "\"], \"bounces\": {\"apiKeys\": [\"bounce-key\"]}, \"publicBaseUrl\": \"https://mail.example.com/\","
                + "\"maxMessageBytes\": 4096}");
        ServerSocket socket = new ServerSocket(0, 50, InetAddress.getLoopbackAddress());
        main = Main.start(config, socket);
        main.setDeliveryQueue(enqueued::add);
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
}
