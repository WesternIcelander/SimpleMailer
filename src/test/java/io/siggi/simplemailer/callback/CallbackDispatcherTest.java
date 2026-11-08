package io.siggi.simplemailer.callback;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.sun.net.httpserver.HttpServer;
import io.siggi.simplemailer.config.Config;
import io.siggi.simplemailer.model.Job;
import io.siggi.simplemailer.model.JobStatus;
import io.siggi.simplemailer.model.RecipientResult;
import io.siggi.simplemailer.model.SendRequest;
import io.siggi.simplemailer.store.JobStore;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.BooleanSupplier;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CallbackDispatcherTest {
    private static final String SECRET = "s3cret";
    private static final String URL = "https://caller.test/hook";

    @TempDir
    Path dataDir;

    private final List<AutoCloseable> closeables = new ArrayList<>();
    private final ExecutorService executor = Executors.newVirtualThreadPerTaskExecutor();

    @AfterEach
    void tearDown() throws Exception {
        for (AutoCloseable c : closeables) c.close();
        executor.shutdownNow();
        executor.awaitTermination(5, TimeUnit.SECONDS);
    }

    record Sent(URI url, String body, Map<String, String> headers) {
    }

    /** Records requests and answers with the scripted status codes (then 200). */
    static final class FakeTransport implements CallbackDispatcher.Transport {
        final LinkedBlockingQueue<Sent> sent = new LinkedBlockingQueue<>();
        final LinkedBlockingQueue<Integer> answers = new LinkedBlockingQueue<>();

        @Override
        public int post(URI url, byte[] body, Map<String, String> headers) {
            sent.add(new Sent(url, new String(body, StandardCharsets.UTF_8), Map.copyOf(headers)));
            Integer status = answers.poll();
            return status == null ? 200 : status;
        }

        Sent next() throws InterruptedException {
            Sent s = sent.poll(5, TimeUnit.SECONDS);
            assertNotNull(s, "expected a callback request");
            return s;
        }
    }

    private Config config(Duration... schedule) {
        Config config = new Config();
        config.dataDir = dataDir.toString();
        config.publicBaseUrl = "https://mailer.test";
        config.callbackSecret = SECRET;
        config.callbackRetrySchedule = new ArrayList<>(List.of(schedule.length == 0
                ? new Duration[]{Duration.ofMillis(20)} : schedule));
        config.callbackMaxRetryDuration = Duration.ofHours(1);
        return config;
    }

    private JobStore store() throws IOException {
        return new JobStore(dataDir);
    }

    private CallbackDispatcher dispatcher(Config config, JobStore store, CallbackDispatcher.Transport t)
            throws IOException {
        CallbackDispatcher d = new CallbackDispatcher(config, store, executor, t);
        closeables.add(d);
        return d;
    }

    private static Job newJob(JobStore store, String callbackUrl, JobStatus status) throws IOException {
        SendRequest req = new SendRequest();
        req.id = UUID.randomUUID().toString();
        req.from = "sender@example.test";
        req.to = List.of("a@x.test");
        req.subject = "hi";
        req.text = "hello";
        req.callbackUrl = callbackUrl;
        Job job = Job.create(req, "hash", Instant.now(), status);
        store.create(job.id, "hash", () -> job);
        return job;
    }

    private static Job setStatus(JobStore store, Job job, JobStatus status, RecipientResult.Status rs)
            throws IOException {
        return store.update(job.id, j -> {
            j.status = status;
            j.recipients.forEach(r -> r.status = rs);
        }).orElseThrow();
    }

    private static void await(BooleanSupplier condition) throws InterruptedException {
        long end = System.nanoTime() + TimeUnit.SECONDS.toNanos(5);
        while (!condition.getAsBoolean()) {
            if (System.nanoTime() > end) throw new AssertionError("condition not met in time");
            Thread.sleep(10);
        }
    }

    private static long countPending(CallbackDispatcher d) {
        try {
            return d.pendingCount();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    private static Job.CallbackState callbackState(JobStore store, String id) {
        try {
            return store.get(id).orElseThrow().callback;
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    @Test
    void terminalEventIsSignedCarriesIdAndJobAndIsSentOnce() throws Exception {
        JobStore store = store();
        FakeTransport t = new FakeTransport();
        CallbackDispatcher d = dispatcher(config(), store, t);
        Job job = newJob(store, URL, JobStatus.QUEUED);
        Job delivered = setStatus(store, job, JobStatus.DELIVERED, RecipientResult.Status.DELIVERED);

        d.onJobChanged(delivered);
        Sent s = t.next();
        assertEquals(URI.create(URL), s.url());
        JsonObject body = JsonParser.parseString(s.body()).getAsJsonObject();
        assertEquals("delivered", body.get("event").getAsString());
        String eventId = body.get("eventId").getAsString();
        UUID.fromString(eventId);
        assertEquals(eventId, s.headers().get(CallbackDispatcher.EVENT_ID_HEADER));
        assertEquals("delivered", s.headers().get(CallbackDispatcher.EVENT_HEADER));
        JsonObject jobJson = body.getAsJsonObject("job");
        assertEquals(job.id, jobJson.get("id").getAsString());
        assertEquals("delivered", jobJson.get("status").getAsString());
        assertEquals("https://mailer.test/v1/messages/" + job.id, jobJson.get("statusUrl").getAsString());

        String sig = s.headers().get(CallbackDispatcher.SIGNATURE_HEADER);
        byte[] bytes = s.body().getBytes(StandardCharsets.UTF_8);
        assertTrue(sig.startsWith("sha256="));
        assertTrue(CallbackDispatcher.verifySignature(SECRET, bytes, sig));
        assertFalse(CallbackDispatcher.verifySignature("other", bytes, sig));

        await(() -> "delivered".equals(callbackState(store, job.id).status));
        Job.CallbackState cb = callbackState(store, job.id);
        assertEquals(eventId, cb.lastEventId);
        assertEquals(1, cb.attempts);
        assertEquals(200, cb.lastHttpStatus);
        assertEquals(0, d.pendingCount());

        // a second notification for the same terminal state fires nothing
        d.onJobChanged(store.get(job.id).orElseThrow());
        assertNull(t.sent.poll(200, TimeUnit.MILLISECONDS));
    }

    @Test
    void firstDeferredOnlyThenTerminal() throws Exception {
        JobStore store = store();
        FakeTransport t = new FakeTransport();
        CallbackDispatcher d = dispatcher(config(), store, t);
        Job job = newJob(store, URL, JobStatus.QUEUED);

        d.onJobChanged(setStatus(store, job, JobStatus.DEFERRED, RecipientResult.Status.DEFERRED));
        assertTrue(t.next().body().contains("\"event\":\"deferred\""));
        d.onJobChanged(setStatus(store, job, JobStatus.DEFERRED, RecipientResult.Status.DEFERRED));
        assertNull(t.sent.poll(200, TimeUnit.MILLISECONDS));

        d.onJobChanged(setStatus(store, job, JobStatus.FAILED, RecipientResult.Status.FAILED));
        assertTrue(t.next().body().contains("\"event\":\"failed\""));
    }

    @Test
    void everyBounceGetsItsOwnEvent() throws Exception {
        JobStore store = store();
        FakeTransport t = new FakeTransport();
        CallbackDispatcher d = dispatcher(config(), store, t);
        Job job = newJob(store, URL, JobStatus.DELIVERED);
        String a = d.bounced(job.id).orElseThrow();
        String b = d.bounced(job.id).orElseThrow();
        assertNotEquals(a, b);
        Sent s1 = t.next(), s2 = t.next();
        assertTrue(s1.body().contains("\"event\":\"bounced\""));
        assertTrue(s2.body().contains("\"event\":\"bounced\""));
        await(() -> "delivered".equals(callbackState(store, job.id).status) && countPending(d) == 0);
    }

    @Test
    void noCallbackUrlMeansNoEvent() throws Exception {
        JobStore store = store();
        FakeTransport t = new FakeTransport();
        CallbackDispatcher d = dispatcher(config(), store, t);
        Job job = newJob(store, null, JobStatus.QUEUED);
        d.onJobChanged(setStatus(store, job, JobStatus.DELIVERED, RecipientResult.Status.DELIVERED));
        assertTrue(d.fire(job.id, "delivered").isEmpty());
        assertNull(t.sent.poll(200, TimeUnit.MILLISECONDS));
    }

    @Test
    void retriesNon2xxWithTheSameBytesUntilSuccess() throws Exception {
        JobStore store = store();
        FakeTransport t = new FakeTransport();
        t.answers.addAll(List.of(500, 404));
        CallbackDispatcher d = dispatcher(config(Duration.ofMillis(20)), store, t);
        Job job = newJob(store, URL, JobStatus.FAILED);
        d.fire(job.id, "failed");

        Sent first = t.next(), second = t.next(), third = t.next();
        assertEquals(first.body(), second.body());
        assertEquals(first.body(), third.body());
        assertEquals(first.headers().get(CallbackDispatcher.SIGNATURE_HEADER),
                third.headers().get(CallbackDispatcher.SIGNATURE_HEADER));
        await(() -> "delivered".equals(callbackState(store, job.id).status));
        assertEquals(3, callbackState(store, job.id).attempts);
        assertEquals(0, d.pendingCount());
    }

    @Test
    void transportErrorsAreRetriedAndRecorded() throws Exception {
        JobStore store = store();
        AtomicInteger calls = new AtomicInteger();
        CallbackDispatcher d = dispatcher(config(Duration.ofMillis(20)), store, (url, body, headers) -> {
            if (calls.incrementAndGet() == 1) throw new IOException("connection refused");
            return 204;
        });
        Job job = newJob(store, URL, JobStatus.DELIVERED);
        d.fire(job.id, "delivered");
        await(() -> "delivered".equals(callbackState(store, job.id).status));
        assertEquals(2, calls.get());
        assertEquals(204, callbackState(store, job.id).lastHttpStatus);
    }

    @Test
    void givesUpAfterMaxRetryDuration() throws Exception {
        JobStore store = store();
        FakeTransport t = new FakeTransport();
        for (int i = 0; i < 100; i++) t.answers.add(503);
        Config config = config(Duration.ofMillis(30));
        config.callbackMaxRetryDuration = Duration.ofMillis(100);
        CallbackDispatcher d = dispatcher(config, store, t);
        Job job = newJob(store, URL, JobStatus.FAILED);
        d.fire(job.id, "failed");
        await(() -> "failed".equals(callbackState(store, job.id).status));
        Job.CallbackState cb = callbackState(store, job.id);
        assertEquals(503, cb.lastHttpStatus);
        assertEquals("HTTP 503", cb.lastError);
        assertNull(cb.nextAttemptAt);
        assertTrue(cb.attempts >= 2);
        assertEquals(0, d.pendingCount());
    }

    @Test
    void pendingEventsSurviveARestart() throws Exception {
        JobStore store = store();
        FakeTransport failing = new FakeTransport();
        failing.answers.add(500);
        Config config = config(Duration.ofHours(1));
        config.callbackMaxRetryDuration = Duration.ofHours(24);
        CallbackDispatcher first = dispatcher(config, store, failing);
        Job job = newJob(store, URL, JobStatus.DELIVERED);
        first.fire(job.id, "delivered");
        Sent original = failing.next();
        await(() -> callbackState(store, job.id).attempts == 1);
        // the outbox file is rewritten after the job: wait for it too, or the edit below races that write
        Path outboxDir = dataDir.resolve("callbacks");
        await(() -> {
            try (var files = java.nio.file.Files.list(outboxDir)) {
                return files.filter(f -> f.getFileName().toString().endsWith(".json")).anyMatch(f -> {
                    try {
                        return java.nio.file.Files.readString(f).contains("\"attempts\":1");
                    } catch (IOException e) {
                        return false;
                    }
                });
            } catch (IOException e) {
                return false;
            }
        });
        first.close();
        assertEquals(1, first.pendingCount());

        // the next process retries it (here immediately, by moving the scheduled time forward)
        config.callbackRetrySchedule = List.of(Duration.ofMillis(10));
        FakeTransport ok = new FakeTransport();
        CallbackDispatcher second = dispatcher(config, store, ok);
        Path file;
        try (var files = java.nio.file.Files.list(dataDir.resolve("callbacks"))) {
            file = files.filter(f -> f.getFileName().toString().endsWith(".json")).findFirst().orElseThrow();
        }
        String stored = java.nio.file.Files.readString(file);
        java.nio.file.Files.writeString(file, stored.replaceAll("\"nextAttemptAt\":\"[^\"]+\"",
                "\"nextAttemptAt\":\"" + Instant.now() + "\""));
        assertEquals(1, second.resumeAll());
        Sent resent = ok.next();
        assertEquals(original.body(), resent.body());
        await(() -> "delivered".equals(callbackState(store, job.id).status));
        assertEquals(2, callbackState(store, job.id).attempts);
    }

    // ---- SSRF guard ----

    private CallbackDispatcher guarded(Config config, JobStore store, CallbackDispatcher.Transport t,
                                       CallbackDispatcher.Resolver r) throws IOException {
        CallbackDispatcher d = new CallbackDispatcher(config, store, executor, t, r);
        closeables.add(d);
        return d;
    }

    private static CallbackDispatcher.Resolver resolvesTo(String... ips) {
        return host -> {
            InetAddress[] out = new InetAddress[ips.length];
            for (int i = 0; i < ips.length; i++) out[i] = InetAddress.getByName(ips[i]);
            return out;
        };
    }

    @Test
    void ssrfGuardRefusesPrivateTargetsWithoutSendingOrRetrying() throws Exception {
        for (String ip : List.of("127.0.0.1", "10.1.2.3", "192.168.0.10", "169.254.169.254", "::1", "fd00::1",
                "::ffff:127.0.0.1")) {
            JobStore store = store();
            FakeTransport t = new FakeTransport();
            Config config = config();
            config.blockPrivateCallbackTargets = true;
            CallbackDispatcher d = guarded(config, store, t, resolvesTo(ip));
            Job job = newJob(store, URL, JobStatus.DELIVERED);
            d.fire(job.id, "delivered");
            await(() -> "failed".equals(callbackState(store, job.id).status));
            Job.CallbackState cb = callbackState(store, job.id);
            assertTrue(cb.lastError.startsWith("CALLBACK_TARGET_BLOCKED"), ip + ": " + cb.lastError);
            assertNull(cb.nextAttemptAt);
            assertNull(cb.lastHttpStatus);
            assertEquals(1, cb.attempts);
            assertEquals(0, d.pendingCount());
            assertTrue(t.sent.isEmpty(), ip + " must not be contacted");
        }
    }

    @Test
    void ssrfGuardRefusesWhenAnyResolvedAddressIsPrivate() throws Exception {
        JobStore store = store();
        FakeTransport t = new FakeTransport();
        Config config = config();
        config.blockPrivateCallbackTargets = true;
        CallbackDispatcher d = guarded(config, store, t, resolvesTo("93.184.216.34", "10.0.0.1"));
        Job job = newJob(store, URL, JobStatus.DELIVERED);
        d.fire(job.id, "delivered");
        await(() -> "failed".equals(callbackState(store, job.id).status));
        assertTrue(t.sent.isEmpty());
    }

    @Test
    void ssrfGuardAllowsPublicTargets() throws Exception {
        JobStore store = store();
        FakeTransport t = new FakeTransport();
        Config config = config();
        config.blockPrivateCallbackTargets = true;
        CallbackDispatcher d = guarded(config, store, t, resolvesTo("93.184.216.34", "2606:2800:220:1::1"));
        Job job = newJob(store, URL, JobStatus.DELIVERED);
        d.fire(job.id, "delivered");
        assertEquals(URI.create(URL), t.next().url());
        await(() -> "delivered".equals(callbackState(store, job.id).status));
    }

    @Test
    void ssrfGuardOffAllowsPrivateTargets() throws Exception {
        JobStore store = store();
        FakeTransport t = new FakeTransport();
        Config config = config();
        assertFalse(config.blockPrivateCallbackTargets, "the guard is off by default");
        AtomicInteger lookups = new AtomicInteger();
        CallbackDispatcher d = guarded(config, store, t, host -> {
            lookups.incrementAndGet();
            return new InetAddress[]{InetAddress.getLoopbackAddress()};
        });
        Job job = newJob(store, URL, JobStatus.DELIVERED);
        d.fire(job.id, "delivered");
        t.next();
        await(() -> "delivered".equals(callbackState(store, job.id).status));
        assertEquals(0, lookups.get());
    }

    @Test
    void ssrfGuardRetriesUnresolvableHosts() throws Exception {
        JobStore store = store();
        FakeTransport t = new FakeTransport();
        Config config = config(Duration.ofMillis(20));
        config.blockPrivateCallbackTargets = true;
        AtomicInteger lookups = new AtomicInteger();
        CallbackDispatcher d = guarded(config, store, t, host -> {
            if (lookups.incrementAndGet() == 1) throw new java.net.UnknownHostException(host);
            return new InetAddress[]{InetAddress.getByName("93.184.216.34")};
        });
        Job job = newJob(store, URL, JobStatus.DELIVERED);
        d.fire(job.id, "delivered");
        t.next();
        await(() -> "delivered".equals(callbackState(store, job.id).status));
        assertEquals(2, callbackState(store, job.id).attempts);
    }

    @Test
    void ssrfGuardBlocksARealLoopbackServer() throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
        AtomicInteger hits = new AtomicInteger();
        server.createContext("/hook", ex -> {
            hits.incrementAndGet();
            ex.sendResponseHeaders(204, -1);
            ex.close();
        });
        server.start();
        closeables.add(() -> server.stop(0));
        JobStore store = store();
        Config config = config();
        config.blockPrivateCallbackTargets = true;
        CallbackDispatcher d = new CallbackDispatcher(config, store, executor);
        closeables.add(d);
        Job job = newJob(store, "http://localhost:" + server.getAddress().getPort() + "/hook", JobStatus.DELIVERED);
        d.fire(job.id, "delivered");
        await(() -> "failed".equals(callbackState(store, job.id).status));
        assertEquals(0, hits.get());
    }

    @Test
    void httpTransportPostsToARealServer() throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
        LinkedBlockingQueue<String> received = new LinkedBlockingQueue<>();
        server.createContext("/hook", ex -> {
            String sig = ex.getRequestHeaders().getFirst(CallbackDispatcher.SIGNATURE_HEADER);
            byte[] body = ex.getRequestBody().readAllBytes();
            received.add(CallbackDispatcher.verifySignature(SECRET, body, sig) + " " + ex.getRequestMethod());
            ex.sendResponseHeaders(204, -1);
            ex.close();
        });
        server.start();
        closeables.add(() -> server.stop(0));
        JobStore store = store();
        Config config = config();
        CallbackDispatcher d = new CallbackDispatcher(config, store, executor);
        closeables.add(d);
        Job job = newJob(store, "http://127.0.0.1:" + server.getAddress().getPort() + "/hook", JobStatus.DELIVERED);
        d.fire(job.id, "delivered");
        assertEquals("true POST", received.poll(5, TimeUnit.SECONDS));
        await(() -> "delivered".equals(callbackState(store, job.id).status));
        assertEquals(204, callbackState(store, job.id).lastHttpStatus);
    }

    @Test
    void signatureIsHexHmacSha256() {
        // RFC 4231 test case 2
        assertEquals("sha256=5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
                CallbackDispatcher.signature("Jefe", "what do ya want for nothing?".getBytes(StandardCharsets.UTF_8)));
    }

    @Test
    void verifySignatureRejectsTamperedBodiesAndMalformedHeaders() {
        byte[] body = "{\"event\":\"delivered\"}".getBytes(StandardCharsets.UTF_8);
        String sig = CallbackDispatcher.signature(SECRET, body);
        assertTrue(CallbackDispatcher.verifySignature(SECRET, body, sig));
        assertTrue(CallbackDispatcher.verifySignature(SECRET, body, " " + sig.toUpperCase(java.util.Locale.ROOT) + " "));
        assertFalse(CallbackDispatcher.verifySignature(SECRET,
                "{\"event\":\"failed\"}".getBytes(StandardCharsets.UTF_8), sig));
        assertFalse(CallbackDispatcher.verifySignature(SECRET, body, null));
        assertFalse(CallbackDispatcher.verifySignature(SECRET, body, ""));
        assertFalse(CallbackDispatcher.verifySignature(SECRET, body, sig.substring("sha256=".length())));
        assertFalse(CallbackDispatcher.verifySignature(SECRET, body, sig.substring(0, sig.length() - 1)));
        assertFalse(CallbackDispatcher.verifySignature(SECRET, body, "sha1=" + sig.substring("sha256=".length())));
    }
}
