package io.siggi.simplemailer.inbound;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import io.siggi.simplemailer.callback.CallbackDispatcher;
import io.siggi.simplemailer.config.Config;
import io.siggi.simplemailer.inbound.BounceProcessor.Outcome;
import io.siggi.simplemailer.inbound.BounceProcessor.Result;
import io.siggi.simplemailer.inbound.BounceProcessor.Source;
import io.siggi.simplemailer.model.Job;
import io.siggi.simplemailer.model.JobStatus;
import io.siggi.simplemailer.model.RecipientResult;
import io.siggi.simplemailer.model.SendRequest;
import io.siggi.simplemailer.store.JobStore;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.Callable;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class BounceProcessorTest {
    private static final String DOMAIN = "bounces.example.com";
    private static final String URL = "https://caller.test/hook";

    @TempDir
    Path dataDir;

    private final ExecutorService executor = Executors.newVirtualThreadPerTaskExecutor();
    private final LinkedBlockingQueue<String> callbacks = new LinkedBlockingQueue<>();
    private JobStore store;
    private CallbackDispatcher dispatcher;
    private VerpAddress verp;
    private BounceProcessor processor;

    @BeforeEach
    void setUp() throws Exception {
        Config config = new Config();
        config.dataDir = dataDir.toString();
        config.publicBaseUrl = "https://mailer.test";
        config.callbackRetrySchedule = new ArrayList<>(List.of(Duration.ofMillis(20)));
        store = new JobStore(dataDir);
        dispatcher = new CallbackDispatcher(config, store, executor,
                (URI url, byte[] body, Map<String, String> headers) -> {
                    callbacks.add(new String(body, StandardCharsets.UTF_8));
                    return 200;
                });
        verp = new VerpAddress(DOMAIN, "bounce-secret");
        processor = new BounceProcessor(dataDir, store, verp, dispatcher);
    }

    @AfterEach
    void tearDown() throws Exception {
        dispatcher.close();
        // let in-flight callback attempts finish recording before the temp directory goes away
        executor.shutdown();
        if (!executor.awaitTermination(5, TimeUnit.SECONDS)) executor.shutdownNow();
    }

    /** A job whose recipients are all delivered. */
    private Job deliveredJob(String... rcpts) throws Exception {
        SendRequest req = new SendRequest();
        req.id = UUID.randomUUID().toString();
        req.from = "sender@example.test";
        req.to = List.of(rcpts);
        req.subject = "hi";
        req.text = "hello";
        req.callbackUrl = URL;
        Job job = Job.create(req, "hash", Instant.now(), JobStatus.QUEUED);
        store.create(job.id, "hash", () -> job);
        return store.update(job.id, j -> {
            Instant now = Instant.now();
            for (RecipientResult r : j.recipients) r.markDelivered(now, "mx.test", 250, "OK", true);
            j.recomputeStatus(now);
            // the delivery callback was already sent
            j.callback.terminalNotified = true;
        }).orElseThrow();
    }

    private static byte[] crlf(String s) {
        return s.replace("\r\n", "\n").replace("\n", "\r\n").getBytes(StandardCharsets.UTF_8);
    }

    private static byte[] dsn(String messageId, String verpAddress, String action, String status, String... rcpts) {
        StringBuilder groups = new StringBuilder();
        for (String r : rcpts) {
            groups.append("\nFinal-Recipient: rfc822; ").append(r)
                    .append("\nAction: ").append(action)
                    .append("\nStatus: ").append(status)
                    .append("\nDiagnostic-Code: smtp; 550 ").append(status).append(" user unknown\n");
        }
        return crlf("""
                Return-Path: <>
                From: MAILER-DAEMON@mx.example.org
                To: %s
                Subject: Undelivered Mail Returned to Sender
                Message-ID: %s
                MIME-Version: 1.0
                Content-Type: multipart/report; report-type=delivery-status; boundary="BND"

                --BND
                Content-Type: text/plain

                Your message could not be delivered.

                --BND
                Content-Type: message/delivery-status

                Reporting-MTA: dns; mx.example.org
                %s
                --BND--
                """.formatted(verpAddress, messageId, groups));
    }

    private static byte[] autoReply(String messageId, String verpAddress) {
        return crlf("""
                From: someone@x.test
                To: %s
                Subject: Out of office
                Message-ID: %s
                Auto-Submitted: auto-replied

                I am away.
                """.formatted(verpAddress, messageId));
    }

    private String nextCallback() throws InterruptedException {
        String body = callbacks.poll(5, TimeUnit.SECONDS);
        assertNotNull(body, "expected a callback");
        return body;
    }

    @Test
    void failedDsnMarksRecipientBouncedStoresRawAndFiresCallback() throws Exception {
        Job job = deliveredJob("a@x.test");
        String address = verp.encode(job.id, 0);
        byte[] raw = dsn("<b1@mx.example.org>", address, "failed", "5.1.1", "a@x.test");

        Result result = processor.processMessage(raw, address, "", Source.SMTP);

        assertEquals(Outcome.APPLIED, result.outcome());
        assertEquals(job.id, result.jobId());
        assertEquals(0, result.recipientIndex());
        assertNotNull(result.eventId());

        Job after = store.get(job.id).orElseThrow();
        assertEquals(JobStatus.BOUNCED, after.status);
        RecipientResult r = after.recipient(0);
        assertEquals(RecipientResult.Status.BOUNCED, r.status);
        assertEquals("5.1.1", r.dsnStatus);
        assertEquals("550 5.1.1 user unknown", r.dsnDiagnostic);
        assertNotNull(r.bouncedAt);
        assertNotNull(r.deliveredAt, "delivered → bounced keeps the delivery time");

        assertEquals(1, after.bounces.size());
        Job.BounceRecord b = after.bounces.get(0);
        assertEquals("smtp", b.source);
        assertEquals(BounceProcessor.KIND_DSN, b.kind);
        assertEquals("failed", b.action);
        assertFalse(b.ignored);
        assertEquals("a@x.test", b.recipient);
        assertNull(b.finalRecipient);
        assertEquals("message-id:<b1@mx.example.org>", b.dedupeKey);
        assertEquals("bounces/" + job.id + "-1.eml", b.file);
        assertArrayEquals(raw, Files.readAllBytes(dataDir.resolve(b.file)));

        JsonObject event = JsonParser.parseString(nextCallback()).getAsJsonObject();
        assertEquals("bounced", event.get("event").getAsString());
        assertEquals(result.eventId(), event.get("eventId").getAsString());
        assertEquals("bounced", event.getAsJsonObject("job").get("status").getAsString());
    }

    @Test
    void duplicateBounceChangesNothingAndFiresNoSecondCallback() throws Exception {
        Job job = deliveredJob("a@x.test");
        String address = verp.encode(job.id, 0);
        byte[] raw = dsn("<b1@mx.example.org>", address, "failed", "5.1.1", "a@x.test");

        assertEquals(Outcome.APPLIED, processor.processMessage(raw, address, "", Source.SMTP).outcome());
        nextCallback();
        // the same DSN again, through the other intake
        Result again = processor.processMessage(raw, address, null, Source.API);
        assertEquals(Outcome.DUPLICATE, again.outcome());
        assertNull(again.eventId());
        // same Message-ID, slightly different bytes: still a duplicate
        byte[] variant = dsn("<b1@mx.example.org>", address, "failed", "5.1.2", "a@x.test");
        assertEquals(Outcome.DUPLICATE, processor.processMessage(variant, address, "", Source.SMTP).outcome());

        assertEquals(1, store.get(job.id).orElseThrow().bounces.size());
        assertNull(callbacks.poll(300, TimeUnit.MILLISECONDS));
        try (var files = Files.list(dataDir.resolve("bounces"))) {
            assertEquals(1, files.count());
        }
    }

    @Test
    void concurrentDuplicatesAreAppliedOnce() throws Exception {
        Job job = deliveredJob("a@x.test");
        String address = verp.encode(job.id, 0);
        byte[] raw = dsn("<b1@mx.example.org>", address, "failed", "5.1.1", "a@x.test");
        CountDownLatch start = new CountDownLatch(1);
        List<Future<Result>> futures = new ArrayList<>();
        for (int i = 0; i < 8; i++) {
            Callable<Result> task = () -> {
                start.await();
                return processor.processMessage(raw, address, "", Source.SMTP);
            };
            futures.add(executor.submit(task));
        }
        start.countDown();
        int applied = 0;
        for (Future<Result> f : futures) {
            Outcome o = f.get(5, TimeUnit.SECONDS).outcome();
            if (o == Outcome.APPLIED) applied++;
            else assertEquals(Outcome.DUPLICATE, o);
        }
        assertEquals(1, applied);
        assertEquals(1, store.get(job.id).orElseThrow().bounces.size());
    }

    @Test
    void bounceForOneOfTwoRecipientsMakesJobPartiallyFailed() throws Exception {
        Job job = deliveredJob("a@x.test", "b@y.test");
        String address = verp.encode(job.id, 1);
        // the DSN lists another address first; the VERP-identified recipient's group is used
        byte[] raw = dsn("<b2@mx.example.org>", address, "failed", "5.1.1", "other@y.test", "b@y.test");

        assertEquals(Outcome.APPLIED, processor.processMessage(raw, address, "", Source.SMTP).outcome());

        Job after = store.get(job.id).orElseThrow();
        assertEquals(JobStatus.PARTIALLY_FAILED, after.status);
        assertEquals(RecipientResult.Status.DELIVERED, after.recipient(0).status);
        assertEquals(RecipientResult.Status.BOUNCED, after.recipient(1).status);
        assertEquals(1, after.bounces.get(0).recipientIndex);
        assertEquals("b@y.test", after.bounces.get(0).recipient);
        assertEquals("partially_failed", JsonParser.parseString(nextCallback()).getAsJsonObject()
                .getAsJsonObject("job").get("status").getAsString());
    }

    @Test
    void forwardedRecipientIsRecordedAsFinalRecipient() throws Exception {
        Job job = deliveredJob("a@x.test");
        String address = verp.encode(job.id, 0);
        byte[] raw = dsn("<b3@mx.example.org>", address, "failed", "5.2.2", "forwarded@z.test");

        assertEquals(Outcome.APPLIED, processor.processMessage(raw, address, "", Source.SMTP).outcome());
        Job after = store.get(job.id).orElseThrow();
        assertEquals("forwarded@z.test", after.bounces.get(0).finalRecipient);
        assertEquals("5.2.2", after.recipient(0).dsnStatus);
    }

    @Test
    void delayedDsnIsNotedWithoutChangingStatus() throws Exception {
        Job job = deliveredJob("a@x.test");
        String address = verp.encode(job.id, 0);
        byte[] raw = dsn("<d1@mx.example.org>", address, "delayed", "4.4.7", "a@x.test");

        Result result = processor.processMessage(raw, address, "", Source.SMTP);

        assertEquals(Outcome.NOTED, result.outcome());
        Job after = store.get(job.id).orElseThrow();
        assertEquals(JobStatus.DELIVERED, after.status);
        assertEquals(RecipientResult.Status.DELIVERED, after.recipient(0).status);
        Job.BounceRecord b = after.bounces.get(0);
        assertEquals("delayed", b.action);
        assertTrue(b.ignored);
        assertEquals("4.4.7", b.status);
        assertNull(callbacks.poll(300, TimeUnit.MILLISECONDS));
    }

    @Test
    void autoReplyIsRecordedAsIgnored() throws Exception {
        Job job = deliveredJob("a@x.test");
        String address = verp.encode(job.id, 0);

        Result result = processor.processMessage(autoReply("<ar1@x.test>", address), address, "someone@x.test",
                Source.SMTP);

        assertEquals(Outcome.IGNORED, result.outcome());
        Job after = store.get(job.id).orElseThrow();
        assertEquals(JobStatus.DELIVERED, after.status);
        Job.BounceRecord b = after.bounces.get(0);
        assertEquals(BounceProcessor.KIND_AUTO_REPLY, b.kind);
        assertTrue(b.ignored);
        assertNotNull(b.file);
        assertNull(callbacks.poll(300, TimeUnit.MILLISECONDS));
    }

    @Test
    void nonDsnBounceFromNullSenderIsApplied() throws Exception {
        Job job = deliveredJob("a@x.test");
        String address = verp.encode(job.id, 0);
        byte[] raw = crlf("""
                From: postmaster@x.test
                To: %s
                Subject: Delivery failure
                Message-ID: <nd1@x.test>

                Delivery to a@x.test failed: 550 5.1.1 mailbox unavailable
                """.formatted(address));

        assertEquals(Outcome.APPLIED, processor.processMessage(raw, address, "<>", Source.SMTP).outcome());
        Job after = store.get(job.id).orElseThrow();
        assertEquals(RecipientResult.Status.BOUNCED, after.recipient(0).status);
        assertEquals("5.1.1", after.recipient(0).dsnStatus);
        assertEquals(BounceProcessor.KIND_NON_DSN_BOUNCE, after.bounces.get(0).kind);
        nextCallback();
    }

    @Test
    void addressesAreVerified() throws Exception {
        Job job = deliveredJob("a@x.test");
        String good = verp.encode(job.id, 0);
        byte[] raw = dsn("<b1@mx.example.org>", good, "failed", "5.1.1", "a@x.test");

        String forged = good.replaceFirst("\\.[0-9a-f]{16}@", ".0000000000000000@");
        assertEquals(Outcome.BAD_TAG, processor.processMessage(raw, forged, "", Source.SMTP).outcome());
        assertEquals(Outcome.BAD_TAG, processor.checkAddress(forged).outcome());
        // a valid tag signed with another secret doesn't verify either
        String otherSecret = new VerpAddress(DOMAIN, "other").encode(job.id, 0);
        assertEquals(Outcome.BAD_TAG, processor.processMessage(raw, otherSecret, "", Source.API).outcome());
        assertEquals(Outcome.NOT_BOUNCE_ADDRESS,
                processor.processMessage(raw, "postmaster@" + DOMAIN, "", Source.SMTP).outcome());
        assertEquals(Outcome.NOT_BOUNCE_ADDRESS,
                processor.processMessage(raw, good.replace(DOMAIN, "evil.test"), "", Source.SMTP).outcome());
        // properly signed, but the job or recipient doesn't exist
        String unknownJob = verp.encode(UUID.randomUUID().toString(), 0);
        assertEquals(Outcome.UNKNOWN_JOB, processor.processMessage(raw, unknownJob, "", Source.SMTP).outcome());
        assertEquals(Outcome.UNKNOWN_JOB, processor.processMessage(raw, verp.encode(job.id, 1), "", Source.SMTP)
                .outcome());

        assertTrue(processor.checkAddress(good).accepted());
        assertTrue(processor.checkAddress("<" + good.toUpperCase() + ">").accepted());
        Job after = store.get(job.id).orElseThrow();
        assertEquals(JobStatus.DELIVERED, after.status);
        assertTrue(after.bounces.isEmpty());
        assertNull(callbacks.poll(200, TimeUnit.MILLISECONDS));
    }

    @Test
    void preParsedReportIsAppliedAndDeduplicated() throws Exception {
        Job job = deliveredJob("a@x.test");
        String address = verp.encode(job.id, 0);
        BounceProcessor.Report report = new BounceProcessor.Report("Failed", "5.1.1", "550 5.1.1 user unknown",
                "a@x.test");

        Result result = processor.processReport(address, report, Source.API);

        assertEquals(Outcome.APPLIED, result.outcome());
        Job after = store.get(job.id).orElseThrow();
        assertEquals(JobStatus.BOUNCED, after.status);
        assertEquals("550 5.1.1 user unknown", after.recipient(0).dsnDiagnostic);
        Job.BounceRecord b = after.bounces.get(0);
        assertEquals("api", b.source);
        assertEquals(BounceProcessor.KIND_REPORT, b.kind);
        assertEquals("failed", b.action);
        assertNull(b.file);
        nextCallback();

        assertEquals(Outcome.DUPLICATE, processor.processReport(address, report, Source.API).outcome());
        assertNull(callbacks.poll(300, TimeUnit.MILLISECONDS));

        // without an action, a 4.x.x status is a delay
        BounceProcessor.Report delayed = new BounceProcessor.Report(null, "4.2.2", "mailbox full", null);
        assertEquals(Outcome.NOTED, processor.processReport(address, delayed, Source.API).outcome());
    }

    @Test
    void recordsPerRecipientAreCapped() throws Exception {
        Job job = deliveredJob("a@x.test");
        String address = verp.encode(job.id, 0);
        for (int i = 0; i < BounceProcessor.MAX_RECORDS_PER_RECIPIENT; i++) {
            assertEquals(Outcome.IGNORED, processor.processMessage(autoReply("<ar" + i + "@x.test>", address),
                    address, "someone@x.test", Source.SMTP).outcome());
        }
        Result dropped = processor.processMessage(autoReply("<ar-extra@x.test>", address), address,
                "someone@x.test", Source.SMTP);
        assertEquals(Outcome.IGNORED, dropped.outcome());
        assertEquals(BounceProcessor.MAX_RECORDS_PER_RECIPIENT, store.get(job.id).orElseThrow().bounces.size());

        // a real bounce still gets through
        byte[] raw = dsn("<b1@mx.example.org>", address, "failed", "5.1.1", "a@x.test");
        assertEquals(Outcome.APPLIED, processor.processMessage(raw, address, "", Source.SMTP).outcome());
        Job after = store.get(job.id).orElseThrow();
        assertEquals(RecipientResult.Status.BOUNCED, after.recipient(0).status);
        assertEquals(BounceProcessor.MAX_RECORDS_PER_RECIPIENT + 1, after.bounces.size());
    }

    @Test
    void worksWithoutCallbackDispatcher() throws Exception {
        BounceProcessor noCallbacks = new BounceProcessor(dataDir, store, verp, null);
        Job job = deliveredJob("a@x.test");
        String address = verp.encode(job.id, 0);
        Result result = noCallbacks.processMessage(dsn("<b1@mx.example.org>", address, "failed", "5.1.1",
                "a@x.test"), address, "", Source.SMTP);
        assertEquals(Outcome.APPLIED, result.outcome());
        assertNull(result.eventId());
        assertNull(callbacks.poll(200, TimeUnit.MILLISECONDS));
    }
}
