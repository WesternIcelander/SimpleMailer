package io.siggi.simplemailer.delivery;

import io.siggi.simplemailer.config.Config;
import io.siggi.simplemailer.model.Job;
import io.siggi.simplemailer.model.JobStatus;
import io.siggi.simplemailer.model.RecipientResult;
import io.siggi.simplemailer.model.SendRequest;
import io.siggi.simplemailer.inbound.VerpAddress;
import io.siggi.simplemailer.smtp.FakeSmtpServer;
import io.siggi.simplemailer.smtp.MxResolver;
import io.siggi.simplemailer.smtp.TestCertificate;
import io.siggi.simplemailer.smtp.TlsPolicy;
import io.siggi.simplemailer.store.JobStore;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import javax.net.ssl.SSLContext;
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class DeliveryEngineTest {
    @TempDir
    Path dataDir;
    @TempDir
    static Path certDir;
    /** Self-signed certificate for {@link #TLS_MX}. */
    private static TestCertificate cert;
    private static final String TLS_MX = "mx.tls.test";
    /** Context the engine uses for {@code verifyCertificate}; {@code null} = JDK default trust store. */
    private SSLContext verifyingContext;

    private JobStore store;
    private ExecutorService executor;
    private final List<FakeSmtpServer> servers = new ArrayList<>();
    /** domain → MX records ("pref host"); a missing domain is NXDOMAIN. */
    private final Map<String, List<String>> mxRecords = new ConcurrentHashMap<>();
    /** MX host name → local endpoint. */
    private final Map<String, InetSocketAddress> endpoints = new ConcurrentHashMap<>();

    @BeforeAll
    static void createCertificate() throws Exception {
        cert = TestCertificate.create(certDir, TLS_MX);
    }

    @BeforeEach
    void setUp() throws Exception {
        store = new JobStore(dataDir);
        executor = Executors.newVirtualThreadPerTaskExecutor();
    }

    @AfterEach
    void tearDown() throws Exception {
        executor.shutdownNow();
        for (FakeSmtpServer s : servers) s.close();
    }

    private FakeSmtpServer server(String mxHost) throws IOException {
        FakeSmtpServer s = new FakeSmtpServer();
        servers.add(s);
        endpoints.put(mxHost, s.address());
        return s;
    }

    /** An endpoint where nothing listens (connection refused). */
    private void deadHost(String mxHost) throws IOException {
        try (ServerSocket ss = new ServerSocket(0, 1, InetAddress.getLoopbackAddress())) {
            endpoints.put(mxHost, new InetSocketAddress(InetAddress.getLoopbackAddress(), ss.getLocalPort()));
        }
    }

    private MxResolver resolver() {
        return new MxResolver((name, type) -> {
            List<String> mx = mxRecords.get(name);
            if (mx == null) throw new MxResolver.NameNotFound(name);
            return type.equals("MX") ? mx : List.of();
        }, host -> new InetAddress[]{InetAddress.getLoopbackAddress()}, null);
    }

    private DeliveryEngine engine(int maxConcurrent) throws Exception {
        return engine(maxConcurrent, null);
    }

    private DeliveryEngine engine(int maxConcurrent, DeliveryEngine.EnvelopeSender envelopeSender) throws Exception {
        Config config = Config.fromJson("{\"heloName\": \"sender.example.com\", \"connectTimeout\": \"2s\","
                + " \"readTimeout\": \"5s\", \"maxConcurrentDeliveries\": " + maxConcurrent
                + ", \"retrySchedule\": [\"1m\", \"5m\"]}");
        DeliveryEngine.Options options = new DeliveryEngine.Options();
        options.endpoints = (mx, address) -> {
            InetSocketAddress e = endpoints.get(mx.host());
            if (e == null) throw new IllegalStateException("no endpoint for " + mx.host());
            return e;
        };
        options.verifyingContext = verifyingContext;
        if (envelopeSender != null) options.envelopeSender = envelopeSender;
        return new DeliveryEngine(config, store, resolver(), executor, options);
    }

    private String createJob(String... recipients) throws Exception {
        return createJob(false, false, recipients);
    }

    private String createJob(boolean requireTls, boolean verifyCertificate, String... recipients) throws Exception {
        SendRequest send = new SendRequest();
        send.requireTls = requireTls;
        send.verifyCertificate = verifyCertificate;
        send.id = UUID.randomUUID().toString();
        send.from = "sender@example.com";
        send.to = List.of(recipients);
        send.subject = "Hello";
        send.text = "Hi there";
        assertTrue(send.validate().isEmpty(), send.validate().toString());
        store.create(send.id, JobStore.payloadHash(send), () -> {
            store.writePayload(send.id, "Subject: Hello\r\n\r\nHi there\r\n".getBytes(StandardCharsets.UTF_8));
            return Job.create(send, "x", Instant.now(), JobStatus.QUEUED);
        });
        return send.id;
    }

    private static long count(FakeSmtpServer s, String prefix) {
        return s.commands.stream().filter(c -> c.toUpperCase().startsWith(prefix)).count();
    }

    @Test
    void deliversEachDomainSeparately() throws Exception {
        mxRecords.put("one.test", List.of("10 mx.one.test"));
        mxRecords.put("two.test", List.of("10 mx.two.test"));
        FakeSmtpServer one = server("mx.one.test");
        FakeSmtpServer two = server("mx.two.test");
        String id = createJob("a@one.test", "b@two.test", "c@one.test");

        Job job = engine(10).deliver(id).orElseThrow();

        assertEquals(JobStatus.DELIVERED, job.status);
        for (RecipientResult r : job.recipients) {
            assertEquals(RecipientResult.Status.DELIVERED, r.status, r.address);
            assertEquals(1, r.attempts);
            assertEquals(250, r.smtpCode);
            assertEquals(Boolean.FALSE, r.tls);
        }
        assertEquals("mx.one.test", job.recipients.get(0).mx);
        assertEquals("mx.two.test", job.recipients.get(1).mx);
        // one transaction per domain, carrying only that domain's recipients
        assertEquals(1, one.messages.size());
        assertEquals(1, two.messages.size());
        assertTrue(one.commands.containsAll(List.of("RCPT TO:<a@one.test>", "RCPT TO:<c@one.test>")));
        assertEquals(2, count(one, "RCPT"));
        assertEquals(List.of("RCPT TO:<b@two.test>"), two.commands.stream().filter(c -> c.startsWith("RCPT")).toList());
        assertTrue(one.commands.get(0).startsWith("EHLO sender.example.com"));
        assertTrue(one.commands.stream().anyMatch(c -> c.startsWith("MAIL FROM:<sender@example.com>")));
        assertEquals("Subject: Hello\r\n\r\nHi there\r\n", new String(one.messages.get(0), StandardCharsets.UTF_8));
        // persisted
        assertEquals(JobStatus.DELIVERED, store.get(id).orElseThrow().status);
    }

    @Test
    void verpMailFromIsPerRecipient() throws Exception {
        mxRecords.put("one.test", List.of("10 mx.one.test"));
        FakeSmtpServer one = server("mx.one.test");
        String id = createJob("a@one.test", "c@one.test");
        VerpAddress verp = new VerpAddress("bounces.example.com", "secret");

        Job job = engine(10, verp.envelopeSender()).deliver(id).orElseThrow();

        assertEquals(JobStatus.DELIVERED, job.status);
        // each recipient has its own reverse path, so each gets its own transaction
        assertEquals(2, one.messages.size());
        List<String> mailFroms = one.commands.stream().filter(c -> c.startsWith("MAIL FROM:")).toList();
        assertEquals(2, mailFroms.size());
        for (int i = 0; i < 2; i++) {
            String address = verp.encode(id, i);
            assertTrue(mailFroms.stream().anyMatch(c -> c.startsWith("MAIL FROM:<" + address + ">")), mailFroms.toString());
            VerpAddress.Verification v = verp.verify(address);
            assertTrue(v.valid());
            assertEquals(id, v.address().jobId());
            assertEquals(i, v.address().recipientIndex());
        }
    }

    @Test
    void failsOverToNextMxInPreferenceOrder() throws Exception {
        mxRecords.put("x.test", List.of("30 mx3.x.test", "10 mx1.x.test", "20 mx2.x.test"));
        deadHost("mx1.x.test");
        FakeSmtpServer mx2 = server("mx2.x.test");
        mx2.greeting = "421 4.3.2 too busy\r\n";
        FakeSmtpServer mx3 = server("mx3.x.test");
        String id = createJob("a@x.test");

        Job job = engine(10).deliver(id).orElseThrow();

        RecipientResult r = job.recipients.get(0);
        assertEquals(RecipientResult.Status.DELIVERED, r.status);
        assertEquals("mx3.x.test", r.mx);
        assertEquals(0, count(mx2, "MAIL"));
        assertEquals(1, mx3.messages.size());
    }

    @Test
    void temporaryRcptFailureTriesNextMx() throws Exception {
        mxRecords.put("x.test", List.of("10 mx1.x.test", "20 mx2.x.test"));
        FakeSmtpServer mx1 = server("mx1.x.test");
        mx1.handler = c -> c.startsWith("RCPT") ? "451 4.7.1 greylisted\r\n" : FakeSmtpServer.defaultReply(c);
        FakeSmtpServer mx2 = server("mx2.x.test");
        String id = createJob("a@x.test");

        Job job = engine(10).deliver(id).orElseThrow();

        assertEquals(RecipientResult.Status.DELIVERED, job.recipients.get(0).status);
        assertEquals("mx2.x.test", job.recipients.get(0).mx);
        assertEquals(0, mx1.messages.size());
        assertEquals(1, mx2.messages.size());
    }

    @Test
    void permanentRcptFailureIsFinalAndDoesNotFailOver() throws Exception {
        mxRecords.put("x.test", List.of("10 mx1.x.test", "20 mx2.x.test"));
        FakeSmtpServer mx1 = server("mx1.x.test");
        mx1.handler = c -> c.equals("RCPT TO:<bad@x.test>") ? "550 5.1.1 no such user\r\n"
                : FakeSmtpServer.defaultReply(c);
        FakeSmtpServer mx2 = server("mx2.x.test");
        String id = createJob("good@x.test", "bad@x.test");

        Job job = engine(10).deliver(id).orElseThrow();

        assertEquals(RecipientResult.Status.DELIVERED, job.recipients.get(0).status);
        RecipientResult bad = job.recipients.get(1);
        assertEquals(RecipientResult.Status.FAILED, bad.status);
        assertEquals(550, bad.smtpCode);
        assertEquals(DeliveryEngine.SMTP_PERMANENT_FAILURE, bad.error);
        assertEquals("mx1.x.test", bad.mx);
        assertTrue(mx2.commands.isEmpty());
        assertEquals(JobStatus.PARTIALLY_FAILED, job.status);
    }

    @Test
    void allMxUnreachableDefers() throws Exception {
        mxRecords.put("x.test", List.of("10 mx1.x.test", "20 mx2.x.test"));
        deadHost("mx1.x.test");
        deadHost("mx2.x.test");
        String id = createJob("a@x.test");

        Instant before = Instant.now();
        Job job = engine(10).deliver(id).orElseThrow();

        RecipientResult r = job.recipients.get(0);
        assertEquals(RecipientResult.Status.DEFERRED, r.status);
        assertEquals(DeliveryEngine.CONNECTION_FAILED, r.error);
        assertEquals("mx2.x.test", r.mx);
        assertNotNull(r.nextAttemptAt);
        assertTrue(!r.nextAttemptAt.isBefore(before.plusSeconds(60)));
        assertEquals(JobStatus.DEFERRED, job.status);

        // not due yet: a second run leaves it alone
        Job again = engine(10).deliver(id).orElseThrow();
        assertEquals(1, again.recipients.get(0).attempts);
    }

    @Test
    void nullMxFailsPermanently() throws Exception {
        mxRecords.put("x.test", List.of("0 ."));
        mxRecords.put("y.test", List.of("10 mx.y.test"));
        server("mx.y.test");
        String id = createJob("a@x.test", "b@y.test");

        Job job = engine(10).deliver(id).orElseThrow();

        RecipientResult r = job.recipients.get(0);
        assertEquals(RecipientResult.Status.FAILED, r.status);
        assertEquals(DeliveryEngine.NO_MAIL_HOST, r.error);
        assertNull(r.smtpCode);
        assertEquals(RecipientResult.Status.DELIVERED, job.recipients.get(1).status);
        assertEquals(JobStatus.PARTIALLY_FAILED, job.status);
    }

    @Test
    void temporaryDnsFailureDefers() throws Exception {
        String id = createJob("a@x.test");
        MxResolver failing = new MxResolver((name, type) -> {
            throw new IOException("SERVFAIL");
        }, host -> new InetAddress[0], null);
        Config config = Config.fromJson("{\"heloName\": \"sender.example.com\"}");
        Job job = new DeliveryEngine(config, store, failing, executor, null).deliver(id).orElseThrow();
        assertEquals(RecipientResult.Status.DEFERRED, job.recipients.get(0).status);
        assertEquals(DeliveryEngine.DNS_TEMPORARY_FAILURE, job.recipients.get(0).error);
    }

    @Test
    void concurrencyLimitBoundsParallelDomainDeliveries() throws Exception {
        AtomicInteger active = new AtomicInteger();
        AtomicInteger maxActive = new AtomicInteger();
        FakeSmtpServer s = server("mx.shared.test");
        s.handler = c -> {
            if (c.startsWith("EHLO")) {
                maxActive.accumulateAndGet(active.incrementAndGet(), Math::max);
                try {
                    Thread.sleep(150);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            } else if (c.equals("QUIT")) {
                active.decrementAndGet();
            }
            return FakeSmtpServer.defaultReply(c);
        };
        List<String> rcpts = new ArrayList<>();
        for (int i = 0; i < 6; i++) {
            mxRecords.put("d" + i + ".test", List.of("10 mx.shared.test"));
            rcpts.add("user@d" + i + ".test");
        }
        String id = createJob(rcpts.toArray(new String[0]));

        DeliveryEngine engine = engine(2);
        Job job = engine.deliver(id).orElseThrow();

        assertEquals(JobStatus.DELIVERED, job.status);
        assertEquals(6, s.messages.size());
        assertEquals(2, maxActive.get());
        assertEquals(2, engine.availablePermits());
    }

    @Test
    void submitRunsInBackgroundAndReportsFinishedRun() throws Exception {
        mxRecords.put("x.test", List.of("10 mx.x.test"));
        server("mx.x.test");
        String id = createJob("a@x.test");
        Config config = Config.fromJson("{\"heloName\": \"sender.example.com\"}");
        DeliveryEngine.Options options = new DeliveryEngine.Options();
        options.endpoints = (mx, address) -> endpoints.get(mx.host());
        CountDownLatch finished = new CountDownLatch(1);
        Map<String, JobStatus> seen = new HashMap<>();
        options.onRunFinished = job -> {
            synchronized (seen) {
                seen.put(job.id, job.status);
            }
            finished.countDown();
        };
        DeliveryEngine engine = new DeliveryEngine(config, store, resolver(), executor, options);

        engine.submit(store.get(id).orElseThrow());

        assertTrue(finished.await(10, TimeUnit.SECONDS));
        synchronized (seen) {
            assertEquals(JobStatus.DELIVERED, seen.get(id));
        }
    }

    @Test
    void finishedJobsAreNotDeliveredAgain() throws Exception {
        mxRecords.put("x.test", List.of("10 mx.x.test"));
        FakeSmtpServer s = server("mx.x.test");
        String id = createJob("a@x.test");
        DeliveryEngine engine = engine(10);
        engine.deliver(id);
        Job again = engine.deliver(id).orElseThrow();
        assertEquals(JobStatus.DELIVERED, again.status);
        assertEquals(1, s.messages.size());
        assertEquals(1, again.recipients.get(0).attempts);
    }

    // ---- result classification and per-recipient results ------------------------------------------------------

    @Test
    void mixedRcptRepliesGivePerRecipientResults() throws Exception {
        mxRecords.put("x.test", List.of("10 mx.x.test"));
        FakeSmtpServer s = server("mx.x.test");
        s.handler = c -> switch (c) {
            case "RCPT TO:<later@x.test>" -> "450 4.2.1 mailbox busy\r\n";
            case "RCPT TO:<gone@x.test>" -> "550 5.1.1 no such user\r\n";
            default -> FakeSmtpServer.defaultReply(c);
        };
        String id = createJob("ok@x.test", "later@x.test", "gone@x.test");

        Job job = engine(10).deliver(id).orElseThrow();

        RecipientResult ok = job.recipients.get(0);
        assertEquals(RecipientResult.Status.DELIVERED, ok.status);
        assertEquals(250, ok.smtpCode);
        assertEquals("2.0.0", ok.enhancedStatus);
        assertEquals("mx.x.test", ok.mx);
        assertNotNull(ok.deliveredAt);
        assertNull(ok.error);

        RecipientResult later = job.recipients.get(1);
        assertEquals(RecipientResult.Status.DEFERRED, later.status);
        assertEquals(450, later.smtpCode);
        assertEquals("4.2.1", later.enhancedStatus);
        assertEquals("4.2.1 mailbox busy", later.smtpMessage);
        assertEquals(DeliveryEngine.SMTP_TEMPORARY_FAILURE, later.error);
        assertNotNull(later.nextAttemptAt);

        RecipientResult gone = job.recipients.get(2);
        assertEquals(RecipientResult.Status.FAILED, gone.status);
        assertEquals(550, gone.smtpCode);
        assertEquals("5.1.1", gone.enhancedStatus);
        assertEquals(DeliveryEngine.SMTP_PERMANENT_FAILURE, gone.error);
        assertNotNull(gone.failedAt);

        assertEquals(JobStatus.DEFERRED, job.status);
        // only the accepted recipient got the message
        assertEquals(1, s.messages.size());
        // persisted as reported
        Job stored = store.get(id).orElseThrow();
        assertEquals("4.2.1", stored.recipients.get(1).enhancedStatus);
    }

    @Test
    void temporaryDataFailureDefersAcceptedRecipients() throws Exception {
        mxRecords.put("x.test", List.of("10 mx.x.test"));
        FakeSmtpServer s = server("mx.x.test");
        s.dataReply = "451 4.3.0 try again later\r\n";
        String id = createJob("a@x.test", "b@x.test");

        Job job = engine(10).deliver(id).orElseThrow();

        for (RecipientResult r : job.recipients) {
            assertEquals(RecipientResult.Status.DEFERRED, r.status, r.address);
            assertEquals(451, r.smtpCode);
            assertEquals(DeliveryEngine.SMTP_TEMPORARY_FAILURE, r.error);
        }
        assertEquals(JobStatus.DEFERRED, job.status);
    }

    @Test
    void permanentDataFailureFailsAcceptedRecipients() throws Exception {
        mxRecords.put("x.test", List.of("10 mx1.x.test", "20 mx2.x.test"));
        FakeSmtpServer mx1 = server("mx1.x.test");
        mx1.dataReply = "554 5.7.1 message rejected as spam\r\n";
        FakeSmtpServer mx2 = server("mx2.x.test");
        String id = createJob("a@x.test", "b@x.test");

        Job job = engine(10).deliver(id).orElseThrow();

        for (RecipientResult r : job.recipients) {
            assertEquals(RecipientResult.Status.FAILED, r.status, r.address);
            assertEquals(554, r.smtpCode);
            assertEquals("5.7.1", r.enhancedStatus);
            assertEquals(DeliveryEngine.SMTP_PERMANENT_FAILURE, r.error);
        }
        assertEquals(JobStatus.FAILED, job.status);
        assertTrue(mx2.commands.isEmpty(), "a 5xx to the message is final, no failover");
    }

    @Test
    void permanentMailFromFailureFailsTheGroup() throws Exception {
        mxRecords.put("x.test", List.of("10 mx.x.test"));
        FakeSmtpServer s = server("mx.x.test");
        s.handler = c -> c.startsWith("MAIL") ? "553 5.7.1 sender rejected\r\n" : FakeSmtpServer.defaultReply(c);
        String id = createJob("a@x.test");

        Job job = engine(10).deliver(id).orElseThrow();

        RecipientResult r = job.recipients.get(0);
        assertEquals(RecipientResult.Status.FAILED, r.status);
        assertEquals(553, r.smtpCode);
        assertEquals(0, count(s, "RCPT"));
    }

    @Test
    void rcpt552IsTemporaryAndFailsOver() throws Exception {
        mxRecords.put("x.test", List.of("10 mx1.x.test", "20 mx2.x.test"));
        FakeSmtpServer mx1 = server("mx1.x.test");
        mx1.handler = c -> c.startsWith("RCPT") ? "552 too many recipients\r\n" : FakeSmtpServer.defaultReply(c);
        FakeSmtpServer mx2 = server("mx2.x.test");
        String id = createJob("a@x.test");

        Job job = engine(10).deliver(id).orElseThrow();

        assertEquals(RecipientResult.Status.DELIVERED, job.recipients.get(0).status);
        assertEquals("mx2.x.test", job.recipients.get(0).mx);
        assertEquals(1, mx2.messages.size());
    }

    @Test
    void sessionRejectedByEveryMxFailsPermanently() throws Exception {
        mxRecords.put("x.test", List.of("10 mx1.x.test", "20 mx2.x.test"));
        server("mx1.x.test").greeting = "554 5.7.1 no service for you\r\n";
        FakeSmtpServer mx2 = server("mx2.x.test");
        mx2.handler = c -> c.startsWith("EHLO") || c.startsWith("HELO") ? "550 go away\r\n"
                : FakeSmtpServer.defaultReply(c);
        String id = createJob("a@x.test");

        Job job = engine(10).deliver(id).orElseThrow();

        RecipientResult r = job.recipients.get(0);
        assertEquals(RecipientResult.Status.FAILED, r.status);
        assertEquals(DeliveryEngine.SMTP_PERMANENT_FAILURE, r.error);
        assertEquals("mx2.x.test", r.mx);
        assertEquals(550, r.smtpCode);
    }

    @Test
    void sessionRejectionPlusTemporaryFailureDefers() throws Exception {
        mxRecords.put("x.test", List.of("10 mx1.x.test", "20 mx2.x.test"));
        server("mx1.x.test").greeting = "554 5.7.1 no service for you\r\n";
        server("mx2.x.test").greeting = "421 4.3.2 busy\r\n";
        String id = createJob("a@x.test");

        Job job = engine(10).deliver(id).orElseThrow();

        RecipientResult r = job.recipients.get(0);
        assertEquals(RecipientResult.Status.DEFERRED, r.status);
        assertEquals(421, r.smtpCode);
        assertEquals(DeliveryEngine.SMTP_TEMPORARY_FAILURE, r.error);
    }

    @Test
    void connectionDroppedDuringDataDefers() throws Exception {
        mxRecords.put("x.test", List.of("10 mx.x.test"));
        FakeSmtpServer s = server("mx.x.test");
        // the server reads the message, then closes the connection without answering
        s.dataReply = null;
        String id = createJob("a@x.test");

        Job job = engine(10).deliver(id).orElseThrow();

        RecipientResult r = job.recipients.get(0);
        assertEquals(RecipientResult.Status.DEFERRED, r.status);
        assertEquals(DeliveryEngine.CONNECTION_FAILED, r.error);
        assertNull(r.smtpCode);
        assertEquals("mx.x.test", r.mx);
    }

    // ---- restart recovery ---------------------------------------------------------------------------------------

    /** An engine as a fresh process would create it, reporting finished runs to {@code finished}. */
    private DeliveryEngine restartedEngine(List<Job> finished, CountDownLatch latch) throws Exception {
        Config config = Config.fromJson("{\"heloName\": \"sender.example.com\", \"connectTimeout\": \"2s\","
                + " \"readTimeout\": \"5s\"}");
        DeliveryEngine.Options options = new DeliveryEngine.Options();
        options.endpoints = (mx, address) -> endpoints.get(mx.host());
        options.onRunFinished = job -> {
            synchronized (finished) {
                finished.add(job);
            }
            latch.countDown();
        };
        return new DeliveryEngine(config, store, resolver(), executor, options);
    }

    @Test
    void restartResendsOnlyUnfinishedRecipients() throws Exception {
        mxRecords.put("x.test", List.of("10 mx.x.test"));
        FakeSmtpServer s = server("mx.x.test");
        String id = createJob("done@x.test", "rejected@x.test", "inflight@x.test", "new@x.test", "later@x.test");
        Instant before = Instant.now().minusSeconds(60);
        Instant later = Instant.now().plusSeconds(3600);
        // the state a crash mid-run leaves behind
        store.update(id, job -> {
            job.status = JobStatus.SENDING;
            job.recipients.get(0).beginAttempt(before);
            job.recipients.get(0).markDelivered(before, "mx.x.test", 250, "ok", false);
            job.recipients.get(1).beginAttempt(before);
            job.recipients.get(1).markFailed(before, "mx.x.test", 550, "no such user",
                    DeliveryEngine.SMTP_PERMANENT_FAILURE);
            job.recipients.get(2).beginAttempt(before);
            job.recipients.get(4).beginAttempt(before);
            job.recipients.get(4).markDeferred(later, "mx.x.test", 451, "try later",
                    DeliveryEngine.SMTP_TEMPORARY_FAILURE);
        });
        List<Job> finished = new ArrayList<>();
        CountDownLatch latch = new CountDownLatch(1);
        List<Job> scheduled = new ArrayList<>();

        int resumed = restartedEngine(finished, latch).resumeAll(scheduled::add);

        assertEquals(1, resumed);
        assertTrue(latch.await(10, TimeUnit.SECONDS));
        assertTrue(scheduled.isEmpty());
        List<String> rcpts = s.commands.stream().filter(c -> c.startsWith("RCPT")).toList();
        assertEquals(List.of("RCPT TO:<inflight@x.test>", "RCPT TO:<new@x.test>"), rcpts);
        assertEquals(1, s.messages.size());

        Job job = store.get(id).orElseThrow();
        assertEquals(RecipientResult.Status.DELIVERED, job.recipients.get(0).status);
        assertEquals(1, job.recipients.get(0).attempts);
        assertEquals(RecipientResult.Status.FAILED, job.recipients.get(1).status);
        assertEquals(1, job.recipients.get(1).attempts);
        assertEquals(RecipientResult.Status.DELIVERED, job.recipients.get(2).status);
        assertEquals(2, job.recipients.get(2).attempts);
        assertEquals(RecipientResult.Status.DELIVERED, job.recipients.get(3).status);
        assertEquals(1, job.recipients.get(3).attempts);
        // not due yet: left for the retry scheduler, which the run's onRunFinished re-arms
        assertEquals(RecipientResult.Status.DEFERRED, job.recipients.get(4).status);
        assertEquals(later, job.recipients.get(4).nextAttemptAt);
        assertEquals(1, job.recipients.get(4).attempts);
        assertEquals(JobStatus.DEFERRED, job.status);
        synchronized (finished) {
            assertEquals(JobStatus.DEFERRED, finished.get(0).status);
        }
    }

    @Test
    void restartSchedulesDeferredJobsInsteadOfSendingEarly() throws Exception {
        mxRecords.put("x.test", List.of("10 mx.x.test"));
        FakeSmtpServer s = server("mx.x.test");
        String id = createJob("a@x.test");
        Instant later = Instant.now().plusSeconds(3600);
        store.update(id, job -> {
            job.recipients.get(0).beginAttempt(Instant.now());
            job.recipients.get(0).markDeferred(later, "mx.x.test", 451, "busy", DeliveryEngine.SMTP_TEMPORARY_FAILURE);
            job.status = JobStatus.DEFERRED;
        });
        List<Job> scheduled = new ArrayList<>();

        int resumed = restartedEngine(new ArrayList<>(), new CountDownLatch(1)).resumeAll(scheduled::add);

        assertEquals(1, resumed);
        assertEquals(1, scheduled.size());
        assertEquals(id, scheduled.get(0).id);
        assertEquals(later, RetryScheduler.earliestRetry(scheduled.get(0)));
        Thread.sleep(200);
        assertTrue(s.commands.isEmpty());
    }

    @Test
    void restartDeliversDueDeferredAndQueuedJobs() throws Exception {
        mxRecords.put("x.test", List.of("10 mx.x.test"));
        FakeSmtpServer s = server("mx.x.test");
        String queued = createJob("q@x.test");
        String due = createJob("d@x.test");
        store.update(due, job -> {
            job.recipients.get(0).beginAttempt(Instant.now().minusSeconds(120));
            job.recipients.get(0).markDeferred(Instant.now().minusSeconds(1), "mx.x.test", 451, "busy",
                    DeliveryEngine.SMTP_TEMPORARY_FAILURE);
            job.status = JobStatus.DEFERRED;
        });
        List<Job> finished = new ArrayList<>();
        CountDownLatch latch = new CountDownLatch(2);
        List<Job> scheduled = new ArrayList<>();

        assertEquals(2, restartedEngine(finished, latch).resumeAll(scheduled::add));

        assertTrue(latch.await(10, TimeUnit.SECONDS));
        assertTrue(scheduled.isEmpty());
        assertEquals(2, s.messages.size());
        assertEquals(JobStatus.DELIVERED, store.get(queued).orElseThrow().status);
        Job d = store.get(due).orElseThrow();
        assertEquals(JobStatus.DELIVERED, d.status);
        assertEquals(2, d.recipients.get(0).attempts);
    }

    @Test
    void restartSettlesSendingJobWhoseRecipientsAreAllFinal() throws Exception {
        mxRecords.put("x.test", List.of("10 mx.x.test"));
        FakeSmtpServer s = server("mx.x.test");
        String id = createJob("a@x.test", "b@x.test");
        Instant t = Instant.now().minusSeconds(5);
        store.update(id, job -> {
            job.status = JobStatus.SENDING;
            job.recipients.get(0).beginAttempt(t);
            job.recipients.get(0).markDelivered(t, "mx.x.test", 250, "ok", false);
            job.recipients.get(1).beginAttempt(t);
            job.recipients.get(1).markFailed(t, "mx.x.test", 550, "no", DeliveryEngine.SMTP_PERMANENT_FAILURE);
        });
        List<Job> finished = new ArrayList<>();
        CountDownLatch latch = new CountDownLatch(1);

        assertEquals(1, restartedEngine(finished, latch).resumeAll(j -> {
            throw new AssertionError("nothing to schedule");
        }));

        assertTrue(latch.await(10, TimeUnit.SECONDS));
        assertTrue(s.commands.isEmpty());
        Job job = store.get(id).orElseThrow();
        assertEquals(JobStatus.PARTIALLY_FAILED, job.status);
        assertEquals(1, job.recipients.get(0).attempts);
        assertEquals(1, job.recipients.get(1).attempts);
    }

    @Test
    void restartIgnoresFinishedAndPreparingJobs() throws Exception {
        mxRecords.put("x.test", List.of("10 mx.x.test"));
        FakeSmtpServer s = server("mx.x.test");
        String delivered = createJob("a@x.test");
        String preparing = createJob("b@x.test");
        Instant t = Instant.now();
        store.update(delivered, job -> {
            job.recipients.get(0).beginAttempt(t);
            job.recipients.get(0).markDelivered(t, "mx.x.test", 250, "ok", false);
            job.status = JobStatus.DELIVERED;
        });
        store.update(preparing, job -> job.status = JobStatus.PREPARING);

        int resumed = restartedEngine(new ArrayList<>(), new CountDownLatch(1)).resumeAll(j -> {
            throw new AssertionError("nothing to schedule");
        });

        assertEquals(0, resumed);
        Thread.sleep(200);
        assertTrue(s.commands.isEmpty());
        assertEquals(JobStatus.PREPARING, store.get(preparing).orElseThrow().status);
    }

    /** A fake MX offering STARTTLS with the self-signed certificate for {@link #TLS_MX}. */
    private FakeSmtpServer tlsServer(String mxHost) throws IOException {
        FakeSmtpServer s = server(mxHost);
        s.tlsContext = cert.serverContext();
        return s;
    }

    @Test
    void opportunisticTlsIsUsedWhenOffered() throws Exception {
        mxRecords.put("x.test", List.of("10 " + TLS_MX));
        FakeSmtpServer s = tlsServer(TLS_MX);
        String id = createJob("a@x.test");

        Job job = engine(10).deliver(id).orElseThrow();

        RecipientResult r = job.recipients.get(0);
        assertEquals(RecipientResult.Status.DELIVERED, r.status);
        assertEquals(Boolean.TRUE, r.tls);
        assertTrue(s.commands.contains("STARTTLS"));
        assertTrue(s.overTls.get(indexOfPrefix(s, "MAIL")), "MAIL sent over TLS");
    }

    @Test
    void requireTlsWithoutStartTlsFailsPermanently() throws Exception {
        mxRecords.put("x.test", List.of("10 mx1.x.test", "20 mx2.x.test"));
        FakeSmtpServer mx1 = server("mx1.x.test");
        FakeSmtpServer mx2 = server("mx2.x.test");
        String id = createJob(true, false, "a@x.test");

        Job job = engine(10).deliver(id).orElseThrow();

        RecipientResult r = job.recipients.get(0);
        assertEquals(RecipientResult.Status.FAILED, r.status);
        assertEquals(TlsPolicy.TLS_REQUIRED_NOT_AVAILABLE, r.error);
        assertNull(r.nextAttemptAt);
        assertEquals(JobStatus.FAILED, job.status);
        // both MX were tried, neither got the message
        assertEquals(0, count(mx1, "MAIL"));
        assertEquals(0, count(mx2, "MAIL"));
        assertTrue(mx1.commands.get(0).startsWith("EHLO"));
        assertTrue(mx2.commands.get(0).startsWith("EHLO"));
        assertTrue(mx1.messages.isEmpty() && mx2.messages.isEmpty());
        // final: a second run sends nothing
        engine(10).deliver(id);
        assertEquals(0, count(mx1, "MAIL") + count(mx2, "MAIL"));
    }

    @Test
    void requireTlsFailsOverToMxThatOffersStartTls() throws Exception {
        mxRecords.put("x.test", List.of("10 mx1.x.test", "20 " + TLS_MX));
        FakeSmtpServer plain = server("mx1.x.test");
        FakeSmtpServer secure = tlsServer(TLS_MX);
        String id = createJob(true, false, "a@x.test");

        Job job = engine(10).deliver(id).orElseThrow();

        RecipientResult r = job.recipients.get(0);
        assertEquals(RecipientResult.Status.DELIVERED, r.status);
        assertEquals(TLS_MX, r.mx);
        assertEquals(Boolean.TRUE, r.tls);
        assertNull(r.error);
        assertEquals(0, count(plain, "MAIL"));
        assertEquals(1, secure.messages.size());
    }

    @Test
    void requireTlsWithTlsFailureAndUnreachableMxDefers() throws Exception {
        // One MX lacks STARTTLS, the other can't be reached: the second might offer TLS later, so retry.
        mxRecords.put("x.test", List.of("10 mx1.x.test", "20 mx2.x.test"));
        FakeSmtpServer plain = server("mx1.x.test");
        deadHost("mx2.x.test");
        String id = createJob(true, false, "a@x.test");

        Job job = engine(10).deliver(id).orElseThrow();

        RecipientResult r = job.recipients.get(0);
        assertEquals(RecipientResult.Status.DEFERRED, r.status);
        assertNotNull(r.nextAttemptAt);
        assertEquals(JobStatus.DEFERRED, job.status);
        assertEquals(0, count(plain, "MAIL"));
    }

    @Test
    void verifyCertificateWithUntrustedCertificateFailsWithCertInvalid() throws Exception {
        mxRecords.put("x.test", List.of("10 " + TLS_MX));
        FakeSmtpServer s = tlsServer(TLS_MX);
        verifyingContext = SSLContext.getDefault(); // the self-signed cert isn't in the JDK trust store
        String id = createJob(true, true, "a@x.test");

        Job job = engine(10).deliver(id).orElseThrow();

        RecipientResult r = job.recipients.get(0);
        assertEquals(RecipientResult.Status.FAILED, r.status);
        assertEquals(TlsPolicy.TLS_CERT_INVALID, r.error);
        assertEquals(JobStatus.FAILED, job.status);
        assertEquals(0, count(s, "MAIL"));
        assertTrue(s.messages.isEmpty());
    }

    @Test
    void verifyCertificateWithHostNameMismatchFailsWithCertInvalid() throws Exception {
        // the MX is named differently from the certificate, though the certificate itself is trusted
        mxRecords.put("x.test", List.of("10 mx.other.test"));
        FakeSmtpServer s = server("mx.other.test");
        s.tlsContext = cert.serverContext();
        verifyingContext = cert.trustingContext();
        String id = createJob(true, true, "a@x.test");

        Job job = engine(10).deliver(id).orElseThrow();

        assertEquals(RecipientResult.Status.FAILED, job.recipients.get(0).status);
        assertEquals(TlsPolicy.TLS_CERT_INVALID, job.recipients.get(0).error);
        assertTrue(s.messages.isEmpty());
    }

    @Test
    void verifyCertificateWithTrustedCertificateDelivers() throws Exception {
        mxRecords.put("x.test", List.of("10 " + TLS_MX));
        FakeSmtpServer s = tlsServer(TLS_MX);
        verifyingContext = cert.trustingContext();
        String id = createJob(true, true, "a@x.test");

        Job job = engine(10).deliver(id).orElseThrow();

        RecipientResult r = job.recipients.get(0);
        assertEquals(RecipientResult.Status.DELIVERED, r.status);
        assertEquals(Boolean.TRUE, r.tls);
        assertEquals(1, s.messages.size());
    }

    @Test
    void certInvalidOnOneMxFailsOverToAnother() throws Exception {
        mxRecords.put("x.test", List.of("10 mx.other.test", "20 " + TLS_MX));
        FakeSmtpServer wrongName = server("mx.other.test");
        wrongName.tlsContext = cert.serverContext();
        FakeSmtpServer good = tlsServer(TLS_MX);
        verifyingContext = cert.trustingContext();
        String id = createJob(true, true, "a@x.test");

        Job job = engine(10).deliver(id).orElseThrow();

        assertEquals(RecipientResult.Status.DELIVERED, job.recipients.get(0).status);
        assertEquals(TLS_MX, job.recipients.get(0).mx);
        assertTrue(wrongName.messages.isEmpty());
        assertEquals(1, good.messages.size());
    }

    @Test
    void opportunisticCertificateFailureFallsBackToPlaintext() throws Exception {
        // verifyCertificate without requireTls: a bad certificate means "send without TLS", not failure
        mxRecords.put("x.test", List.of("10 " + TLS_MX));
        FakeSmtpServer s = tlsServer(TLS_MX);
        verifyingContext = SSLContext.getDefault();
        String id = createJob(false, true, "a@x.test");

        Job job = engine(10).deliver(id).orElseThrow();

        RecipientResult r = job.recipients.get(0);
        assertEquals(RecipientResult.Status.DELIVERED, r.status);
        assertEquals(Boolean.FALSE, r.tls);
        assertEquals(1, s.messages.size());
        assertTrue(s.commands.contains("STARTTLS"));
        assertTrue(!s.overTls.get(indexOfPrefix(s, "MAIL")));
    }

    @Test
    void tlsFailureIsPerJobNotPerDomain() throws Exception {
        // same MX: a requireTls job fails, an opportunistic one is delivered in plaintext
        mxRecords.put("x.test", List.of("10 mx.x.test"));
        FakeSmtpServer s = server("mx.x.test");
        String strict = createJob(true, false, "a@x.test");
        String relaxed = createJob("b@x.test");
        DeliveryEngine engine = engine(10);

        assertEquals(TlsPolicy.TLS_REQUIRED_NOT_AVAILABLE, engine.deliver(strict).orElseThrow().recipients.get(0).error);
        Job ok = engine.deliver(relaxed).orElseThrow();

        assertEquals(RecipientResult.Status.DELIVERED, ok.recipients.get(0).status);
        assertEquals(Boolean.FALSE, ok.recipients.get(0).tls);
        assertEquals(1, s.messages.size());
    }

    private static int indexOfPrefix(FakeSmtpServer s, String prefix) {
        for (int i = 0; i < s.commands.size(); i++) {
            if (s.commands.get(i).toUpperCase().startsWith(prefix)) return i;
        }
        throw new AssertionError("no " + prefix + " in " + s.commands);
    }
}
