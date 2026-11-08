package io.siggi.simplemailer.delivery;

import io.siggi.simplemailer.config.Config;
import io.siggi.simplemailer.model.Job;
import io.siggi.simplemailer.model.JobStatus;
import io.siggi.simplemailer.model.RecipientResult;
import io.siggi.simplemailer.model.SendRequest;
import io.siggi.simplemailer.smtp.FakeSmtpServer;
import io.siggi.simplemailer.smtp.MxResolver;
import io.siggi.simplemailer.store.JobStore;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Predicate;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class RetrySchedulerTest {
    private static final Instant T0 = Instant.parse("2026-01-01T00:00:00Z");
    private final List<AutoCloseable> closeables = new ArrayList<>();

    @TempDir
    Path dataDir;

    @AfterEach
    void tearDown() throws Exception {
        for (AutoCloseable c : closeables) c.close();
    }

    private RetryScheduler scheduler(List<Duration> schedule, Duration max, Predicate<Job> submitter) {
        RetryScheduler s = new RetryScheduler(schedule, max, submitter, Duration.ofMillis(20));
        closeables.add(s);
        return s;
    }

    private static RecipientResult failedAttempt(int attempts, Instant first) {
        RecipientResult r = new RecipientResult("a@x.test", 0);
        r.attempts = attempts;
        r.firstAttemptAt = first;
        return r;
    }

    private static Job deferredJob(Instant... nextAttempts) {
        Job job = new Job();
        job.id = UUID.randomUUID().toString();
        job.status = JobStatus.DEFERRED;
        for (int i = 0; i < nextAttempts.length; i++) {
            RecipientResult r = new RecipientResult("r" + i + "@x.test", i);
            r.status = RecipientResult.Status.DEFERRED;
            r.nextAttemptAt = nextAttempts[i];
            job.recipients.add(r);
        }
        return job;
    }

    // ---- backoff ----------------------------------------------------------------------------------------------

    @Test
    void backoffFollowsScheduleAndRepeatsLastEntry() {
        List<Duration> schedule = List.of(Duration.ofMinutes(1), Duration.ofMinutes(5), Duration.ofMinutes(15));
        RetryScheduler s = scheduler(schedule, Duration.ofDays(30), j -> true);
        assertEquals(T0.plus(Duration.ofMinutes(1)), s.nextAttempt(failedAttempt(1, T0), T0));
        assertEquals(T0.plus(Duration.ofMinutes(5)), s.nextAttempt(failedAttempt(2, T0), T0));
        assertEquals(T0.plus(Duration.ofMinutes(15)), s.nextAttempt(failedAttempt(3, T0), T0));
        assertEquals(T0.plus(Duration.ofMinutes(15)), s.nextAttempt(failedAttempt(9, T0), T0));
    }

    @Test
    void defaultConfigScheduleIsBoundedBy48Hours() throws Exception {
        Config config = Config.fromJson("{}");
        DeliveryEngine.RetryPolicy p = RetryScheduler.backoff(config);
        assertEquals(T0.plus(Duration.ofMinutes(1)), p.nextAttempt(failedAttempt(1, T0), T0));
        assertEquals(T0.plus(Duration.ofMinutes(5)), p.nextAttempt(failedAttempt(2, T0), T0));
        // keep retrying until 48h after the first attempt; count the attempts it takes
        RecipientResult r = failedAttempt(1, T0);
        Instant now = T0;
        Instant next;
        while ((next = p.nextAttempt(r, now)) != null) {
            assertTrue(next.isAfter(now));
            assertTrue(!next.isAfter(T0.plus(Duration.ofHours(48))));
            now = next;
            r.attempts++;
        }
        assertEquals(T0.plus(Duration.ofHours(48)), now, "the last attempt is at the deadline");
        assertTrue(r.attempts > 10);
    }

    @Test
    void lastRetryIsClampedToDeadlineThenGivesUp() {
        RetryScheduler s = scheduler(List.of(Duration.ofHours(4)), Duration.ofHours(10), j -> true);
        Instant afterNine = T0.plus(Duration.ofHours(9));
        assertEquals(T0.plus(Duration.ofHours(10)), s.nextAttempt(failedAttempt(3, T0), afterNine));
        assertNull(s.nextAttempt(failedAttempt(4, T0), T0.plus(Duration.ofHours(10))));
        assertNull(s.nextAttempt(failedAttempt(4, T0), T0.plus(Duration.ofHours(11))));
    }

    @Test
    void emptyScheduleUsesDefaultDelay() {
        RetryScheduler s = scheduler(List.of(), Duration.ofDays(2), j -> true);
        assertEquals(T0.plus(RetryScheduler.DEFAULT_DELAY), s.nextAttempt(failedAttempt(1, T0), T0));
    }

    // ---- scheduling -------------------------------------------------------------------------------------------

    @Test
    void firesAtEarliestDeferredRecipient() throws Exception {
        LinkedBlockingQueue<Long> fired = new LinkedBlockingQueue<>();
        RetryScheduler s = scheduler(List.of(), null, j -> fired.add(System.nanoTime()));
        Instant now = Instant.now();
        Job job = deferredJob(now.plusSeconds(60), now.plusMillis(200));
        long start = System.nanoTime();
        s.schedule(job);
        assertEquals(now.plusMillis(200), s.scheduledAt(job.id));
        Long at = fired.poll(5, TimeUnit.SECONDS);
        assertNotNull(at);
        assertTrue(TimeUnit.NANOSECONDS.toMillis(at - start) >= 150, "fired too early");
        assertNull(s.scheduledAt(job.id));
        assertEquals(0, s.scheduledCount());
    }

    @Test
    void rescheduleReplacesTimerAndFinishedJobCancelsIt() throws Exception {
        List<String> fired = new CopyOnWriteArrayList<>();
        RetryScheduler s = scheduler(List.of(), null, j -> fired.add(j.id));
        Job job = deferredJob(Instant.now().plusMillis(150));
        s.schedule(job);
        Job later = deferredJob(Instant.now().plusSeconds(60));
        later.id = job.id;
        s.onRunFinished(later);
        assertEquals(later.recipients.get(0).nextAttemptAt, s.scheduledAt(job.id));
        Thread.sleep(400);
        assertTrue(fired.isEmpty(), "replaced timer must not fire");

        later.recipients.get(0).markDelivered(Instant.now(), "mx", 250, "ok", false);
        later.status = JobStatus.DELIVERED;
        s.onRunFinished(later);
        assertNull(s.scheduledAt(job.id));
        assertEquals(0, s.scheduledCount());
    }

    @Test
    void dueRecipientFiresImmediately() throws Exception {
        LinkedBlockingQueue<String> fired = new LinkedBlockingQueue<>();
        RetryScheduler s = scheduler(List.of(), null, j -> fired.add(j.id));
        Job job = deferredJob(Instant.now().minusSeconds(5));
        s.schedule(job);
        assertEquals(job.id, fired.poll(2, TimeUnit.SECONDS));
    }

    @Test
    void busySubmitterIsRetried() throws Exception {
        LinkedBlockingQueue<String> started = new LinkedBlockingQueue<>();
        AtomicBoolean busy = new AtomicBoolean(true);
        List<Integer> tries = new CopyOnWriteArrayList<>();
        RetryScheduler s = scheduler(List.of(), null, j -> {
            tries.add(1);
            if (tries.size() < 3) return false;
            busy.set(false);
            started.add(j.id);
            return true;
        });
        Job job = deferredJob(Instant.now());
        s.schedule(job);
        assertEquals(job.id, started.poll(5, TimeUnit.SECONDS));
        assertEquals(3, tries.size());
        assertTrue(!busy.get());
        Thread.sleep(100);
        assertEquals(3, tries.size(), "no further submissions after one was accepted");
    }

    @Test
    void nothingDeferredSchedulesNothing() {
        RetryScheduler s = scheduler(List.of(), null, j -> true);
        Job job = deferredJob(Instant.now());
        job.recipients.get(0).status = RecipientResult.Status.DELIVERED;
        job.status = JobStatus.DELIVERED;
        s.schedule(job);
        assertEquals(0, s.scheduledCount());
    }

    // ---- with the delivery engine -----------------------------------------------------------------------------

    @Test
    void deferredDeliveryIsRetriedUntilDelivered() throws Exception {
        FakeSmtpServer server = new FakeSmtpServer();
        closeables.add(server);
        AtomicReference<String> rcptReply = new AtomicReference<>("451 4.3.0 try later\r\n");
        server.handler = cmd -> cmd.toUpperCase().startsWith("RCPT") ? rcptReply.get()
                : FakeSmtpServer.defaultReply(cmd);
        ExecutorService executor = Executors.newVirtualThreadPerTaskExecutor();
        closeables.add(executor::shutdownNow);
        JobStore store = new JobStore(dataDir);
        Config config = Config.fromJson("{\"heloName\": \"sender.example.com\", \"connectTimeout\": \"2s\","
                + " \"readTimeout\": \"5s\", \"retrySchedule\": [\"100ms\", \"200ms\"], \"maxRetryDuration\": \"1h\"}");
        LinkedBlockingQueue<Job> runs = new LinkedBlockingQueue<>();
        DeliveryEngine[] engine = new DeliveryEngine[1];
        RetryScheduler scheduler = new RetryScheduler(config, j -> engine[0].submit(j));
        closeables.add(scheduler);
        DeliveryEngine.Options options = new DeliveryEngine.Options();
        options.retryPolicy = scheduler;
        options.onRunFinished = j -> {
            scheduler.onRunFinished(j);
            runs.add(j);
        };
        options.endpoints = (mx, address) -> server.address();
        MxResolver resolver = new MxResolver((name, type) -> type.equals("MX") ? List.of("10 mx.x.test") : List.of(),
                host -> new InetAddress[]{InetAddress.getLoopbackAddress()}, null);
        engine[0] = new DeliveryEngine(config, store, resolver, executor, options);

        String id = createJob(store, "a@x.test");
        engine[0].submit(store.get(id).orElseThrow());

        Job first = runs.poll(10, TimeUnit.SECONDS);
        assertNotNull(first);
        assertEquals(JobStatus.DEFERRED, first.status);
        assertEquals(451, first.recipients.get(0).smtpCode);
        Job second = runs.poll(10, TimeUnit.SECONDS);
        assertNotNull(second, "retried by the scheduler");
        assertEquals(JobStatus.DEFERRED, second.status);
        assertEquals(2, second.recipients.get(0).attempts);
        // the second wait comes from the next schedule entry
        RecipientResult r2 = second.recipients.get(0);
        Duration wait = Duration.between(r2.lastAttemptAt, r2.nextAttemptAt);
        assertTrue(wait.compareTo(Duration.ofMillis(200)) >= 0 && wait.compareTo(Duration.ofSeconds(3)) < 0,
                "wait: " + wait);

        rcptReply.set("250 2.1.5 ok\r\n");
        Job third = runs.poll(10, TimeUnit.SECONDS);
        assertNotNull(third);
        assertEquals(JobStatus.DELIVERED, third.status);
        assertEquals(3, third.recipients.get(0).attempts);
        assertEquals(1, server.messages.size());
        assertEquals(0, scheduler.scheduledCount());
    }

    @Test
    void retriesStopAtMaxRetryDuration() throws Exception {
        FakeSmtpServer server = new FakeSmtpServer();
        closeables.add(server);
        server.handler = cmd -> cmd.toUpperCase().startsWith("RCPT") ? "451 4.3.0 try later\r\n"
                : FakeSmtpServer.defaultReply(cmd);
        ExecutorService executor = Executors.newVirtualThreadPerTaskExecutor();
        closeables.add(executor::shutdownNow);
        JobStore store = new JobStore(dataDir);
        Config config = Config.fromJson("{\"heloName\": \"sender.example.com\", \"connectTimeout\": \"2s\","
                + " \"readTimeout\": \"5s\", \"retrySchedule\": [\"150ms\"], \"maxRetryDuration\": \"400ms\"}");
        LinkedBlockingQueue<Job> runs = new LinkedBlockingQueue<>();
        DeliveryEngine[] engine = new DeliveryEngine[1];
        RetryScheduler scheduler = new RetryScheduler(config, j -> engine[0].submit(j));
        closeables.add(scheduler);
        DeliveryEngine.Options options = new DeliveryEngine.Options();
        options.retryPolicy = scheduler;
        options.onRunFinished = j -> {
            scheduler.onRunFinished(j);
            runs.add(j);
        };
        options.endpoints = (mx, address) -> server.address();
        MxResolver resolver = new MxResolver((name, type) -> type.equals("MX") ? List.of("10 mx.x.test") : List.of(),
                host -> new InetAddress[]{InetAddress.getLoopbackAddress()}, null);
        engine[0] = new DeliveryEngine(config, store, resolver, executor, options);

        String id = createJob(store, "a@x.test");
        engine[0].submit(store.get(id).orElseThrow());

        Job last;
        do {
            last = runs.poll(10, TimeUnit.SECONDS);
            assertNotNull(last);
        } while (last.status == JobStatus.DEFERRED);
        RecipientResult r = last.recipients.get(0);
        assertEquals(JobStatus.FAILED, last.status);
        assertEquals(RecipientResult.Status.FAILED, r.status);
        assertEquals(DeliveryEngine.RETRIES_EXHAUSTED, r.error);
        assertEquals(451, r.smtpCode);
        assertTrue(r.attempts >= 3 && r.attempts <= 5, "attempts: " + r.attempts);
        // the final attempt happened at (not before) the deadline
        assertTrue(!r.lastAttemptAt.isBefore(r.firstAttemptAt.plusMillis(400)));
        assertEquals(0, scheduler.scheduledCount());
    }

    private static String createJob(JobStore store, String... recipients) throws Exception {
        SendRequest send = new SendRequest();
        send.id = UUID.randomUUID().toString();
        send.from = "sender@example.com";
        send.to = List.of(recipients);
        send.subject = "Hello";
        send.text = "Hi there";
        store.create(send.id, JobStore.payloadHash(send), () -> {
            store.writePayload(send.id, "Subject: Hello\r\n\r\nHi there\r\n".getBytes(StandardCharsets.UTF_8));
            return Job.create(send, "x", Instant.now(), JobStatus.QUEUED);
        });
        return send.id;
    }
}
