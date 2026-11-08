package io.siggi.simplemailer.callback;

import com.google.gson.JsonObject;
import com.google.gson.JsonParseException;
import io.siggi.simplemailer.api.Json;
import io.siggi.simplemailer.api.MessagesResponder;
import io.siggi.simplemailer.config.Config;
import io.siggi.simplemailer.mime.AttachmentFetcher;
import io.siggi.simplemailer.model.Job;
import io.siggi.simplemailer.model.JobStatus;
import io.siggi.simplemailer.model.ModelJson;
import io.siggi.simplemailer.store.JobStore;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.net.InetAddress;
import java.net.URI;
import java.net.UnknownHostException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executor;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ScheduledThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Sends callback events to a job's {@code callbackUrl} (PLAN.md §6).
 *
 * <ul>
 *   <li><b>Events</b>: {@code delivered}, {@code partially_failed} or {@code failed} once delivery is over, the first
 *       {@code deferred}, and every {@code bounced} (which may follow an earlier {@code delivered}). Each event has a
 *       unique {@code eventId} (a UUID), so callers can drop duplicates. The body is
 *       {@code {"eventId","event","createdAt","job": <status JSON>}}, with the job as it was when the event fired.</li>
 *   <li><b>Signature</b>: when {@code callbackSecret} is configured, the header
 *       {@code X-SimpleMailer-Signature: sha256=<hex HMAC-SHA256 of the body>} lets the caller verify the request.
 *       {@code X-SimpleMailer-Event} and {@code X-SimpleMailer-Event-Id} repeat the event name and id.</li>
 *   <li><b>Retries</b>: any non-2xx answer or I/O error is retried following {@code callbackRetrySchedule} (the last
 *       entry repeats) until {@code callbackMaxRetryDuration} after the event was created; then the event is given up.
 *       Every retry sends exactly the same bytes, with the same {@code eventId}.</li>
 *   <li><b>Persistence</b>: an event is written to {@code data/callbacks/{eventId}.json} before the job records it,
 *       and removed once it is delivered or given up, so {@link #resumeAll} carries pending events across a restart.
 *       The job's {@link Job.CallbackState} records the outcome of its most recent event.</li>
 *   <li><b>SSRF guard</b> (optional, {@code blockPrivateCallbackTargets}): before every attempt the callback host is
 *       resolved and, if any of its addresses is loopback, private, link-local or otherwise non-public (the same
 *       rules as {@link AttachmentFetcher#isBlockedAddress}), the event is given up at once without sending
 *       anything. Redirects are never followed, so a public target can't bounce the request inward. The check runs
 *       just before the request, so a host whose DNS answer changes between the check and the connection (DNS
 *       rebinding) is only caught if the change is visible to the check; a host that resolves to nothing is retried
 *       like any other network error.</li>
 * </ul>
 *
 * <p>Callback failures never change the mail status.
 */
public final class CallbackDispatcher implements AutoCloseable {
    private static final Logger LOG = Logger.getLogger(CallbackDispatcher.class.getName());

    public static final String SIGNATURE_HEADER = "X-SimpleMailer-Signature";
    public static final String EVENT_HEADER = "X-SimpleMailer-Event";
    public static final String EVENT_ID_HEADER = "X-SimpleMailer-Event-Id";

    public static final String EVENT_DELIVERED = "delivered";
    public static final String EVENT_PARTIALLY_FAILED = "partially_failed";
    public static final String EVENT_FAILED = "failed";
    public static final String EVENT_DEFERRED = "deferred";
    public static final String EVENT_BOUNCED = "bounced";

    /** Values of {@link Job.CallbackState#status}. */
    public static final String STATUS_PENDING = "pending";
    public static final String STATUS_DELIVERED = "delivered";
    public static final String STATUS_FAILED = "failed";

    static final Duration DEFAULT_DELAY = Duration.ofMinutes(1);
    private static final int MAX_ERROR_LENGTH = 500;

    /** Sends one callback request; returns the HTTP status code. */
    @FunctionalInterface
    public interface Transport {
        int post(URI url, byte[] body, Map<String, String> headers) throws IOException, InterruptedException;
    }

    /** Resolves a callback host for the SSRF guard. */
    @FunctionalInterface
    public interface Resolver {
        InetAddress[] resolve(String host) throws UnknownHostException;
    }

    /** Thrown (and recorded as the error) when the SSRF guard refuses a callback target. */
    static final class BlockedTargetException extends IOException {
        BlockedTargetException(String message) {
            super(message);
        }
    }

    /** A pending event as stored in {@code data/callbacks/{eventId}.json}. */
    static final class PendingEvent {
        String eventId;
        String jobId;
        String event;
        String url;
        /** The exact request body, so every attempt sends the same bytes. */
        String body;
        Instant createdAt;
        int attempts;
        Instant nextAttemptAt;
    }

    private final Config config;
    private final JobStore store;
    private final Executor executor;
    private final Transport transport;
    private final Resolver resolver;
    private final Path outbox;
    private final List<Duration> schedule;
    private final Duration maxRetryDuration;
    private final ScheduledThreadPoolExecutor timer;
    private final Set<String> inFlight = ConcurrentHashMap.newKeySet();

    public CallbackDispatcher(Config config, JobStore store, Executor executor) throws IOException {
        this(config, store, executor, httpTransport(config.callbackTimeout));
    }

    public CallbackDispatcher(Config config, JobStore store, Executor executor, Transport transport) throws IOException {
        this(config, store, executor, transport, InetAddress::getAllByName);
    }

    public CallbackDispatcher(Config config, JobStore store, Executor executor, Transport transport, Resolver resolver)
            throws IOException {
        this.config = config;
        this.store = store;
        this.executor = executor;
        this.transport = transport;
        this.resolver = resolver;
        this.outbox = Path.of(config.dataDir, "callbacks");
        Files.createDirectories(outbox);
        this.schedule = config.callbackRetrySchedule == null ? List.of() : List.copyOf(config.callbackRetrySchedule);
        this.maxRetryDuration = config.callbackMaxRetryDuration;
        ScheduledThreadPoolExecutor t = new ScheduledThreadPoolExecutor(1, r -> {
            Thread th = new Thread(r, "callback-retry");
            th.setDaemon(true);
            return th;
        });
        t.setRemoveOnCancelPolicy(true);
        t.setExecuteExistingDelayedTasksAfterShutdownPolicy(false);
        this.timer = t;
    }

    /** The default transport: {@link HttpClient}, no redirects, with the given connect and response timeout. */
    public static Transport httpTransport(Duration timeout) {
        HttpClient client = HttpClient.newBuilder()
                .connectTimeout(timeout)
                .followRedirects(HttpClient.Redirect.NEVER)
                .build();
        return (url, body, headers) -> {
            HttpRequest.Builder b = HttpRequest.newBuilder(url)
                    .timeout(timeout)
                    .POST(HttpRequest.BodyPublishers.ofByteArray(body));
            headers.forEach(b::header);
            return client.send(b.build(), HttpResponse.BodyHandlers.discarding()).statusCode();
        };
    }

    // ---- firing events ----------------------------------------------------------------------------------------

    /**
     * Called whenever a job's delivery state may have changed (after a delivery run, or when preparation failed):
     * fires the terminal event once, or the first {@code deferred} event, as appropriate. Does nothing for jobs
     * without a {@code callbackUrl} or when no event is due.
     */
    public void onJobChanged(Job job) {
        if (job == null || job.callback == null) return;
        try {
            fireIf(job.id, j -> {
                Job.CallbackState cb = j.callback;
                if (j.status == JobStatus.DEFERRED) {
                    if (cb.deferredNotified || cb.terminalNotified) return null;
                    cb.deferredNotified = true;
                    return EVENT_DEFERRED;
                }
                String terminal = switch (j.status) {
                    case DELIVERED -> EVENT_DELIVERED;
                    case PARTIALLY_FAILED -> EVENT_PARTIALLY_FAILED;
                    case FAILED -> EVENT_FAILED;
                    default -> null;
                };
                if (terminal == null || cb.terminalNotified) return null;
                cb.terminalNotified = true;
                return terminal;
            });
        } catch (IOException | RuntimeException e) {
            LOG.log(Level.WARNING, "could not queue callback for job " + job.id, e);
        }
    }

    /** Fires a {@code bounced} event (every bounce gets one). */
    public Optional<String> bounced(String jobId) throws IOException {
        return fire(jobId, EVENT_BOUNCED);
    }

    /**
     * Fires {@code event} for the job unconditionally (if it has a {@code callbackUrl}).
     *
     * @return the new event's id, or empty if the job doesn't exist or has no callback URL
     */
    public Optional<String> fire(String jobId, String event) throws IOException {
        return fireIf(jobId, j -> event);
    }

    @FunctionalInterface
    private interface EventChooser {
        /** Picks the event to fire (and may update the callback flags), or null for none. */
        String choose(Job job);
    }

    private Optional<String> fireIf(String jobId, EventChooser chooser) throws IOException {
        PendingEvent[] created = {null};
        store.update(jobId, job -> {
            if (job.callback == null || job.callback.url == null || job.callback.url.isBlank()) return;
            String event = chooser.choose(job);
            if (event == null) return;
            Instant now = Instant.now();
            PendingEvent pe = new PendingEvent();
            pe.eventId = UUID.randomUUID().toString();
            pe.jobId = job.id;
            pe.event = event;
            pe.url = job.callback.url;
            pe.createdAt = now;
            pe.nextAttemptAt = now;
            Job.CallbackState cb = job.callback;
            cb.status = STATUS_PENDING;
            cb.lastEventId = pe.eventId;
            cb.lastEvent = event;
            cb.attempts = 0;
            cb.lastAttemptAt = null;
            cb.nextAttemptAt = now;
            cb.lastHttpStatus = null;
            cb.lastError = null;
            job.updatedAt = now;
            pe.body = eventBody(pe, job);
            // written before the job is saved: a crash in between re-sends the event rather than losing it
            writeEvent(pe);
            created[0] = pe;
        });
        PendingEvent pe = created[0];
        if (pe == null) return Optional.empty();
        dispatch(pe.eventId);
        return Optional.of(pe.eventId);
    }

    private String eventBody(PendingEvent pe, Job job) {
        JsonObject body = new JsonObject();
        body.addProperty("eventId", pe.eventId);
        body.addProperty("event", pe.event);
        body.addProperty("createdAt", pe.createdAt.toString());
        body.add("job", Json.jobStatus(job, MessagesResponder.statusUrl(config, job.id)));
        return ModelJson.GSON.toJson(body);
    }

    // ---- signing ----------------------------------------------------------------------------------------------

    /** {@code sha256=<hex HMAC-SHA256(secret, body)>}, the value of {@link #SIGNATURE_HEADER}. */
    public static String signature(String secret, byte[] body) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
            return "sha256=" + HexFormat.of().formatHex(mac.doFinal(body));
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("HmacSHA256 unavailable", e);
        }
    }

    /** Constant-time check of a {@link #SIGNATURE_HEADER} value, as a caller would do it. */
    public static boolean verifySignature(String secret, byte[] body, String header) {
        if (header == null) return false;
        byte[] expected = signature(secret, body).getBytes(StandardCharsets.US_ASCII);
        byte[] actual = header.trim().toLowerCase(Locale.ROOT).getBytes(StandardCharsets.US_ASCII);
        return java.security.MessageDigest.isEqual(expected, actual);
    }

    // ---- sending and retries ----------------------------------------------------------------------------------

    /** Re-schedules every event left pending by a previous process (startup, PLAN.md §4). */
    public int resumeAll() throws IOException {
        List<String> ids = new ArrayList<>();
        try (DirectoryStream<Path> dir = Files.newDirectoryStream(outbox, "*.json")) {
            for (Path p : dir) {
                String name = p.getFileName().toString();
                ids.add(name.substring(0, name.length() - ".json".length()));
            }
        }
        int resumed = 0;
        for (String id : ids) {
            try {
                Optional<PendingEvent> pe = readEvent(id);
                if (pe.isEmpty()) continue;
                scheduleAt(id, pe.get().nextAttemptAt);
                resumed++;
            } catch (IOException | RuntimeException e) {
                LOG.log(Level.WARNING, "could not resume callback event " + id, e);
            }
        }
        return resumed;
    }

    /** Number of events not yet delivered or given up (for tests and monitoring). */
    public int pendingCount() throws IOException {
        try (var files = Files.list(outbox)) {
            return (int) files.filter(p -> p.getFileName().toString().endsWith(".json")).count();
        }
    }

    private void scheduleAt(String eventId, Instant at) {
        long delay = at == null ? 0 : Math.max(0, Duration.between(Instant.now(), at).toMillis());
        try {
            timer.schedule(() -> dispatch(eventId), delay, TimeUnit.MILLISECONDS);
        } catch (RejectedExecutionException e) {
            // shutting down: the event stays in the outbox for the next start
        }
    }

    private void dispatch(String eventId) {
        try {
            executor.execute(() -> attempt(eventId));
        } catch (RejectedExecutionException e) {
            // shutting down: the event stays in the outbox for the next start
        }
    }

    private void attempt(String eventId) {
        if (!inFlight.add(eventId)) return;
        try {
            Optional<PendingEvent> loaded = readEvent(eventId);
            if (loaded.isEmpty()) return;
            PendingEvent pe = loaded.get();
            byte[] body = pe.body.getBytes(StandardCharsets.UTF_8);
            Map<String, String> headers = new LinkedHashMap<>();
            headers.put("Content-Type", "application/json; charset=utf-8");
            headers.put(EVENT_HEADER, pe.event);
            headers.put(EVENT_ID_HEADER, pe.eventId);
            if (config.callbackSecret != null && !config.callbackSecret.isEmpty()) {
                headers.put(SIGNATURE_HEADER, signature(config.callbackSecret, body));
            }
            Integer httpStatus = null;
            String error = null;
            boolean permanent = false;
            try {
                URI url = URI.create(pe.url);
                if (config.blockPrivateCallbackTargets) checkTarget(url);
                httpStatus = transport.post(url, body, headers);
                if (httpStatus < 200 || httpStatus > 299) error = "HTTP " + httpStatus;
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return; // shutting down: try again on the next start
            } catch (BlockedTargetException e) {
                error = e.getMessage();
                permanent = true;
                LOG.warning("callback event " + pe.eventId + " for job " + pe.jobId + " refused: " + error);
            } catch (IOException | RuntimeException e) {
                error = e.getClass().getSimpleName() + (e.getMessage() == null ? "" : ": " + e.getMessage());
            }
            recordAttempt(pe, httpStatus, error, permanent);
        } catch (IOException | RuntimeException e) {
            LOG.log(Level.WARNING, "callback event " + eventId + " failed", e);
        } finally {
            inFlight.remove(eventId);
        }
    }

    /**
     * SSRF guard: refuses a URL whose host is not http(s), or resolves to any non-public address.
     *
     * @throws BlockedTargetException if the target is refused
     * @throws UnknownHostException if the host doesn't resolve (retried like other network errors)
     */
    private void checkTarget(URI url) throws IOException {
        String scheme = url.getScheme() == null ? "" : url.getScheme().toLowerCase(Locale.ROOT);
        if (!scheme.equals("http") && !scheme.equals("https")) {
            throw new BlockedTargetException("CALLBACK_TARGET_BLOCKED: unsupported scheme " + scheme);
        }
        String host = url.getHost();
        if (host == null || host.isEmpty()) {
            throw new BlockedTargetException("CALLBACK_TARGET_BLOCKED: no host");
        }
        if (host.startsWith("[") && host.endsWith("]")) host = host.substring(1, host.length() - 1);
        InetAddress[] addresses = resolver.resolve(host);
        if (addresses == null || addresses.length == 0) throw new UnknownHostException(host);
        for (InetAddress a : addresses) {
            if (AttachmentFetcher.isBlockedAddress(a)) {
                throw new BlockedTargetException("CALLBACK_TARGET_BLOCKED: " + host + " resolves to non-public address "
                        + a.getHostAddress());
            }
        }
    }

    private void recordAttempt(PendingEvent pe, Integer httpStatus, String error, boolean permanent)
            throws IOException {
        Instant now = Instant.now();
        pe.attempts++;
        String outcome;
        if (error == null) {
            outcome = STATUS_DELIVERED;
            pe.nextAttemptAt = null;
        } else if (permanent) {
            outcome = STATUS_FAILED;
            pe.nextAttemptAt = null;
        } else {
            Instant next = now.plus(delayAfter(schedule, pe.attempts));
            Instant deadline = pe.createdAt.plus(maxRetryDuration);
            if (next.isAfter(deadline)) {
                outcome = STATUS_FAILED;
                pe.nextAttemptAt = null;
                LOG.warning("giving up callback event " + pe.eventId + " for job " + pe.jobId + " after "
                        + pe.attempts + " attempts: " + error);
            } else {
                outcome = STATUS_PENDING;
                pe.nextAttemptAt = next;
            }
        }
        String lastError = error == null ? null
                : error.length() > MAX_ERROR_LENGTH ? error.substring(0, MAX_ERROR_LENGTH) : error;
        store.update(pe.jobId, job -> {
            Job.CallbackState cb = job.callback;
            // the state describes the most recent event; an older event finishing doesn't overwrite it
            if (cb == null || !pe.eventId.equals(cb.lastEventId)) return;
            cb.status = outcome;
            cb.attempts = pe.attempts;
            cb.lastAttemptAt = now;
            cb.nextAttemptAt = pe.nextAttemptAt;
            cb.lastHttpStatus = httpStatus;
            cb.lastError = lastError;
        });
        if (outcome.equals(STATUS_PENDING)) {
            writeEvent(pe);
            scheduleAt(pe.eventId, pe.nextAttemptAt);
        } else {
            Files.deleteIfExists(eventFile(pe.eventId));
        }
    }

    /** The wait after the given number of failed attempts (1-based); the last schedule entry repeats. */
    static Duration delayAfter(List<Duration> schedule, int attempts) {
        if (schedule.isEmpty()) return DEFAULT_DELAY;
        int i = Math.max(0, Math.min(attempts - 1, schedule.size() - 1));
        return schedule.get(i);
    }

    // ---- outbox files -----------------------------------------------------------------------------------------

    private Path eventFile(String eventId) {
        // event ids are UUIDs we generate; reject anything else so a file name can't escape the outbox
        return outbox.resolve(UUID.fromString(eventId) + ".json");
    }

    private void writeEvent(PendingEvent pe) throws IOException {
        JobStore.writeAtomic(eventFile(pe.eventId), ModelJson.GSON.toJson(pe).getBytes(StandardCharsets.UTF_8));
    }

    private Optional<PendingEvent> readEvent(String eventId) throws IOException {
        Path file;
        try {
            file = eventFile(eventId);
        } catch (IllegalArgumentException e) {
            return Optional.empty();
        }
        if (!Files.exists(file)) return Optional.empty();
        try {
            PendingEvent pe = ModelJson.GSON.fromJson(Files.readString(file, StandardCharsets.UTF_8), PendingEvent.class);
            if (pe == null || pe.body == null || pe.url == null || pe.jobId == null || pe.createdAt == null) {
                LOG.warning("dropping malformed callback event file " + file);
                Files.deleteIfExists(file);
                return Optional.empty();
            }
            return Optional.of(pe);
        } catch (JsonParseException e) {
            LOG.log(Level.WARNING, "dropping unreadable callback event file " + file, e);
            Files.deleteIfExists(file);
            return Optional.empty();
        }
    }

    @Override
    public void close() {
        timer.shutdownNow();
    }
}
