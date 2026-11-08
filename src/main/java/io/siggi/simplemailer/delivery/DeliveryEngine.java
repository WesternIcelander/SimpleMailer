package io.siggi.simplemailer.delivery;

import io.siggi.simplemailer.config.Config;
import io.siggi.simplemailer.mime.DkimSigner;
import io.siggi.simplemailer.model.Job;
import io.siggi.simplemailer.model.JobStatus;
import io.siggi.simplemailer.model.RecipientResult;
import io.siggi.simplemailer.smtp.MxResolver;
import io.siggi.simplemailer.smtp.SmtpClient;
import io.siggi.simplemailer.smtp.SmtpResponse;
import io.siggi.simplemailer.smtp.TlsPolicy;
import io.siggi.simplemailer.store.JobStore;

import javax.net.ssl.SSLContext;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.SequenceInputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executor;
import java.util.concurrent.Semaphore;
import java.util.function.Consumer;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Delivers queued jobs directly to the recipient domains' mail exchangers (PLAN.md §5).
 *
 * <ul>
 *   <li><b>Per-domain tasks</b>: a job's due recipients are grouped by domain and each domain is delivered by its own
 *       task on the executor (virtual threads in production), so a slow domain doesn't hold up the others.</li>
 *   <li><b>Concurrency limit</b>: a global semaphore of {@code maxConcurrentDeliveries} permits bounds how many
 *       domain tasks talk SMTP at the same time, across all jobs.</li>
 *   <li><b>MX failover</b>: the domain's mail exchangers are tried in preference order, and every address of each
 *       one, until all recipients have a final answer. A connection failure, a non-2xx greeting or {@code EHLO}, a
 *       TLS policy failure, or a 4xx reply moves the still-unanswered recipients on to the next address/MX; a 5xx
 *       reply to {@code MAIL}, {@code RCPT} or the message is final for the recipients it concerns.</li>
 *   <li><b>Result classification</b> ({@link ResultClassifier}): 2xx → {@code delivered}; 5xx → {@code failed};
 *       4xx, network errors and temporary DNS failures → {@code deferred}. Each recipient records the MX, reply
 *       code, enhanced status code, reply text, machine-readable error and whether TLS was used.</li>
 * </ul>
 *
 * <p>When every mail exchanger has been tried, recipients without an answer are {@code deferred} (with the next
 * attempt time from the {@link RetryPolicy}), or {@code failed} if the retry policy gives up, DNS says the domain
 * accepts no mail, every mail exchanger rejected the session with a 5xx (greeting or {@code EHLO}), or
 * {@code requireTls} was set and every mail exchanger failed the TLS policy
 * ({@code TLS_REQUIRED_NOT_AVAILABLE} / {@code TLS_CERT_INVALID}).
 *
 * <p><b>DKIM</b> (PLAN.md §5): if {@link Options#dkim} has a key for the domain of the message's {@code From}
 * header, the message is signed just before its first attempt. The {@code DKIM-Signature} header is computed once
 * per job, saved next to the payload ({@link JobStore#signatureFile}) and sent in front of the unchanged payload on
 * every attempt, to every domain, so retries and restarts send exactly the same bytes. A message that can't be
 * signed is sent unsigned (and the problem logged).
 *
 * <p>Results are written to the job store as soon as each domain finishes, and the job's overall status is
 * recomputed when all its domain tasks are done. Re-running deferred jobs at their next attempt time is up to the
 * caller (the retry scheduler): {@link #submit} only delivers recipients that are pending or due.
 */
public final class DeliveryEngine {
    private static final Logger LOG = Logger.getLogger(DeliveryEngine.class.getName());

    /** Standard SMTP port for MX delivery. */
    public static final int SMTP_PORT = 25;

    /** DNS for the domain failed temporarily (timeout, SERVFAIL). */
    public static final String DNS_TEMPORARY_FAILURE = "DNS_TEMPORARY_FAILURE";
    /** The domain doesn't exist, has no mail host, or publishes a null MX. */
    public static final String NO_MAIL_HOST = "NO_MAIL_HOST";
    /** No mail exchanger could be reached or completed the SMTP dialogue. */
    public static final String CONNECTION_FAILED = "CONNECTION_FAILED";
    /** The server gave a 4xx reply. */
    public static final String SMTP_TEMPORARY_FAILURE = "SMTP_TEMPORARY_FAILURE";
    /** The server gave a 5xx reply. */
    public static final String SMTP_PERMANENT_FAILURE = "SMTP_PERMANENT_FAILURE";
    /** The server gave a reply that makes no sense at that point (e.g. a 3xx to {@code RCPT}). */
    public static final String SMTP_PROTOCOL_ERROR = "SMTP_PROTOCOL_ERROR";
    /** Temporary failures continued past {@code maxRetryDuration}. */
    public static final String RETRIES_EXHAUSTED = "RETRIES_EXHAUSTED";
    /** The job's message file is missing or unreadable. */
    public static final String MESSAGE_UNAVAILABLE = "MESSAGE_UNAVAILABLE";

    /** Decides when a deferred recipient is tried again. */
    @FunctionalInterface
    public interface RetryPolicy {
        /**
         * @param recipient the recipient after its failed attempt ({@code attempts} and {@code firstAttemptAt} set)
         * @return when to try again, or {@code null} to give up (the recipient then fails permanently)
         */
        Instant nextAttempt(RecipientResult recipient, Instant now);
    }

    /** The {@code MAIL FROM} reverse path for a recipient (VERP addresses differ per recipient, PLAN.md §6a). */
    @FunctionalInterface
    public interface EnvelopeSender {
        String reversePath(Job job, RecipientResult recipient);
    }

    /** Where to connect for one address of a mail exchanger; tests point this at local fake servers. */
    @FunctionalInterface
    public interface Endpoints {
        InetSocketAddress endpoint(MxResolver.MxHost mx, InetAddress address);
    }

    /** Optional settings; the defaults are right for production. */
    public static final class Options {
        public Endpoints endpoints = (mx, address) -> new InetSocketAddress(address, SMTP_PORT);
        /** Context for certificate verification ({@code verifyCertificate}); {@code null} = JDK default. */
        public SSLContext verifyingContext;
        public RetryPolicy retryPolicy;
        /** DKIM keys per signing domain; messages whose {@code From} domain has no key are sent unsigned. */
        public DkimSigner.Keys dkim = DkimSigner.Keys.none();
        public EnvelopeSender envelopeSender = (job, r) -> job.request.from == null ? "" : job.request.from.trim();
        /** Called with the job's state after each delivery run (callbacks, retry scheduling). */
        public Consumer<Job> onRunFinished = job -> {
        };
    }

    private final Config config;
    private final JobStore store;
    private final MxResolver resolver;
    private final Executor executor;
    private final Semaphore permits;
    private final Options options;
    private final RetryPolicy retryPolicy;
    private final Set<String> running = ConcurrentHashMap.newKeySet();

    public DeliveryEngine(Config config, JobStore store, MxResolver resolver, Executor executor, Options options) {
        this.config = config;
        this.store = store;
        this.resolver = resolver;
        this.executor = executor;
        this.options = options != null ? options : new Options();
        this.permits = new Semaphore(config.maxConcurrentDeliveries, true);
        this.retryPolicy = this.options.retryPolicy != null ? this.options.retryPolicy : RetryScheduler.backoff(config);
    }

    /** Number of domain deliveries that may start right now (for tests and monitoring). */
    public int availablePermits() {
        return permits.availablePermits();
    }

    // ---- job runs ---------------------------------------------------------------------------------------------

    /**
     * Delivers the job in the background; ignored if a run for it is already in progress.
     *
     * @return {@code true} if a run was started, {@code false} if one was already in progress
     */
    public boolean submit(Job job) {
        String id = job.id;
        if (!running.add(id)) return false;
        try {
            executor.execute(() -> {
                try {
                    run(id);
                } finally {
                    running.remove(id);
                }
            });
        } catch (RuntimeException e) {
            running.remove(id);
            throw e;
        }
        return true;
    }

    /**
     * Delivers the job's due recipients synchronously (domain tasks still run on the executor and wait for permits)
     * and returns its resulting state. Recipients that are pending, left {@code sending} by an interrupted run, or
     * deferred with a due {@code nextAttemptAt} are attempted; the others are left alone.
     */
    public Optional<Job> deliver(String id) {
        if (!running.add(id)) {
            try {
                return store.get(id);
            } catch (IOException e) {
                return Optional.empty();
            }
        }
        try {
            return run(id);
        } finally {
            running.remove(id);
        }
    }

    private Optional<Job> run(String id) {
        try {
            Instant now = Instant.now();
            Map<String, List<Integer>> byDomain = new LinkedHashMap<>();
            boolean[] settled = {false};
            Optional<Job> started = store.update(id, job -> {
                if (!job.status.needsDelivery()) return;
                for (RecipientResult r : job.recipients) {
                    if (isDue(r, now)) byDomain.computeIfAbsent(r.domain(), d -> new ArrayList<>()).add(r.index);
                }
                if (!byDomain.isEmpty()) {
                    job.status = JobStatus.SENDING;
                } else {
                    // nothing due: if a run was interrupted after the recipients got their answers but before the
                    // job status was recomputed (e.g. a restart), settle it now
                    JobStatus derived = JobStatus.aggregate(job.recipients.stream().map(r -> r.status).toList());
                    if (derived != null && derived != job.status) {
                        job.recomputeStatus(now);
                        settled[0] = true;
                    }
                }
            });
            if (settled[0]) started.ifPresent(options.onRunFinished);
            if (started.isEmpty() || byDomain.isEmpty()) return started;
            Job snapshot = started.get();

            CountDownLatch done = new CountDownLatch(byDomain.size());
            for (Map.Entry<String, List<Integer>> e : byDomain.entrySet()) {
                Runnable task = () -> {
                    try {
                        deliverDomain(snapshot, e.getKey(), e.getValue());
                    } finally {
                        done.countDown();
                    }
                };
                try {
                    executor.execute(task);
                } catch (RuntimeException rejected) {
                    done.countDown();
                    LOG.log(Level.WARNING, "could not start delivery of job " + id + " to " + e.getKey(), rejected);
                }
            }
            done.await();

            Optional<Job> finished = store.update(id, job -> job.recomputeStatus(Instant.now()));
            finished.ifPresent(options.onRunFinished);
            return finished;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return Optional.empty();
        } catch (IOException | RuntimeException e) {
            LOG.log(Level.WARNING, "delivery run for job " + id + " failed", e);
            return Optional.empty();
        }
    }

    // ---- restart recovery -------------------------------------------------------------------------------------

    /**
     * Startup recovery (PLAN.md §4): re-enqueues every job a previous process left unfinished ({@code queued},
     * {@code sending} or {@code deferred}).
     *
     * <p>Only recipients without a final answer are attempted again: {@code delivered}, {@code failed} and
     * {@code bounced} recipients are never re-sent. Recipients that are {@code pending}, or were left
     * {@code sending} by the interrupted run, are delivered right away (a recipient left {@code sending} may already
     * have received the message if the process died between the server's reply and saving it; that small window is
     * the "where possible" in the plan). A job whose remaining recipients are all {@code deferred} until later is
     * handed to {@code scheduleLater} (the {@link RetryScheduler}) instead, so its backoff is kept. A job left
     * {@code sending} with every recipient already final just has its status recomputed (and reported to
     * {@link Options#onRunFinished}).
     *
     * @param scheduleLater receives jobs with nothing due now, e.g. {@link RetryScheduler#schedule}
     * @return the number of jobs resumed (submitted now or scheduled)
     */
    public int resumeAll(Consumer<Job> scheduleLater) throws IOException {
        int resumed = 0;
        for (String id : store.listIds()) {
            try {
                Optional<Job> loaded = store.get(id);
                if (loaded.isEmpty() || !loaded.get().status.needsDelivery()) continue;
                Job job = loaded.get();
                if (hasWorkNow(job, Instant.now())) submit(job);
                else scheduleLater.accept(job);
                resumed++;
            } catch (IOException | RuntimeException e) {
                LOG.log(Level.WARNING, "could not resume job " + id, e);
            }
        }
        return resumed;
    }

    /**
     * True if a run now would attempt a recipient, or would settle a job status that is out of date (e.g.
     * {@code sending} although every recipient is final).
     */
    private static boolean hasWorkNow(Job job, Instant now) {
        for (RecipientResult r : job.recipients) {
            if (isDue(r, now)) return true;
        }
        JobStatus derived = JobStatus.aggregate(job.recipients.stream().map(r -> r.status).toList());
        return derived != null && derived != job.status;
    }

    private static boolean isDue(RecipientResult r, Instant now) {
        return switch (r.status) {
            case PENDING, SENDING -> true;
            case DEFERRED -> r.nextAttemptAt == null || !r.nextAttemptAt.isAfter(now);
            default -> false;
        };
    }

    // ---- one domain -------------------------------------------------------------------------------------------

    /** The answer for one recipient within a domain task. */
    private static final class Outcome {
        final RecipientResult recipient;
        /** null = no final answer yet. */
        RecipientResult.Status status;
        String mx;
        Integer smtpCode;
        String enhancedStatus;
        String smtpMessage;
        String error;
        Boolean tls;
        /** True while every failure noted so far was permanent (e.g. a 5xx greeting from each MX). */
        boolean permanentEverywhere = true;
        boolean anyNote;

        Outcome(RecipientResult recipient) {
            this.recipient = recipient;
        }

        void set(RecipientResult.Status status, String mx, SmtpResponse reply, String error, Boolean tls) {
            this.status = status;
            record(mx, reply, error, tls);
        }

        /** Remembers the latest failure without deciding the outcome. */
        void note(String mx, SmtpResponse reply, ResultClassifier.Classification c, Boolean tls) {
            record(mx, reply, c.error(), tls);
            track(c);
        }

        void note(String mx, String message, ResultClassifier.Classification c, Boolean tls) {
            record(mx, (SmtpResponse) null, c.error(), tls);
            this.smtpMessage = message;
            track(c);
        }

        private void track(ResultClassifier.Classification c) {
            anyNote = true;
            if (!c.isPermanent()) permanentEverywhere = false;
        }

        private void record(String mx, SmtpResponse reply, String error, Boolean tls) {
            this.mx = mx;
            this.smtpCode = reply != null ? reply.code() : null;
            this.enhancedStatus = reply != null ? reply.enhancedStatus() : null;
            this.smtpMessage = reply != null ? reply.message() : null;
            this.error = error;
            this.tls = tls;
        }
    }

    private void deliverDomain(Job snapshot, String domain, List<Integer> indexes) {
        try {
            permits.acquire();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return;
        }
        try {
            Instant start = Instant.now();
            List<Outcome> outcomes = new ArrayList<>();
            Optional<Job> begun = store.update(snapshot.id, job -> {
                for (int i : indexes) {
                    RecipientResult r = job.recipient(i);
                    if (r != null && !r.status.isFinal()) r.beginAttempt(start);
                }
            });
            if (begun.isEmpty()) return;
            for (int i : indexes) {
                RecipientResult r = begun.get().recipient(i);
                if (r != null && r.status == RecipientResult.Status.SENDING) outcomes.add(new Outcome(r));
            }
            if (outcomes.isEmpty()) return;

            boolean tlsPolicyOnly = attempt(begun.get(), domain, outcomes);
            apply(snapshot.id, outcomes, tlsPolicyOnly);
        } catch (IOException | RuntimeException e) {
            LOG.log(Level.WARNING, "delivery of job " + snapshot.id + " to " + domain + " failed", e);
        } finally {
            permits.release();
        }
    }

    /**
     * Tries the domain's mail exchangers until every outcome is decided or they run out.
     *
     * @return true if mail exchangers were reached and every one of them failed the TLS policy (so undecided
     *         recipients fail permanently with the TLS error rather than being deferred)
     */
    private boolean attempt(Job job, String domain, List<Outcome> outcomes) {
        Path file = store.payloadFile(job.id);
        MessageSource message;
        try {
            byte[] signature = dkimSignature(job.id, file);
            message = new MessageSource(signature, file, signature.length + Files.size(file));
        } catch (IOException e) {
            for (Outcome o : outcomes) {
                o.note(null, "message file unavailable: " + e.getMessage(),
                        new ResultClassifier.Classification(ResultClassifier.Kind.TRANSIENT, MESSAGE_UNAVAILABLE, true),
                        null);
            }
            return false;
        }

        List<MxResolver.MxHost> hosts;
        try {
            hosts = resolver.resolve(domain);
        } catch (MxResolver.MxException e) {
            ResultClassifier.Classification c = ResultClassifier.dns(e);
            for (Outcome o : outcomes) {
                if (c.isPermanent()) o.set(RecipientResult.Status.FAILED, null, null, c.error(), null);
                else o.note(null, e.getMessage(), c, null);
                o.smtpMessage = e.getMessage();
            }
            return false;
        }

        TlsPolicy policy = options.verifyingContext != null
                ? new TlsPolicy(job.request.requireTls, job.request.verifyCertificate, options.verifyingContext)
                : new TlsPolicy(job.request.requireTls, job.request.verifyCertificate);

        boolean anyHostTried = false;
        boolean allTlsPolicyFailures = true;
        for (MxResolver.MxHost mx : hosts) {
            if (undecided(outcomes).isEmpty()) break;
            InetAddress[] addresses;
            try {
                addresses = resolver.addresses(mx);
            } catch (UnknownHostException e) {
                for (Outcome o : undecided(outcomes)) {
                    o.note(mx.host(), "cannot resolve " + mx.host() + ": " + e.getMessage(),
                            ResultClassifier.network(), null);
                }
                anyHostTried = true;
                allTlsPolicyFailures = false;
                continue;
            }
            boolean hostTlsFailure = false;
            boolean hostOtherFailure = false;
            for (InetAddress address : addresses) {
                if (undecided(outcomes).isEmpty()) break;
                HostResult result = session(job, mx, address, policy, message, outcomes, true);
                if (result == HostResult.RETRY_PLAINTEXT) {
                    result = session(job, mx, address, policy, message, outcomes, false);
                }
                if (result == HostResult.TLS_POLICY_FAILED) hostTlsFailure = true;
                else if (result != HostResult.DONE) hostOtherFailure = true;
                else break; // the session reached the end of its transaction(s)
            }
            anyHostTried = true;
            // a host counts as a TLS failure only if no address got any further for another reason
            if (!hostTlsFailure || hostOtherFailure) allTlsPolicyFailures = false;
        }
        return anyHostTried && allTlsPolicyFailures;
    }

    private enum HostResult {
        /** The transaction(s) ran; recipients still undecided got 4xx replies. */
        DONE,
        /** Couldn't connect, or the server failed before the transaction. */
        FAILED,
        /** The TLS policy rejected this host ({@code requireTls} / {@code verifyCertificate}). */
        TLS_POLICY_FAILED,
        /** Opportunistic TLS failed; reconnect and send without STARTTLS. */
        RETRY_PLAINTEXT
    }

    /** One SMTP connection: greeting, EHLO, STARTTLS, then one transaction per distinct reverse path. */
    private HostResult session(Job job, MxResolver.MxHost mx, InetAddress address, TlsPolicy policy,
                               MessageSource message, List<Outcome> outcomes, boolean useTls) {
        String host = mx.host();
        InetSocketAddress endpoint = options.endpoints.endpoint(mx, address);
        SmtpClient client;
        try {
            client = SmtpClient.connect(endpoint, host, config.connectTimeout, config.readTimeout);
        } catch (IOException e) {
            noteAll(outcomes, host, "connect to " + host + " (" + address.getHostAddress() + ") failed: " + e,
                    ResultClassifier.network(), null);
            return HostResult.FAILED;
        }
        boolean tls = false;
        try {
            SmtpResponse greeting = client.greeting();
            if (!greeting.isPositive()) {
                noteAll(outcomes, host, greeting, null);
                return HostResult.FAILED;
            }
            SmtpResponse ehlo = client.ehlo(config.heloName);
            if (!ehlo.isPositive()) {
                noteAll(outcomes, host, ehlo, null);
                return HostResult.FAILED;
            }
            if (useTls) {
                TlsPolicy.Result t = policy.negotiate(client, config.heloName);
                if (t.status() == TlsPolicy.Status.FAILED) {
                    if (t.retryWithoutTls()) return HostResult.RETRY_PLAINTEXT;
                    noteAll(outcomes, host, t.detail(), new ResultClassifier.Classification(
                            ResultClassifier.Kind.TRANSIENT, t.errorCode(), false), false);
                    return HostResult.TLS_POLICY_FAILED;
                }
                tls = t.encrypted();
                if (tls && (t.ehlo() == null || !t.ehlo().isPositive())) {
                    if (t.ehlo() != null) noteAll(outcomes, host, t.ehlo(), true);
                    else noteAll(outcomes, host, "no EHLO reply after STARTTLS", ResultClassifier.network(), true);
                    return HostResult.FAILED;
                }
            }

            // group by reverse path: with VERP each recipient needs its own transaction
            Map<String, List<Outcome>> byReversePath = new LinkedHashMap<>();
            for (Outcome o : undecided(outcomes)) {
                byReversePath.computeIfAbsent(options.envelopeSender.reversePath(job, o.recipient),
                        k -> new ArrayList<>()).add(o);
            }
            boolean first = true;
            for (Map.Entry<String, List<Outcome>> e : byReversePath.entrySet()) {
                if (!first) {
                    SmtpResponse rset = client.rset();
                    if (!rset.isPositive()) {
                        noteAll(outcomes, host, rset, tls);
                        return HostResult.FAILED;
                    }
                }
                first = false;
                transaction(client, host, tls, e.getKey(), e.getValue(), message);
            }
            return HostResult.DONE;
        } catch (IOException e) {
            noteAll(outcomes, host, "connection to " + host + " failed: " + e, ResultClassifier.network(),
                    tls ? true : null);
            return HostResult.FAILED;
        } finally {
            LOG.fine(() -> "SMTP " + job.id + " " + host + ":\n  " + String.join("\n  ", client.transcript()));
            client.quit();
        }
    }

    /** {@code MAIL}, {@code RCPT} per recipient, {@code DATA}. Decides outcomes on 2xx/5xx; 4xx leaves them open. */
    private void transaction(SmtpClient client, String host, boolean tls, String reversePath, List<Outcome> group,
                             MessageSource message) throws IOException {
        SmtpResponse mail = client.mail(reversePath, message.size());
        if (!mail.isPositive()) {
            for (Outcome o : group) decide(o, host, mail, ResultClassifier.Phase.MAIL, tls);
            return;
        }
        List<Outcome> accepted = new ArrayList<>();
        for (Outcome o : group) {
            SmtpResponse rcpt = client.rcpt(o.recipient.address);
            if (rcpt.isPositive()) accepted.add(o);
            else decide(o, host, rcpt, ResultClassifier.Phase.RCPT, tls);
        }
        if (accepted.isEmpty()) return;
        SmtpResponse data;
        try (InputStream in = message.open()) {
            data = client.data(in);
        }
        for (Outcome o : accepted) decide(o, host, data, ResultClassifier.Phase.DATA, tls);
    }

    // ---- DKIM ---------------------------------------------------------------------------------------------------

    /** The bytes sent as the message: the DKIM-Signature header (possibly empty) followed by the payload file. */
    private record MessageSource(byte[] signature, Path file, long size) {
        InputStream open() throws IOException {
            InputStream payload = Files.newInputStream(file);
            return signature.length == 0 ? payload
                    : new SequenceInputStream(new ByteArrayInputStream(signature), payload);
        }
    }

    /**
     * The job's {@code DKIM-Signature} header field (ending in CRLF), or an empty array if the message isn't signed.
     * Computed once per job under the job's lock and saved, so concurrent domain tasks, retries and restarts all use
     * the same signature.
     *
     * @throws IOException only if the payload file can't be read (the message can't be sent at all)
     */
    private byte[] dkimSignature(String id, Path payload) throws IOException {
        Path saved = store.signatureFile(id);
        return store.withLock(id, () -> {
            try {
                return Files.readAllBytes(saved);
            } catch (NoSuchFileException e) {
                // not signed yet
            }
            if (!Files.isRegularFile(payload)) throw new NoSuchFileException(payload.toString());
            if (options.dkim.domains().isEmpty()) return new byte[0];
            DkimSigner signer;
            String header;
            try {
                String domain = DkimSigner.fromDomain(payload);
                signer = options.dkim.forDomain(domain);
                if (signer == null) return new byte[0];
                header = signer.sign(payload);
            } catch (IOException | RuntimeException e) {
                LOG.log(Level.WARNING, "could not DKIM-sign job " + id + "; sending it unsigned", e);
                return new byte[0];
            }
            byte[] bytes = header.getBytes(StandardCharsets.ISO_8859_1);
            try {
                JobStore.writeAtomic(saved, bytes);
            } catch (IOException e) {
                LOG.log(Level.WARNING, "could not save DKIM signature of job " + id, e);
            }
            return bytes;
        });
    }

    /** Applies the {@link ResultClassifier} verdict: delivered, failed, or left open (next MX / deferred). */
    private static void decide(Outcome o, String host, SmtpResponse reply, ResultClassifier.Phase phase, boolean tls) {
        ResultClassifier.Classification c = ResultClassifier.classify(reply, phase);
        if (c.isSuccess()) o.set(RecipientResult.Status.DELIVERED, host, reply, null, tls);
        else if (c.isPermanent() && c.decides()) o.set(RecipientResult.Status.FAILED, host, reply, c.error(), tls);
        else o.note(host, reply, c, tls);
    }

    private static List<Outcome> undecided(List<Outcome> outcomes) {
        List<Outcome> out = new ArrayList<>();
        for (Outcome o : outcomes) if (o.status == null) out.add(o);
        return out;
    }

    /** Notes a session-level reply (greeting, EHLO, RSET) for every undecided recipient. */
    private static void noteAll(List<Outcome> outcomes, String host, SmtpResponse reply, Boolean tls) {
        ResultClassifier.Classification c = ResultClassifier.classify(reply, ResultClassifier.Phase.SESSION);
        for (Outcome o : undecided(outcomes)) o.note(host, reply, c, tls);
    }

    private static void noteAll(List<Outcome> outcomes, String host, String message,
                                ResultClassifier.Classification c, Boolean tls) {
        for (Outcome o : undecided(outcomes)) o.note(host, message, c, tls);
    }

    /** Writes the domain's outcomes to the job. */
    private void apply(String id, List<Outcome> outcomes, boolean tlsPolicyOnly) throws IOException {
        store.update(id, job -> {
            Instant now = Instant.now();
            for (Outcome o : outcomes) {
                RecipientResult r = job.recipient(o.recipient.index);
                if (r == null || r.status.isFinal()) continue;
                if (o.status == RecipientResult.Status.DELIVERED) {
                    r.markDelivered(now, o.mx, o.smtpCode != null ? o.smtpCode : 250, o.smtpMessage,
                            Boolean.TRUE.equals(o.tls));
                } else if (o.status == RecipientResult.Status.FAILED) {
                    r.markFailed(now, o.mx, o.smtpCode, o.smtpMessage, o.error);
                } else if (tlsPolicyOnly && isTlsError(o.error)) {
                    r.markFailed(now, o.mx, o.smtpCode, o.smtpMessage, o.error);
                } else if (o.anyNote && o.permanentEverywhere) {
                    // every mail exchanger refused the session with a 5xx
                    r.markFailed(now, o.mx, o.smtpCode, o.smtpMessage, o.error);
                } else {
                    Instant next = retryPolicy.nextAttempt(r, now);
                    if (next == null) {
                        r.markFailed(now, o.mx, o.smtpCode, o.smtpMessage, RETRIES_EXHAUSTED);
                    } else {
                        r.markDeferred(next, o.mx, o.smtpCode, o.smtpMessage,
                                o.error != null ? o.error : CONNECTION_FAILED);
                    }
                }
                r.tls = o.tls;
                r.enhancedStatus = o.enhancedStatus;
            }
        });
    }

    private static boolean isTlsError(String error) {
        return TlsPolicy.TLS_REQUIRED_NOT_AVAILABLE.equals(error) || TlsPolicy.TLS_CERT_INVALID.equals(error);
    }
}
