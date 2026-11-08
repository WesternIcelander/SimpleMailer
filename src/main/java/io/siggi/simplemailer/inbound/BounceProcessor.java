package io.siggi.simplemailer.inbound;

import io.siggi.simplemailer.callback.CallbackDispatcher;
import io.siggi.simplemailer.model.Job;
import io.siggi.simplemailer.model.RecipientResult;
import io.siggi.simplemailer.store.JobStore;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.Optional;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Applies a received bounce to its job (PLAN.md §6a). Both intakes (the inbound SMTP listener and
 * {@code POST /v1/bounces}) go through here, so a bounce has the same effect whichever way it arrives:
 *
 * <ol>
 *   <li><b>Verify</b> the envelope recipient against the VERP HMAC ({@link VerpAddress#verify}) and look up the job
 *       and recipient it names.</li>
 *   <li><b>Parse</b> the message with {@link BounceParser} (or take the fields of a pre-parsed API report).</li>
 *   <li><b>Dedupe</b>: a bounce whose DSN {@code Message-ID} or content hash is already recorded for that recipient
 *       changes nothing and fires no callback ({@link Outcome#DUPLICATE}).</li>
 *   <li><b>Apply</b>: {@code Action: failed} (or a non-DSN bounce) moves the recipient to {@code bounced} (also
 *       from {@code delivered}: bounces can arrive late), records the DSN status and diagnostic, recomputes the job
 *       status, saves the raw message to {@code data/bounces/{uuid}-{n}.eml}, adds an entry to the job's
 *       {@code bounces[]} and fires a {@code bounced} callback event. {@code delayed} (and other non-failure actions)
 *       is recorded as a note without changing any status; auto-replies and other non-bounces are recorded as
 *       ignored.</li>
 * </ol>
 *
 * <p>All job changes happen under the job's store lock, so concurrent deliveries of the same bounce are applied
 * once. The callback is fired after the lock is released. Callers bound the size of raw messages. Thread safe.
 */
public final class BounceProcessor {
    private static final Logger LOG = Logger.getLogger(BounceProcessor.class.getName());

    /**
     * Records kept per recipient. Past this, messages that don't newly bounce the recipient are dropped (not
     * recorded, raw message not stored), so a flood of auto-replies to a bounce address can't grow a job without
     * bound.
     */
    static final int MAX_RECORDS_PER_RECIPIENT = 10;
    /** Longest DSN status / diagnostic / address kept from a pre-parsed report. */
    private static final int MAX_FIELD = 1000;

    public static final String KIND_DSN = "dsn";
    public static final String KIND_NON_DSN_BOUNCE = "non_dsn_bounce";
    public static final String KIND_REPORT = "report";
    public static final String KIND_AUTO_REPLY = "auto_reply";
    public static final String KIND_NOT_BOUNCE = "not_bounce";

    /** Which intake a bounce arrived through; recorded as {@code source} in {@code bounces[]}. */
    public enum Source {
        SMTP("smtp"), API("api");

        private final String wireName;

        Source(String wireName) {
            this.wireName = wireName;
        }

        public String wireName() {
            return wireName;
        }
    }

    /** What happened to a bounce. */
    public enum Outcome {
        /** A failure: the recipient is now {@code bounced} and a callback event was fired. */
        APPLIED,
        /** A DSN with a non-failure action ({@code delayed}, {@code delivered}, ...): recorded, nothing changed. */
        NOTED,
        /** Not a bounce (auto-reply or anything else): recorded as ignored, nothing changed. */
        IGNORED,
        /** Already recorded for this recipient (same DSN {@code Message-ID} or content hash): nothing changed. */
        DUPLICATE,
        /** The address isn't a {@code bounce+…@bounceDomain} address. */
        NOT_BOUNCE_ADDRESS,
        /** The address looks like a bounce address but its HMAC tag is wrong (forged or altered). */
        BAD_TAG,
        /** The address is valid but the job (or the recipient index) doesn't exist, e.g. it has expired. */
        UNKNOWN_JOB
    }

    /**
     * Result of processing one bounce.
     *
     * @param outcome        what happened
     * @param jobId          the job the address names (null for {@link Outcome#NOT_BOUNCE_ADDRESS} and
     *                       {@link Outcome#BAD_TAG})
     * @param recipientIndex the recipient index the address names, or null
     * @param eventId        the {@code bounced} callback event id, if one was fired
     * @param detail         a short human-readable explanation
     */
    public record Result(Outcome outcome, String jobId, Integer recipientIndex, String eventId, String detail) {
    }

    /** Result of {@link #checkAddress}, e.g. for the inbound SMTP {@code RCPT TO}. */
    public record AddressCheck(Outcome outcome, String jobId, Integer recipientIndex) {
        /** True if a bounce for this address would be accepted. */
        public boolean accepted() {
            return outcome == null;
        }
    }

    /**
     * A pre-parsed bounce from {@code POST /v1/bounces} (JSON form).
     *
     * @param action         DSN action ({@code failed}, {@code delayed}, ...); if null it is derived from
     *                       {@code status} (5.x.x failed, 4.x.x delayed, 2.x.x delivered), defaulting to failed
     * @param status         RFC 3463 status, e.g. {@code 5.1.1}, or null
     * @param diagnostic     diagnostic text, e.g. {@code 550 5.1.1 user unknown}, or null
     * @param finalRecipient the recipient the receiver saw, or null
     */
    public record Report(String action, String status, String diagnostic, String finalRecipient) {
    }

    private final JobStore store;
    private final VerpAddress verp;
    private final CallbackDispatcher callbacks;
    private final Path dataDir;
    private final Path bouncesDir;

    /**
     * @param dataDir   the data directory; raw bounces go to {@code bounces/} below it
     * @param store     the job store
     * @param verp      the VERP address codec ({@code bounces.domain} and {@code bounces.secret})
     * @param callbacks the callback dispatcher, or null to fire no callbacks
     */
    public BounceProcessor(Path dataDir, JobStore store, VerpAddress verp, CallbackDispatcher callbacks)
            throws IOException {
        this.store = Objects.requireNonNull(store, "store");
        this.verp = Objects.requireNonNull(verp, "verp");
        this.callbacks = callbacks;
        this.dataDir = dataDir;
        this.bouncesDir = dataDir.resolve("bounces");
        Files.createDirectories(bouncesDir);
    }

    /**
     * Checks a bounce address: VERP syntax and domain, HMAC tag, and that the job and recipient exist. Accepted
     * when {@link AddressCheck#accepted()}; otherwise the outcome says why not.
     */
    public AddressCheck checkAddress(String address) throws IOException {
        VerpAddress.Verification v = verp.verify(address);
        if (v.status() == VerpAddress.Status.NOT_BOUNCE_ADDRESS) {
            return new AddressCheck(Outcome.NOT_BOUNCE_ADDRESS, null, null);
        }
        if (v.status() == VerpAddress.Status.BAD_TAG) return new AddressCheck(Outcome.BAD_TAG, null, null);
        VerpAddress.Decoded d = v.address();
        Optional<Job> job = store.get(d.jobId());
        if (job.isEmpty() || job.get().recipient(d.recipientIndex()) == null) {
            return new AddressCheck(Outcome.UNKNOWN_JOB, d.jobId(), d.recipientIndex());
        }
        return new AddressCheck(null, d.jobId(), d.recipientIndex());
    }

    /**
     * Processes a complete received message (SMTP intake, or the raw API form).
     *
     * @param raw            the message bytes (bounded by the caller)
     * @param address        the envelope recipient it was sent to (the VERP bounce address)
     * @param envelopeSender the SMTP {@code MAIL FROM} path ({@code ""} for the null path), or null when unknown
     * @param source         the intake it came through
     */
    public Result processMessage(byte[] raw, String address, String envelopeSender, Source source) throws IOException {
        Objects.requireNonNull(raw, "raw");
        AddressCheck check = checkAddress(address);
        if (!check.accepted()) return rejected(check);

        BounceParser.Result parsed = BounceParser.parse(raw, envelopeSender);
        Incoming in = new Incoming();
        in.source = source;
        in.raw = raw;
        in.messageId = parsed.messageId();
        in.contentHash = parsed.contentHash();
        switch (parsed.kind()) {
            case DSN -> in.kind = KIND_DSN;
            case NON_DSN_BOUNCE -> in.kind = KIND_NON_DSN_BOUNCE;
            case AUTO_REPLY -> in.kind = KIND_AUTO_REPLY;
            case NOT_BOUNCE -> in.kind = KIND_NOT_BOUNCE;
        }
        in.candidates = parsed.recipients();
        return apply(check, in);
    }

    /** Processes a pre-parsed report ({@code POST /v1/bounces} JSON form). */
    public Result processReport(String address, Report report, Source source) throws IOException {
        Objects.requireNonNull(report, "report");
        AddressCheck check = checkAddress(address);
        if (!check.accepted()) return rejected(check);

        String status = limit(trimToNull(report.status()));
        String diagnostic = limit(trimToNull(report.diagnostic()));
        String finalRecipient = limit(trimToNull(report.finalRecipient()));
        String action = trimToNull(report.action());
        action = action == null ? null : action.toLowerCase(Locale.ROOT);
        Incoming in = new Incoming();
        in.source = source;
        in.kind = KIND_REPORT;
        in.candidates = List.of(new BounceParser.Recipient(finalRecipient, null, action, status, diagnostic, null));
        // a resent identical report is a duplicate
        String canonical = String.join("\n", nz(action), nz(status), nz(diagnostic), nz(finalRecipient));
        in.contentHash = JobStore.sha256Hex(canonical.getBytes(StandardCharsets.UTF_8)).toLowerCase(Locale.ROOT);
        return apply(check, in);
    }

    // ---- internals --------------------------------------------------------------------------------------------

    /** A bounce on its way in: what the parser (or the API report) said about it. */
    private static final class Incoming {
        Source source;
        String kind;
        byte[] raw;
        String messageId;
        String contentHash;
        List<BounceParser.Recipient> candidates = List.of();
    }

    private static Result rejected(AddressCheck check) {
        String detail = switch (check.outcome()) {
            case NOT_BOUNCE_ADDRESS -> "not a bounce address";
            case BAD_TAG -> "bounce address tag does not verify";
            case UNKNOWN_JOB -> "unknown job or recipient";
            default -> check.outcome().name();
        };
        return new Result(check.outcome(), check.jobId(), check.recipientIndex(), null, detail);
    }

    private Result apply(AddressCheck check, Incoming in) throws IOException {
        String jobId = check.jobId();
        int index = check.recipientIndex();
        Result result = store.withLock(jobId, () -> {
            Optional<Job> loaded = store.get(jobId);
            if (loaded.isEmpty() || loaded.get().recipient(index) == null) {
                return new Result(Outcome.UNKNOWN_JOB, jobId, index, null, "unknown job or recipient");
            }
            Job job = loaded.get();
            RecipientResult rcpt = job.recipient(index);

            String dedupeKey = in.messageId != null ? "message-id:" + in.messageId : "sha256:" + in.contentHash;
            int recordsForRecipient = 0;
            for (Job.BounceRecord b : job.bounces) {
                if (b.recipientIndex != index) continue;
                recordsForRecipient++;
                if (dedupeKey.equals(b.dedupeKey) || (in.contentHash != null && in.contentHash.equals(b.contentHash))) {
                    return new Result(Outcome.DUPLICATE, jobId, index, null, "bounce already recorded");
                }
            }

            BounceParser.Recipient chosen = choose(in.candidates, rcpt.address);
            String action = chosen == null ? null : effectiveAction(chosen.action(), chosen.status());
            boolean isBounce = in.kind.equals(KIND_DSN) || in.kind.equals(KIND_NON_DSN_BOUNCE)
                    || in.kind.equals(KIND_REPORT);
            boolean failure = isBounce && "failed".equals(action);
            Outcome outcome = !isBounce ? Outcome.IGNORED : failure ? Outcome.APPLIED : Outcome.NOTED;

            boolean newlyBounced = failure && rcpt.status != RecipientResult.Status.BOUNCED;
            if (recordsForRecipient >= MAX_RECORDS_PER_RECIPIENT && !newlyBounced) {
                LOG.warning("dropping " + in.kind + " for job " + jobId + " recipient " + index
                        + ": too many bounces recorded");
                return new Result(Outcome.IGNORED, jobId, index, null, "too many bounces recorded for this recipient");
            }

            Instant now = Instant.now();
            Job.BounceRecord record = new Job.BounceRecord();
            record.receivedAt = now;
            record.source = in.source.wireName();
            record.recipientIndex = index;
            record.recipient = rcpt.address;
            record.kind = in.kind;
            record.action = action;
            record.ignored = outcome != Outcome.APPLIED;
            if (chosen != null) {
                record.status = chosen.status();
                record.diagnostic = chosen.diagnosticCode();
                String fr = chosen.finalRecipient() != null ? chosen.finalRecipient() : chosen.originalRecipient();
                if (fr != null && !fr.equalsIgnoreCase(rcpt.address)) record.finalRecipient = fr;
            }
            record.dedupeKey = dedupeKey;
            record.contentHash = in.contentHash;
            if (in.raw != null) {
                String name = jobId + "-" + (job.bounces.size() + 1) + ".eml";
                JobStore.writeAtomic(bouncesDir.resolve(name), in.raw);
                record.file = dataDir.relativize(bouncesDir.resolve(name)).toString().replace('\\', '/');
            }
            job.bounces.add(record);

            if (failure) {
                rcpt.markBounced(now, record.status, record.diagnostic);
                job.recomputeStatus(now);
            }
            store.save(job);
            String detail = switch (outcome) {
                case APPLIED -> "recipient marked bounced";
                case NOTED -> "recorded (action " + action + "), status unchanged";
                default -> "not a bounce (" + in.kind + "), ignored";
            };
            return new Result(outcome, jobId, index, null, detail);
        });

        LOG.info("bounce via " + in.source.wireName() + " for job " + jobId + " recipient " + index + ": "
                + result.outcome() + " (" + result.detail() + ")");
        if (result.outcome() == Outcome.APPLIED && callbacks != null) {
            try {
                Optional<String> eventId = callbacks.bounced(jobId);
                if (eventId.isPresent()) {
                    result = new Result(result.outcome(), jobId, index, eventId.get(), result.detail());
                }
            } catch (IOException | RuntimeException e) {
                // the bounce is applied; a callback problem never changes mail status
                LOG.log(Level.WARNING, "could not queue bounced callback for job " + jobId, e);
            }
        }
        return result;
    }

    /**
     * The DSN recipient group that describes {@code address}: one whose {@code Final-Recipient} or
     * {@code Original-Recipient} matches it, else the first {@code failed} group (VERP already identifies the
     * recipient, so a forwarded address is fine), else the first group.
     */
    static BounceParser.Recipient choose(List<BounceParser.Recipient> candidates, String address) {
        if (candidates == null || candidates.isEmpty()) return null;
        for (BounceParser.Recipient r : candidates) {
            if (address.equalsIgnoreCase(nz(r.finalRecipient())) || address.equalsIgnoreCase(nz(r.originalRecipient()))) {
                return r;
            }
        }
        for (BounceParser.Recipient r : candidates) {
            if ("failed".equals(effectiveAction(r.action(), r.status()))) return r;
        }
        return candidates.get(0);
    }

    /** The action, or one derived from the status class when the action is missing (default {@code failed}). */
    static String effectiveAction(String action, String status) {
        if (action != null && !action.isBlank()) return action.trim().toLowerCase(Locale.ROOT);
        if (status != null) {
            if (status.startsWith("4")) return "delayed";
            if (status.startsWith("2")) return "delivered";
        }
        return "failed";
    }

    private static String nz(String s) {
        return s == null ? "" : s;
    }

    private static String trimToNull(String s) {
        if (s == null) return null;
        String t = s.trim();
        return t.isEmpty() ? null : t;
    }

    private static String limit(String s) {
        if (s == null) return null;
        String oneLine = s.replaceAll("[\\r\\n]+", " ");
        return oneLine.length() <= MAX_FIELD ? oneLine : oneLine.substring(0, MAX_FIELD);
    }
}
