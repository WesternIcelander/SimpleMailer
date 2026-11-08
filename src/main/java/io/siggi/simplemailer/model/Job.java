package io.siggi.simplemailer.model;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

/**
 * A send job: the persisted state behind {@code data/jobs/{uuid}.json} and the status JSON (PLAN.md §3, §4).
 *
 * <p>Mutable and not thread safe; the job store serialises access per job.
 */
public final class Job {
    public String id;
    public JobStatus status = JobStatus.QUEUED;
    /** SHA-256 (hex) of the canonicalised request, for idempotent replays (PLAN.md §4). */
    public String payloadHash;
    public Instant createdAt;
    public Instant updatedAt;

    /** The request as accepted (message bodies may be moved to the payload file by the store). */
    public SendRequest request;
    public List<RecipientResult> recipients = new ArrayList<>();

    /** Job-level error such as {@code ATTACHMENT_FETCH_FAILED}. */
    public String error;
    public String errorMessage;

    public CallbackState callback;
    public List<BounceRecord> bounces = new ArrayList<>();

    /** Callback delivery status (PLAN.md §6). */
    public static final class CallbackState {
        public String url;
        /** {@code none}, {@code pending}, {@code delivered} or {@code failed} for the most recent event. */
        public String status = "none";
        public String lastEventId;
        public String lastEvent;
        public int attempts;
        public Instant lastAttemptAt;
        public Instant nextAttemptAt;
        public Integer lastHttpStatus;
        public String lastError;
        /** Set once the first {@code deferred} event was sent, so it isn't sent again. */
        public boolean deferredNotified;
    }

    /** Summary of one received bounce (PLAN.md §6a). */
    public static final class BounceRecord {
        public Instant receivedAt;
        /** {@code smtp} or {@code api}. */
        public String source;
        public int recipientIndex;
        public String recipient;
        /** DSN {@code Action}: {@code failed}, {@code delayed}, ... */
        public String action;
        public String status;
        public String diagnostic;
        /** DSN {@code Message-ID} or content hash, for duplicate detection. */
        public String dedupeKey;
        /** Path of the stored raw bounce, if any. */
        public String file;
    }

    public Job() {
    }

    /** Creates a new job for a validated request; one {@link RecipientResult} per envelope recipient. */
    public static Job create(SendRequest request, String payloadHash, Instant now, JobStatus initialStatus) {
        Job job = new Job();
        job.id = request.id;
        job.status = initialStatus;
        job.payloadHash = payloadHash;
        job.createdAt = now;
        job.updatedAt = now;
        job.request = request;
        List<String> rcpts = request.envelopeRecipients();
        for (int i = 0; i < rcpts.size(); i++) {
            job.recipients.add(new RecipientResult(rcpts.get(i), i));
        }
        if (request.callbackUrl != null && !request.callbackUrl.isBlank()) {
            job.callback = new CallbackState();
            job.callback.url = request.callbackUrl.trim();
        }
        return job;
    }

    public RecipientResult recipient(int index) {
        return index >= 0 && index < recipients.size() ? recipients.get(index) : null;
    }

    /** Recipients that still need a delivery attempt (not final). */
    public List<RecipientResult> unfinishedRecipients() {
        List<RecipientResult> out = new ArrayList<>();
        for (RecipientResult r : recipients) {
            if (!r.status.isFinal()) out.add(r);
        }
        return out;
    }

    /**
     * Recomputes {@link #status} from the recipients (see {@link JobStatus#aggregate}) and touches
     * {@link #updatedAt}. While recipients are still pending or sending the status is left alone.
     *
     * @return the new status
     */
    public JobStatus recomputeStatus(Instant now) {
        List<RecipientResult.Status> statuses = new ArrayList<>(recipients.size());
        for (RecipientResult r : recipients) statuses.add(r.status);
        JobStatus derived = JobStatus.aggregate(statuses);
        if (derived != null) status = derived;
        updatedAt = now;
        return status;
    }

    /** Fails the whole job (e.g. {@code ATTACHMENT_FETCH_FAILED}): every unfinished recipient becomes failed. */
    public void failJob(Instant now, String error, String message) {
        this.error = error;
        this.errorMessage = message;
        for (RecipientResult r : recipients) {
            if (!r.status.isFinal()) r.markFailed(now, null, null, message, error);
        }
        status = JobStatus.FAILED;
        updatedAt = now;
    }
}
