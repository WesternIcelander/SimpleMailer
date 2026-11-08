package io.siggi.simplemailer.mime;

import io.siggi.simplemailer.config.Config;
import io.siggi.simplemailer.model.Job;
import io.siggi.simplemailer.model.JobStatus;
import io.siggi.simplemailer.model.SendRequest;
import io.siggi.simplemailer.store.JobStore;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executor;
import java.util.function.Consumer;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Runs the {@code preparing} job state (PLAN.md §3a): fetches a job's URL attachments after the POST has returned,
 * builds the message, and moves the job to {@code queued}.
 *
 * <p>Each URL attachment is downloaded once to {@code payloads/{uuid}/{index}}; an attachment whose file already
 * exists (e.g. after a restart) is not fetched again. A missing {@code contentType} is filled in from the response
 * {@code Content-Type} and saved in the job right away. Each file is limited to {@code maxAttachmentBytes} and all
 * attachments together to {@code maxMessageBytes}.
 *
 * <p>Any failure fails the whole job with {@link #ATTACHMENT_FETCH_FAILED}; nothing is sent. Jobs that leave this
 * state are handed to {@code onQueued} or {@code onFailed} (the delivery engine and the callback dispatcher).
 */
public final class JobPreparer {
    public static final String ATTACHMENT_FETCH_FAILED = "ATTACHMENT_FETCH_FAILED";
    private static final Logger LOG = Logger.getLogger(JobPreparer.class.getName());

    private final Config config;
    private final JobStore store;
    private final AttachmentFetcher fetcher;
    private final Executor executor;
    private final Consumer<Job> onQueued;
    private final Consumer<Job> onFailed;
    private final Set<String> running = ConcurrentHashMap.newKeySet();

    public JobPreparer(Config config, JobStore store, AttachmentFetcher fetcher, Executor executor,
                       Consumer<Job> onQueued, Consumer<Job> onFailed) {
        this.config = config;
        this.store = store;
        this.fetcher = fetcher;
        this.executor = executor;
        this.onQueued = onQueued;
        this.onFailed = onFailed;
    }

    /** Prepares the job in the background; ignored if it is already being prepared. */
    public void submit(Job job) {
        String id = job.id;
        if (!running.add(id)) return;
        try {
            executor.execute(() -> {
                try {
                    prepare(id);
                } finally {
                    running.remove(id);
                }
            });
        } catch (RuntimeException e) {
            running.remove(id);
            throw e;
        }
    }

    /** Submits every stored job still in {@code preparing} (startup recovery). */
    public void resumeAll() throws IOException {
        for (String id : store.listIds()) {
            try {
                Optional<Job> job = store.get(id);
                if (job.isPresent() && job.get().status == JobStatus.PREPARING) submit(job.get());
            } catch (IOException e) {
                LOG.log(Level.WARNING, "could not read job " + id, e);
            }
        }
    }

    /**
     * Prepares one job synchronously: fetch, build, mark {@code queued}. Does nothing unless the job is
     * {@code preparing}.
     *
     * @return the job's resulting state, or empty if it doesn't exist
     */
    public Optional<Job> prepare(String id) {
        try {
            Optional<Job> loaded = store.get(id);
            if (loaded.isEmpty() || loaded.get().status != JobStatus.PREPARING) return loaded;
            Job job = loaded.get();
            SendRequest send = job.request;
            try {
                fetchAll(job);
            } catch (AttachmentFetcher.FetchException e) {
                return fail(id, ATTACHMENT_FETCH_FAILED, e.getMessage());
            }
            // re-read: fetchAll saved filled-in content types
            send = store.get(id).map(j -> j.request).orElse(send);
            MessagePayload.buildMessage(store, send, config.heloName);
            Optional<Job> queued = store.update(id, j -> {
                if (j.status == JobStatus.PREPARING) j.status = JobStatus.QUEUED;
            });
            if (queued.isPresent() && queued.get().status == JobStatus.QUEUED) onQueued.accept(queued.get());
            return queued;
        } catch (IOException | RuntimeException e) {
            LOG.log(Level.WARNING, "preparing job " + id + " failed", e);
            try {
                return fail(id, ATTACHMENT_FETCH_FAILED, "could not prepare the message: "
                        + (e.getMessage() != null ? e.getMessage() : e.getClass().getSimpleName()));
            } catch (IOException e2) {
                LOG.log(Level.SEVERE, "could not mark job " + id + " failed", e2);
                return Optional.empty();
            }
        }
    }

    private void fetchAll(Job job) throws IOException {
        SendRequest send = job.request;
        if (send.attachments == null) return;
        long total = 0;
        // stored (uploaded, base64 or already fetched) attachments count towards the total first
        for (int i = 0; i < send.attachments.size(); i++) {
            Path file = MessagePayload.attachmentFile(store, job.id, i);
            if (Files.exists(file)) total += Files.size(file);
        }
        for (int i = 0; i < send.attachments.size(); i++) {
            SendRequest.Attachment a = send.attachments.get(i);
            if (a == null || a.url == null) continue;
            Path file = MessagePayload.attachmentFile(store, job.id, i);
            if (Files.exists(file)) continue;
            String where = "attachments[" + i + "]";
            long cap = Math.min(config.maxAttachmentBytes, config.maxMessageBytes - total);
            if (cap <= 0) {
                throw new AttachmentFetcher.FetchException(where + ": attachments exceed " + config.maxMessageBytes
                        + " bytes in total");
            }
            AttachmentFetcher.Result result;
            try {
                result = fetcher.fetch(a.url, file, cap);
            } catch (AttachmentFetcher.FetchException e) {
                String msg = e.getMessage();
                if (cap < config.maxAttachmentBytes && msg != null && msg.contains("larger than")) {
                    msg += " (total attachment limit " + config.maxMessageBytes + " bytes)";
                }
                throw new AttachmentFetcher.FetchException(where + ": " + msg, e);
            }
            total += result.size();
            if ((a.contentType == null || a.contentType.isBlank()) && result.contentType() != null) {
                final int index = i;
                store.update(job.id, j -> {
                    SendRequest.Attachment stored = j.request.attachments.get(index);
                    if (stored.contentType == null || stored.contentType.isBlank()) {
                        stored.contentType = result.contentType();
                    }
                });
            }
        }
    }

    private Optional<Job> fail(String id, String error, String message) throws IOException {
        Optional<Job> failed = store.update(id, j -> {
            if (j.status == JobStatus.PREPARING) j.failJob(Instant.now(), error, message);
        });
        if (failed.isPresent() && failed.get().status == JobStatus.FAILED) onFailed.accept(failed.get());
        return failed;
    }
}
