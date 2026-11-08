package io.siggi.simplemailer.delivery;

import io.siggi.simplemailer.config.Config;
import io.siggi.simplemailer.model.Job;
import io.siggi.simplemailer.model.RecipientResult;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.ScheduledThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.function.Predicate;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Retries deferred deliveries (PLAN.md §5).
 *
 * <p>As a {@link DeliveryEngine.RetryPolicy} it picks the backoff: the {@code n}-th failed attempt waits
 * {@code retrySchedule[n-1]} (the last entry repeats, e.g. 1m, 5m, 15m, 1h, 2h, 4h, 4h, …). Retries stop at
 * {@code maxRetryDuration} after the recipient's first attempt: an attempt that would land later is moved to that
 * deadline, so there is always one final try at the deadline, and a failure at or after it gives up (the engine then
 * fails the recipient with {@code RETRIES_EXHAUSTED}).
 *
 * <p>As a scheduler it re-submits jobs: hand it every finished delivery run ({@link #onRunFinished}, wired to
 * {@link DeliveryEngine.Options#onRunFinished}) or a loaded job ({@link #schedule}), and it keeps one timer per job
 * that fires at the earliest {@code nextAttemptAt} of its deferred recipients. A job with nothing deferred has its
 * timer cancelled. If the submitter refuses the job (a run is still in progress) the timer tries again shortly.
 */
public final class RetryScheduler implements DeliveryEngine.RetryPolicy, AutoCloseable {
    private static final Logger LOG = Logger.getLogger(RetryScheduler.class.getName());
    /** Delay used when {@code retrySchedule} is empty. */
    static final Duration DEFAULT_DELAY = Duration.ofMinutes(5);
    /** How long to wait before re-trying a submission the engine refused because the job was busy. */
    static final Duration BUSY_RETRY = Duration.ofSeconds(1);

    private final List<Duration> schedule;
    private final Duration maxRetryDuration;
    private final Predicate<Job> submitter;
    private final ScheduledExecutorService timer;
    private final Map<String, Pending> pending = new ConcurrentHashMap<>();
    private final Duration busyRetry;

    private record Pending(Instant at, ScheduledFuture<?> future) {
    }

    /**
     * @param submitter starts a delivery run for the job; returns {@code false} if it could not (already running),
     *                  e.g. {@link DeliveryEngine#submit}
     */
    public RetryScheduler(Config config, Predicate<Job> submitter) {
        this(config.retrySchedule, config.maxRetryDuration, submitter, BUSY_RETRY);
    }

    RetryScheduler(List<Duration> schedule, Duration maxRetryDuration, Predicate<Job> submitter, Duration busyRetry) {
        this.schedule = schedule == null ? List.of() : List.copyOf(schedule);
        this.maxRetryDuration = maxRetryDuration;
        this.submitter = submitter;
        this.busyRetry = busyRetry;
        ScheduledThreadPoolExecutor t = new ScheduledThreadPoolExecutor(1, r -> {
            Thread th = new Thread(r, "retry-scheduler");
            th.setDaemon(true);
            return th;
        });
        t.setRemoveOnCancelPolicy(true);
        t.setExecuteExistingDelayedTasksAfterShutdownPolicy(false);
        this.timer = t;
    }

    // ---- backoff --------------------------------------------------------------------------------------------

    /** The wait after the given number of failed attempts (1-based). */
    public Duration delayAfter(int attempts) {
        return delayAfter(schedule, attempts);
    }

    private static Duration delayAfter(List<Duration> schedule, int attempts) {
        if (schedule == null || schedule.isEmpty()) return DEFAULT_DELAY;
        return schedule.get(Math.min(Math.max(attempts - 1, 0), schedule.size() - 1));
    }

    @Override
    public Instant nextAttempt(RecipientResult recipient, Instant now) {
        return nextAttempt(schedule, maxRetryDuration, recipient, now);
    }

    /** The backoff alone, without a scheduler (what {@link DeliveryEngine} uses when no policy is given). */
    public static DeliveryEngine.RetryPolicy backoff(Config config) {
        List<Duration> schedule = config.retrySchedule == null ? List.of() : List.copyOf(config.retrySchedule);
        Duration max = config.maxRetryDuration;
        return (r, now) -> nextAttempt(schedule, max, r, now);
    }

    private static Instant nextAttempt(List<Duration> schedule, Duration maxRetryDuration, RecipientResult recipient,
                                       Instant now) {
        Instant next = now.plus(delayAfter(schedule, recipient.attempts));
        if (maxRetryDuration == null) return next;
        Instant first = recipient.firstAttemptAt != null ? recipient.firstAttemptAt : now;
        Instant deadline = first.plus(maxRetryDuration);
        if (!now.isBefore(deadline)) return null;
        return next.isAfter(deadline) ? deadline : next;
    }

    // ---- scheduling -----------------------------------------------------------------------------------------

    /** Schedules (or cancels) the job's next run after a delivery run finished. */
    public void onRunFinished(Job job) {
        schedule(job);
    }

    /**
     * Arms the job's timer for the earliest {@code nextAttemptAt} of its deferred recipients (immediately if one is
     * already due), replacing an earlier timer; cancels it if nothing is deferred.
     */
    public void schedule(Job job) {
        Instant earliest = earliestRetry(job);
        if (earliest == null) {
            cancel(job.id);
            return;
        }
        arm(job, earliest);
    }

    /** The earliest retry time of the job's deferred recipients, or {@code null} if none is deferred. */
    static Instant earliestRetry(Job job) {
        if (job.status == null || !job.status.needsDelivery()) return null;
        Instant earliest = null;
        for (RecipientResult r : job.recipients) {
            if (r.status != RecipientResult.Status.DEFERRED) continue;
            Instant at = r.nextAttemptAt != null ? r.nextAttemptAt : Instant.EPOCH;
            if (earliest == null || at.isBefore(earliest)) earliest = at;
        }
        return earliest;
    }

    private void arm(Job job, Instant at) {
        pending.compute(job.id, (k, old) -> {
            if (old != null) {
                if (old.at.equals(at) && !old.future.isDone()) return old;
                old.future.cancel(false);
            }
            return newTimer(job, at, delayUntil(at));
        });
    }

    private static long delayUntil(Instant at) {
        // +1ms: never fire before nextAttemptAt (the engine only attempts recipients that are due)
        return Math.max(0, Duration.between(Instant.now(), at).toMillis() + 1);
    }

    private Pending newTimer(Job job, Instant at, long delayMs) {
        try {
            return new Pending(at, timer.schedule(() -> fire(job, at), delayMs, TimeUnit.MILLISECONDS));
        } catch (RejectedExecutionException e) {
            return null; // shut down
        }
    }

    private void fire(Job job, Instant at) {
        if (Instant.now().isBefore(at)) {
            // woke up early (clock adjustment): wait for the rest unless a newer timer replaced this one
            pending.computeIfPresent(job.id, (k, p) -> p.at.equals(at) ? newTimer(job, at, delayUntil(at)) : p);
            return;
        }
        // drop this timer first, so the run's onRunFinished can arm the next one
        boolean[] current = {false};
        pending.computeIfPresent(job.id, (k, p) -> {
            if (!p.at.equals(at)) return p;
            current[0] = true;
            return null;
        });
        if (!current[0]) return;
        boolean started;
        try {
            started = submitter.test(job);
        } catch (RuntimeException e) {
            LOG.log(Level.WARNING, "could not start retry of job " + job.id, e);
            started = false;
        }
        if (started) return; // the run's onRunFinished re-arms the timer if recipients are still deferred
        // busy (a run is in progress) or failed: try again shortly unless a newer timer was armed meanwhile
        pending.computeIfAbsent(job.id, k -> newTimer(job, at, busyRetry.toMillis()));
    }

    /** Cancels the job's timer, if any. */
    public void cancel(String id) {
        Pending p = pending.remove(id);
        if (p != null) p.future.cancel(false);
    }

    /** When the job's next retry run is scheduled, or {@code null} if none is. */
    public Instant scheduledAt(String id) {
        Pending p = pending.get(id);
        return p == null ? null : p.at;
    }

    /** Number of jobs with a retry timer (for tests and monitoring). */
    public int scheduledCount() {
        return pending.size();
    }

    @Override
    public void close() {
        timer.shutdownNow();
        pending.clear();
    }
}
