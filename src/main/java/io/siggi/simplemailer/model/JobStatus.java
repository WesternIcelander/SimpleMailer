package io.siggi.simplemailer.model;

import com.google.gson.annotations.SerializedName;

import java.util.Collection;

/**
 * Overall job status as reported by {@code GET /v1/messages/{id}} (PLAN.md §3).
 */
public enum JobStatus {
    /** URL attachments are still being fetched; nothing has been queued for delivery yet. */
    @SerializedName("preparing") PREPARING("preparing"),
    @SerializedName("queued") QUEUED("queued"),
    @SerializedName("sending") SENDING("sending"),
    @SerializedName("delivered") DELIVERED("delivered"),
    @SerializedName("partially_failed") PARTIALLY_FAILED("partially_failed"),
    @SerializedName("failed") FAILED("failed"),
    @SerializedName("deferred") DEFERRED("deferred"),
    @SerializedName("bounced") BOUNCED("bounced");

    private final String wireName;

    JobStatus(String wireName) {
        this.wireName = wireName;
    }

    /** The lower-case name used in JSON. */
    public String wireName() {
        return wireName;
    }

    /**
     * True for states where delivery is over: {@code delivered}, {@code partially_failed}, {@code failed},
     * {@code bounced}. A terminal job can still change later when a bounce arrives.
     */
    public boolean isTerminal() {
        return this == DELIVERED || this == PARTIALLY_FAILED || this == FAILED || this == BOUNCED;
    }

    /** True if the job still has delivery work to do (re-enqueued on startup, PLAN.md §4). */
    public boolean needsDelivery() {
        return this == QUEUED || this == SENDING || this == DEFERRED;
    }

    public static JobStatus fromWireName(String name) {
        for (JobStatus s : values()) {
            if (s.wireName.equals(name)) return s;
        }
        throw new IllegalArgumentException("unknown job status: " + name);
    }

    /**
     * Derives the overall status from the recipient statuses, or returns null if some recipient is still
     * {@code pending}/{@code sending} (the job's lifecycle state then stays as the delivery engine set it).
     *
     * <ul>
     *     <li>any {@code deferred} (and none pending) → {@code deferred}</li>
     *     <li>all {@code delivered} → {@code delivered}</li>
     *     <li>all {@code failed} → {@code failed}</li>
     *     <li>none delivered, at least one {@code bounced} → {@code bounced}</li>
     *     <li>otherwise (a mix of delivered and failed/bounced) → {@code partially_failed}</li>
     * </ul>
     */
    public static JobStatus aggregate(Collection<RecipientResult.Status> statuses) {
        if (statuses.isEmpty()) return null;
        int delivered = 0, failed = 0, bounced = 0, deferred = 0;
        for (RecipientResult.Status s : statuses) {
            switch (s) {
                case PENDING, SENDING -> {
                    return null;
                }
                case DELIVERED -> delivered++;
                case FAILED -> failed++;
                case BOUNCED -> bounced++;
                case DEFERRED -> deferred++;
            }
        }
        if (deferred > 0) return DEFERRED;
        int total = statuses.size();
        if (delivered == total) return DELIVERED;
        if (failed == total) return FAILED;
        if (delivered == 0 && bounced > 0) return BOUNCED;
        return PARTIALLY_FAILED;
    }
}
