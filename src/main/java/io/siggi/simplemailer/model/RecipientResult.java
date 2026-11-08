package io.siggi.simplemailer.model;

import com.google.gson.annotations.SerializedName;

import java.time.Instant;

/**
 * Delivery state of one envelope recipient (PLAN.md §3 status JSON, §5, §6a).
 */
public final class RecipientResult {
    public enum Status {
        /** Not attempted yet. */
        @SerializedName("pending") PENDING,
        /** An attempt is in progress. */
        @SerializedName("sending") SENDING,
        /** Temporary failure; another attempt is scheduled at {@link #nextAttemptAt}. */
        @SerializedName("deferred") DEFERRED,
        @SerializedName("delivered") DELIVERED,
        /** Permanent failure (5xx, retries exhausted, TLS policy, ...). */
        @SerializedName("failed") FAILED,
        /** A bounce arrived for this recipient, possibly after it was {@code delivered}. */
        @SerializedName("bounced") BOUNCED;

        /** True once no more delivery attempts will be made. */
        public boolean isFinal() {
            return this == DELIVERED || this == FAILED || this == BOUNCED;
        }
    }

    /** Envelope recipient address. */
    public String address;
    /** Index of this recipient in the job; part of the VERP bounce address (PLAN.md §6a). */
    public int index;
    public Status status = Status.PENDING;

    /** MX host used for the last attempt. */
    public String mx;
    public Integer smtpCode;
    /** RFC 3463 enhanced status code of the last reply (e.g. {@code 5.1.1}), if the server sent one. */
    public String enhancedStatus;
    public String smtpMessage;
    /** Machine-readable error such as {@code TLS_REQUIRED_NOT_AVAILABLE} or {@code TLS_CERT_INVALID}. */
    public String error;
    /** Whether the last attempt used TLS (null if no connection was made). */
    public Boolean tls;
    public int attempts;

    public Instant firstAttemptAt;
    public Instant lastAttemptAt;
    public Instant nextAttemptAt;
    public Instant deliveredAt;
    public Instant failedAt;

    /** DSN details when {@link Status#BOUNCED}. */
    public Instant bouncedAt;
    public String dsnStatus;
    public String dsnDiagnostic;

    public RecipientResult() {
    }

    public RecipientResult(String address, int index) {
        this.address = address;
        this.index = index;
    }

    /** Records the start of a delivery attempt. */
    public void beginAttempt(Instant now) {
        status = Status.SENDING;
        attempts++;
        if (firstAttemptAt == null) firstAttemptAt = now;
        lastAttemptAt = now;
        nextAttemptAt = null;
    }

    public void markDelivered(Instant now, String mx, int smtpCode, String smtpMessage, boolean tls) {
        this.status = Status.DELIVERED;
        this.mx = mx;
        this.smtpCode = smtpCode;
        this.smtpMessage = smtpMessage;
        this.tls = tls;
        this.error = null;
        this.deliveredAt = now;
        this.nextAttemptAt = null;
    }

    public void markDeferred(Instant nextAttemptAt, String mx, Integer smtpCode, String smtpMessage, String error) {
        this.status = Status.DEFERRED;
        this.mx = mx;
        this.smtpCode = smtpCode;
        this.smtpMessage = smtpMessage;
        this.error = error;
        this.nextAttemptAt = nextAttemptAt;
    }

    public void markFailed(Instant now, String mx, Integer smtpCode, String smtpMessage, String error) {
        this.status = Status.FAILED;
        this.mx = mx;
        this.smtpCode = smtpCode;
        this.smtpMessage = smtpMessage;
        this.error = error;
        this.failedAt = now;
        this.nextAttemptAt = null;
    }

    public void markBounced(Instant now, String dsnStatus, String dsnDiagnostic) {
        this.status = Status.BOUNCED;
        this.bouncedAt = now;
        this.dsnStatus = dsnStatus;
        this.dsnDiagnostic = dsnDiagnostic;
        this.nextAttemptAt = null;
    }

    /** Domain part of {@link #address}, lower-cased; used to group recipients per delivery task. */
    public String domain() {
        return SendRequest.domainOf(address);
    }
}
