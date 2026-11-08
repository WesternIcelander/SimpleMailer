package io.siggi.simplemailer.delivery;

import io.siggi.simplemailer.smtp.MxResolver;
import io.siggi.simplemailer.smtp.SmtpResponse;

/**
 * Classifies the outcome of an SMTP exchange for a recipient (PLAN.md §5): 2xx is success, 5xx is a permanent
 * failure, and 4xx, network errors and temporary DNS failures are transient (the recipient is deferred and retried).
 *
 * <p>Where a reply arrives matters:
 * <ul>
 *   <li>{@link Phase#RCPT} and {@link Phase#MAIL} / {@link Phase#DATA} replies decide the recipients they concern.</li>
 *   <li>{@link Phase#SESSION} replies (greeting, {@code EHLO}, {@code RSET}) concern the mail exchanger rather than a
 *       recipient: even a 5xx only means "try the next MX". It becomes final only if every mail exchanger
 *       answered that way (see {@code DeliveryEngine}).</li>
 *   <li>{@code 552} to {@code RCPT} is treated as {@code 452} (RFC 5321 §4.5.3.1.10: servers have used it for
 *       "too many recipients"), so it is transient.</li>
 *   <li>A reply outside 2xx/4xx/5xx where a final answer was expected (e.g. a 3xx to {@code RCPT}) is a protocol
 *       error and transient.</li>
 * </ul>
 */
public final class ResultClassifier {
    private ResultClassifier() {
    }

    /** Which command a reply answers. */
    public enum Phase {
        /** Greeting, {@code EHLO}/{@code HELO}, {@code RSET}: about the server, not a recipient. */
        SESSION,
        MAIL,
        RCPT,
        DATA
    }

    public enum Kind {
        /** 2xx: accepted. */
        SUCCESS,
        /** Retry later (4xx, network, temporary DNS). */
        TRANSIENT,
        /** Don't retry (5xx, no mail host). */
        PERMANENT
    }

    /**
     * @param kind    the class of the outcome
     * @param error   a machine-readable error code for failures (one of the {@code DeliveryEngine} constants), or
     *                {@code null} on success
     * @param decides true if this is the answer for the recipient now; false if the next mail exchanger should be
     *                tried (a session-level 5xx is only final once every mail exchanger has answered that way)
     */
    public record Classification(Kind kind, String error, boolean decides) {
        public boolean isSuccess() {
            return kind == Kind.SUCCESS;
        }

        public boolean isPermanent() {
            return kind == Kind.PERMANENT;
        }

        public boolean isTransient() {
            return kind == Kind.TRANSIENT;
        }
    }

    private static final Classification SUCCESS = new Classification(Kind.SUCCESS, null, true);

    /** Classifies an SMTP reply to a command of the given phase. */
    public static Classification classify(SmtpResponse reply, Phase phase) {
        int cls = reply.code() / 100;
        if (phase == Phase.SESSION) {
            if (cls == 2) return SUCCESS;
            if (cls == 5) return new Classification(Kind.PERMANENT, DeliveryEngine.SMTP_PERMANENT_FAILURE, false);
            if (cls == 4) return new Classification(Kind.TRANSIENT, DeliveryEngine.SMTP_TEMPORARY_FAILURE, false);
            return new Classification(Kind.TRANSIENT, DeliveryEngine.SMTP_PROTOCOL_ERROR, false);
        }
        if (cls == 2) return SUCCESS;
        if (phase == Phase.RCPT && reply.code() == 552) {
            return new Classification(Kind.TRANSIENT, DeliveryEngine.SMTP_TEMPORARY_FAILURE, false);
        }
        if (cls == 5) return new Classification(Kind.PERMANENT, DeliveryEngine.SMTP_PERMANENT_FAILURE, true);
        if (cls == 4) return new Classification(Kind.TRANSIENT, DeliveryEngine.SMTP_TEMPORARY_FAILURE, false);
        return new Classification(Kind.TRANSIENT, DeliveryEngine.SMTP_PROTOCOL_ERROR, false);
    }

    /** A network failure (connect, timeout, reset, malformed reply): transient, try the next mail exchanger. */
    public static Classification network() {
        return new Classification(Kind.TRANSIENT, DeliveryEngine.CONNECTION_FAILED, false);
    }

    /** A DNS failure for the recipient domain: NXDOMAIN / no host / null MX are permanent, SERVFAIL is transient. */
    public static Classification dns(MxResolver.MxException e) {
        return e.isPermanent()
                ? new Classification(Kind.PERMANENT, DeliveryEngine.NO_MAIL_HOST, true)
                : new Classification(Kind.TRANSIENT, DeliveryEngine.DNS_TEMPORARY_FAILURE, true);
    }
}
