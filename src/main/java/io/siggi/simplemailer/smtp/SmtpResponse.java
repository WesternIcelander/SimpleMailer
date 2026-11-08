package io.siggi.simplemailer.smtp;

import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * One SMTP reply (RFC 5321 §4.2): a three-digit code and one or more text lines (the code and separator stripped).
 *
 * @param code  the reply code, 200..599
 * @param lines the text of each reply line, without the code and the {@code -}/space separator; never empty
 */
public record SmtpResponse(int code, List<String> lines) {
    private static final Pattern ENHANCED_STATUS = Pattern.compile("^([245])\\.(\\d{1,3})\\.(\\d{1,3})(?=\\s|$)");

    public SmtpResponse {
        if (code < 200 || code > 599) throw new IllegalArgumentException("bad SMTP reply code: " + code);
        lines = List.copyOf(lines);
        if (lines.isEmpty()) lines = List.of("");
    }

    public SmtpResponse(int code, String line) {
        this(code, List.of(line));
    }

    /** 2xx: the command succeeded. */
    public boolean isPositive() {
        return code / 100 == 2;
    }

    /** 3xx: the server is waiting for more input (e.g. {@code 354} after {@code DATA}). */
    public boolean isIntermediate() {
        return code / 100 == 3;
    }

    /** 4xx: temporary failure; the delivery may be retried later. */
    public boolean isTransientFailure() {
        return code / 100 == 4;
    }

    /** 5xx: permanent failure. */
    public boolean isPermanentFailure() {
        return code / 100 == 5;
    }

    /** All text lines joined with a space. */
    public String message() {
        return String.join(" ", lines);
    }

    /**
     * The RFC 3463 enhanced status code at the start of the first line (e.g. {@code 5.1.1}), or {@code null} if the
     * server didn't send one, or if its class doesn't match the reply code's.
     */
    public String enhancedStatus() {
        Matcher m = ENHANCED_STATUS.matcher(lines.get(0));
        if (!m.find()) return null;
        if (m.group(1).charAt(0) - '0' != code / 100) return null;
        return m.group(1) + "." + m.group(2) + "." + m.group(3);
    }

    /** The reply as it would appear on a single line, e.g. {@code 250 2.1.0 OK}. */
    @Override
    public String toString() {
        return code + " " + message();
    }
}
