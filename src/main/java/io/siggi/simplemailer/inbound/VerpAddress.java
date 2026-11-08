package io.siggi.simplemailer.inbound;

import io.siggi.simplemailer.config.Config;
import io.siggi.simplemailer.delivery.DeliveryEngine;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.HexFormat;
import java.util.Locale;
import java.util.Objects;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * HMAC-tagged VERP bounce addresses (PLAN.md §6a).
 *
 * <p>Each recipient of a job gets its own envelope sender
 * {@code bounce+{uuid}.{rcptIdx}.{tag}@{bounceDomain}}, where {@code uuid} is the job id written as 32 hex digits
 * (the dashes are dropped so the local part stays within the 64-octet limit of RFC 5321 §4.5.3.1.1),
 * {@code rcptIdx} is the recipient's index in the job, and {@code tag} is the first 64 bits (16 hex digits) of
 * HMAC-SHA256 over {@code "{uuid}.{rcptIdx}"} (canonical, lower-case, dashed uuid) keyed with
 * {@code bounces.secret}. A bounce addressed to anything else, or with a tag that doesn't verify, is rejected.
 *
 * <p>Parsing is case-insensitive (some mail systems change the case of local parts), and the canonical form of
 * every component is required, so each job/recipient pair has exactly one valid address.
 *
 * <p>Immutable and thread safe.
 */
public final class VerpAddress {
    /** The fixed local-part prefix before the {@code +}. */
    public static final String PREFIX = "bounce";
    /** Hex digits of the truncated HMAC in the address. */
    public static final int TAG_HEX_LENGTH = 16;
    /** Largest recipient index; 7 digits keep the local part at most 64 octets. */
    public static final int MAX_RECIPIENT_INDEX = 9_999_999;

    private static final Pattern LOCAL_PART = Pattern.compile(
            "^" + PREFIX + "\\+([0-9a-f]{32})\\.(0|[1-9][0-9]{0,6})\\.([0-9a-f]{" + TAG_HEX_LENGTH + "})$");
    private static final String HMAC = "HmacSHA256";
    private static final HexFormat HEX = HexFormat.of();

    /** A syntactically valid bounce address: the job and recipient it names, and its (unverified) tag. */
    public record Decoded(String jobId, int recipientIndex, String tag) {
    }

    /** Outcome of {@link #verify}. */
    public enum Status {
        /** The address names a job and recipient and its tag is correct. */
        VALID,
        /** Not a {@code bounce+…@bounceDomain} address (wrong domain, prefix or syntax). */
        NOT_BOUNCE_ADDRESS,
        /** Looks like a bounce address, but the tag doesn't match (forged or altered). */
        BAD_TAG
    }

    /** Result of {@link #verify}; {@code address} is set only when {@code status} is {@link Status#VALID}. */
    public record Verification(Status status, Decoded address) {
        public boolean valid() {
            return status == Status.VALID;
        }
    }

    private final String domain;
    private final byte[] secret;

    /**
     * @param domain the bounce domain ({@code bounces.domain})
     * @param secret the HMAC key ({@code bounces.secret}), UTF-8 encoded
     */
    public VerpAddress(String domain, String secret) {
        Objects.requireNonNull(domain, "domain");
        Objects.requireNonNull(secret, "secret");
        String d = domain.trim().toLowerCase(Locale.ROOT);
        while (d.endsWith(".")) d = d.substring(0, d.length() - 1);
        if (d.isEmpty()) throw new IllegalArgumentException("bounce domain is empty");
        if (secret.isEmpty()) throw new IllegalArgumentException("bounce secret is empty");
        this.domain = d;
        this.secret = secret.getBytes(StandardCharsets.UTF_8);
        mac(); // fail fast if HmacSHA256 is unavailable
    }

    /**
     * The VERP encoder for this configuration, or {@code null} when {@code bounces.domain} or
     * {@code bounces.secret} isn't set (then MAIL FROM falls back to the caller's {@code from} address).
     */
    public static VerpAddress fromConfig(Config config) {
        Config.Bounces b = config.bounces;
        if (b == null || b.domain == null || b.domain.isBlank() || b.secret == null || b.secret.isEmpty()) {
            return null;
        }
        return new VerpAddress(b.domain, b.secret);
    }

    public String domain() {
        return domain;
    }

    /** The bounce address for recipient {@code recipientIndex} of job {@code jobId} (a UUID). */
    public String encode(String jobId, int recipientIndex) {
        String uuid = canonicalUuid(jobId);
        if (uuid == null) throw new IllegalArgumentException("job id is not a UUID: " + jobId);
        if (recipientIndex < 0 || recipientIndex > MAX_RECIPIENT_INDEX) {
            throw new IllegalArgumentException("recipient index out of range: " + recipientIndex);
        }
        return PREFIX + "+" + uuid.replace("-", "") + "." + recipientIndex + "." + tag(uuid, recipientIndex)
                + "@" + domain;
    }

    /**
     * Parses and verifies {@code address} (optionally in angle brackets, as in an SMTP {@code RCPT TO}).
     * The domain must be the bounce domain and the tag must match; comparison of the tag is constant time.
     */
    public Verification verify(String address) {
        Decoded decoded = decode(address);
        if (decoded == null) return new Verification(Status.NOT_BOUNCE_ADDRESS, null);
        byte[] expected = tag(decoded.jobId, decoded.recipientIndex).getBytes(StandardCharsets.US_ASCII);
        byte[] actual = decoded.tag.getBytes(StandardCharsets.US_ASCII);
        if (!MessageDigest.isEqual(expected, actual)) return new Verification(Status.BAD_TAG, null);
        return new Verification(Status.VALID, decoded);
    }

    /** Parses a bounce address for this domain without checking the tag; {@code null} if it isn't one. */
    public Decoded decode(String address) {
        if (address == null) return null;
        String a = address.trim();
        if (a.startsWith("<") && a.endsWith(">")) a = a.substring(1, a.length() - 1).trim();
        int at = a.lastIndexOf('@');
        if (at <= 0) return null;
        String addrDomain = a.substring(at + 1).toLowerCase(Locale.ROOT);
        if (addrDomain.endsWith(".")) addrDomain = addrDomain.substring(0, addrDomain.length() - 1);
        if (!addrDomain.equals(domain)) return null;
        Matcher m = LOCAL_PART.matcher(a.substring(0, at).toLowerCase(Locale.ROOT));
        if (!m.matches()) return null;
        String hex = m.group(1);
        String uuid = hex.substring(0, 8) + "-" + hex.substring(8, 12) + "-" + hex.substring(12, 16) + "-"
                + hex.substring(16, 20) + "-" + hex.substring(20);
        int index;
        try {
            index = Integer.parseInt(m.group(2));
        } catch (NumberFormatException e) {
            return null;
        }
        return new Decoded(uuid, index, m.group(3));
    }

    /**
     * A {@link DeliveryEngine.EnvelopeSender} that uses this recipient's bounce address as {@code MAIL FROM}.
     */
    public DeliveryEngine.EnvelopeSender envelopeSender() {
        return (job, recipient) -> encode(job.id, recipient.index);
    }

    private String tag(String canonicalUuid, int recipientIndex) {
        Mac mac = mac();
        byte[] h = mac.doFinal((canonicalUuid + "." + recipientIndex).getBytes(StandardCharsets.US_ASCII));
        return HEX.formatHex(h, 0, TAG_HEX_LENGTH / 2);
    }

    private Mac mac() {
        try {
            Mac mac = Mac.getInstance(HMAC);
            mac.init(new SecretKeySpec(secret, HMAC));
            return mac;
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("HmacSHA256 unavailable", e);
        }
    }

    /** Lower-case dashed UUID, or {@code null} if {@code id} isn't the 8-4-4-4-12 hex form. */
    private static String canonicalUuid(String id) {
        if (id == null) return null;
        String lower = id.trim().toLowerCase(Locale.ROOT);
        return lower.matches("[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}") ? lower : null;
    }
}
