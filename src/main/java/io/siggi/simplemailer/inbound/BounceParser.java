package io.siggi.simplemailer.inbound;

import io.siggi.simplemailer.mime.HeaderParams;
import io.siggi.tools.Digests;
import io.siggi.tools.Hex;
import io.siggi.tools.io.IO;
import io.siggi.tools.io.LineReader;
import io.siggi.tools.io.mimeheader.MimeHeader;
import io.siggi.tools.io.mimeheader.MimeHeaderParser;
import io.siggi.tools.io.multipart.MultipartParser;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Classifies and parses a message received at a bounce address (PLAN.md §6a).
 *
 * <ul>
 *   <li>An RFC 3464 delivery status notification ({@code multipart/report; report-type=delivery-status}, also
 *       found when nested inside another multipart, and the RFC 6533 {@code message/global-delivery-status}
 *       variant) is {@link Kind#DSN}: its per-recipient {@code Final-Recipient}, {@code Original-Recipient},
 *       {@code Action}, {@code Status}, {@code Diagnostic-Code} and {@code Remote-MTA} fields are returned.</li>
 *   <li>Without a DSN, an auto-reply ({@code Auto-Submitted: auto-replied}, or the common {@code X-Autoreply},
 *       {@code X-Autorespond} and {@code Precedence: auto_reply} markers) is {@link Kind#AUTO_REPLY}, to be logged
 *       and ignored.</li>
 *   <li>Otherwise a message that looks like a bounce (null reverse path {@code MAIL FROM:<>}, or a
 *       {@code Return-Path: <>} header when the envelope isn't known, or sent by {@code MAILER-DAEMON}) is
 *       {@link Kind#NON_DSN_BOUNCE}: a single synthetic recipient with action {@code failed}, without a final
 *       recipient (the caller uses the VERP-identified one), and with any SMTP reply found in the text as
 *       diagnostic.</li>
 *   <li>Anything else is {@link Kind#NOT_BOUNCE}.</li>
 * </ul>
 *
 * <p>The parser does no I/O beyond the given bytes and never throws on malformed input; the caller bounds the
 * message size. Bare LF line endings are accepted. Thread safe (stateless).
 */
public final class BounceParser {
    /** Upper bound for a header block (the message's, a MIME part's, or a DSN field group). */
    private static final int MAX_HEADER_BYTES = 256 * 1024;
    /** Longest physical line accepted in a header block. */
    private static final int MAX_LINE = 16 * 1024;
    /** How deep nested multiparts are searched for a delivery report. */
    private static final int MAX_DEPTH = 5;
    /** How much of a non-DSN bounce's text is scanned for an SMTP reply. */
    private static final int MAX_SCAN_BYTES = 64 * 1024;
    /** Longest diagnostic kept. */
    private static final int MAX_DIAGNOSTIC = 1000;

    /** An SMTP reply with an enhanced status code, e.g. {@code 550 5.1.1 <a@x.com>: user unknown}. */
    private static final Pattern SMTP_REPLY = Pattern.compile(
            "(?m)\\b([45][0-9][0-9])[ -]([45]\\.[0-9]{1,3}\\.[0-9]{1,3})\\b[^\\r\\n]*");
    private static final Pattern STATUS = Pattern.compile("[245]\\.[0-9]{1,3}\\.[0-9]{1,3}");

    private BounceParser() {
    }

    /** What kind of message this is. */
    public enum Kind {
        /** An RFC 3464 delivery status notification. */
        DSN,
        /** No DSN, but sent with a null reverse path (or by a mailer daemon): treated as a failure. */
        NON_DSN_BOUNCE,
        /** An auto-reply (vacation message etc.) without a DSN; ignored. */
        AUTO_REPLY,
        /** Neither a DSN nor anything that looks like a bounce; ignored. */
        NOT_BOUNCE
    }

    /**
     * One recipient's delivery status.
     *
     * @param finalRecipient    the address from {@code Final-Recipient} (address type removed), or null
     * @param originalRecipient the address from {@code Original-Recipient}, or null
     * @param action            lower-case {@code Action} ({@code failed}, {@code delayed}, {@code delivered},
     *                          {@code relayed}, {@code expanded}), or null if missing
     * @param status            the RFC 3463 status code, e.g. {@code 5.1.1}, or null
     * @param diagnosticCode    {@code Diagnostic-Code} without its type, unfolded, e.g.
     *                          {@code 550 5.1.1 user unknown}, or null
     * @param remoteMta         {@code Remote-MTA} without its type, or null
     */
    public record Recipient(String finalRecipient, String originalRecipient, String action, String status,
                            String diagnosticCode, String remoteMta) {
        public boolean failed() {
            return "failed".equals(action);
        }

        public boolean delayed() {
            return "delayed".equals(action);
        }
    }

    /**
     * The parse result.
     *
     * @param kind              the classification
     * @param recipients        per-recipient statuses: the DSN's recipient groups for {@link Kind#DSN}, one synthetic
     *                          failed recipient for {@link Kind#NON_DSN_BOUNCE}, otherwise empty
     * @param reportingMta      {@code Reporting-MTA} without its type (DSN only), or null
     * @param messageId         the bounce's own {@code Message-ID} (with angle brackets), or null
     * @param originalMessageId the {@code Message-ID} of the returned original message, if included, or null
     * @param subject           the bounce's {@code Subject}, unfolded, or null
     * @param contentHash       lower-case hex SHA-256 of the raw bytes as given, for de-duplication
     */
    public record Result(Kind kind, List<Recipient> recipients, String reportingMta, String messageId,
                         String originalMessageId, String subject, String contentHash) {
        public Result {
            recipients = List.copyOf(recipients);
        }

        /** True for {@link Kind#DSN} and {@link Kind#NON_DSN_BOUNCE}. */
        public boolean isBounce() {
            return kind == Kind.DSN || kind == Kind.NON_DSN_BOUNCE;
        }
    }

    /**
     * Parses {@code raw}, a complete RFC 5322 message.
     *
     * @param raw            the message bytes
     * @param envelopeSender the SMTP {@code MAIL FROM} path it arrived with ({@code ""} or {@code "<>"} for the null
     *                       reverse path), or null when unknown (API intake); then {@code Return-Path} is consulted
     */
    public static Result parse(byte[] raw, String envelopeSender) {
        String hash = Hex.toHex(Digests.sha256().digest(raw)).toLowerCase(Locale.ROOT);
        // The terminating blank line makes sure the last header is kept when a message has no body
        byte[] msg = withTerminator(toCrlf(stripMboxFromLine(raw)));

        ByteArrayInputStream in = new ByteArrayInputStream(msg);
        List<MimeHeader> headers = readHeaders(in);
        byte[] body = in.readAllBytes();

        String messageId = trimToNull(header(headers, "Message-ID"));
        String subject = trimToNull(header(headers, "Subject"));

        Report report = new Report();
        findReport(headers, body, 0, report);
        if (report.found && !report.recipients.isEmpty()) {
            return new Result(Kind.DSN, report.recipients, report.reportingMta, messageId, report.originalMessageId,
                    subject, hash);
        }

        if (isAutoReply(headers)) {
            return new Result(Kind.AUTO_REPLY, List.of(), null, messageId, null, subject, hash);
        }

        if (looksLikeBounce(headers, envelopeSender)) {
            String diagnostic = null;
            String status = null;
            String text = new String(body, 0, Math.min(body.length, MAX_SCAN_BYTES), StandardCharsets.ISO_8859_1);
            Matcher m = SMTP_REPLY.matcher(text);
            if (m.find()) {
                diagnostic = limit(m.group().trim());
                status = m.group(2);
            }
            if (diagnostic == null) diagnostic = subject == null ? null : limit(subject);
            Recipient r = new Recipient(null, null, "failed", status, diagnostic, null);
            return new Result(Kind.NON_DSN_BOUNCE, List.of(r), null, messageId, null, subject, hash);
        }
        return new Result(Kind.NOT_BOUNCE, List.of(), null, messageId, null, subject, hash);
    }

    // ---- classification ----

    private static boolean isAutoReply(List<MimeHeader> headers) {
        String autoSubmitted = header(headers, "Auto-Submitted");
        if (autoSubmitted != null
                && HeaderParams.parse(autoSubmitted).lowerValue().equals("auto-replied")) {
            return true;
        }
        if (header(headers, "X-Autoreply") != null || header(headers, "X-Autorespond") != null) return true;
        String precedence = header(headers, "Precedence");
        return precedence != null && precedence.trim().toLowerCase(Locale.ROOT).equals("auto_reply");
    }

    private static boolean looksLikeBounce(List<MimeHeader> headers, String envelopeSender) {
        if (envelopeSender != null) {
            if (isNullPath(envelopeSender)) return true;
        } else {
            String returnPath = header(headers, "Return-Path");
            if (returnPath != null && isNullPath(returnPath)) return true;
        }
        String from = header(headers, "From");
        if (from == null) return false;
        String f = from.toLowerCase(Locale.ROOT);
        return f.contains("mailer-daemon@") || f.contains("<mailer-daemon>") || f.trim().equals("mailer-daemon");
    }

    private static boolean isNullPath(String path) {
        String p = path.trim();
        return p.isEmpty() || p.replaceAll("\\s+", "").equals("<>");
    }

    // ---- DSN ----

    private static final class Report {
        boolean found;
        String reportingMta;
        String originalMessageId;
        final List<Recipient> recipients = new ArrayList<>();
    }

    /** Looks for a delivery report in an entity with the given headers and (encoded) body. */
    private static void findReport(List<MimeHeader> headers, byte[] body, int depth, Report report) {
        if (report.found || depth > MAX_DEPTH) return;
        HeaderParams contentType = HeaderParams.parse(header(headers, "Content-Type"));
        String type = contentType.lowerValue();
        if (!type.startsWith("multipart/")) return;
        String boundary = contentType.get("boundary");
        if (boundary == null || boundary.isEmpty()) return;
        boolean isReport = type.equals("multipart/report");

        List<Part> parts = parts(body, boundary);
        if (isReport) {
            for (Part part : parts) {
                String partType = HeaderParams.parse(header(part.headers, "Content-Type")).lowerValue();
                if (partType.equals("message/delivery-status") || partType.equals("message/global-delivery-status")) {
                    report.found = true;
                    parseDeliveryStatus(decode(part.headers, part.body), report);
                } else if (partType.equals("message/rfc822") || partType.equals("text/rfc822-headers")
                        || partType.equals("message/global") || partType.equals("message/global-headers")) {
                    if (report.originalMessageId == null) {
                        List<MimeHeader> original = readHeaders(new ByteArrayInputStream(
                                withTerminator(toCrlf(decode(part.headers, part.body)))));
                        report.originalMessageId = trimToNull(header(original, "Message-ID"));
                    }
                }
            }
            if (report.found) return;
        }
        for (Part part : parts) {
            findReport(part.headers, part.body, depth + 1, report);
            if (report.found) return;
        }
    }

    /** Parses a {@code message/delivery-status} body: a per-message field group, then per-recipient groups. */
    private static void parseDeliveryStatus(byte[] body, Report report) {
        LineReader reader = new LineReader(new ByteArrayInputStream(withTerminator(toCrlf(body))), false,
                MAX_LINE);
        MimeHeaderParser parser = headerParser();
        boolean first = true;
        while (true) {
            List<MimeHeader> group;
            try {
                group = parser.read(reader);
            } catch (IOException | RuntimeException e) {
                return; // malformed: keep what was parsed so far
            }
            if (group == null) return;
            if (group.isEmpty()) continue; // extra blank line between groups
            if (first) {
                first = false;
                report.reportingMta = typedValue(header(group, "Reporting-MTA"));
                // Some MTAs put recipient fields in the first group; treat it as a recipient group too
                if (header(group, "Final-Recipient") == null && header(group, "Action") == null) continue;
            }
            String action = trimToNull(header(group, "Action"));
            if (action != null) action = HeaderParams.parse(action).lowerValue();
            String status = null;
            String rawStatus = header(group, "Status");
            if (rawStatus != null) {
                Matcher m = STATUS.matcher(rawStatus);
                if (m.find()) status = m.group();
            }
            String finalRecipient = address(typedValue(header(group, "Final-Recipient")));
            String originalRecipient = address(typedValue(header(group, "Original-Recipient")));
            if (finalRecipient == null && originalRecipient == null && action == null) continue;
            String diagnostic = typedValue(header(group, "Diagnostic-Code"));
            report.recipients.add(new Recipient(finalRecipient, originalRecipient, action, status,
                    diagnostic == null ? null : limit(diagnostic), typedValue(header(group, "Remote-MTA"))));
        }
    }

    /** {@code rfc822; a@x.com} → {@code a@x.com}; a value without a type is returned as is. Unfolded, trimmed. */
    private static String typedValue(String value) {
        if (value == null) return null;
        String v = value;
        int semi = v.indexOf(';');
        if (semi >= 0 && v.substring(0, semi).trim().matches("[A-Za-z0-9.+-]+")) v = v.substring(semi + 1);
        return trimToNull(v.replaceAll("\\s+", " "));
    }

    /** Strips angle brackets from an address, as some MTAs write {@code rfc822; <a@x.com>}. */
    private static String address(String value) {
        if (value == null) return null;
        String v = value.trim();
        if (v.startsWith("<") && v.endsWith(">")) v = v.substring(1, v.length() - 1).trim();
        return v.isEmpty() ? null : v;
    }

    // ---- MIME helpers ----

    private record Part(List<MimeHeader> headers, byte[] body) {
    }

    /** Splits a multipart body into parts; a malformed body yields the parts read so far. */
    private static List<Part> parts(byte[] body, String boundary) {
        List<Part> parts = new ArrayList<>();
        try {
            MultipartParser parser = new MultipartParser(new ByteArrayInputStream(body), boundary, MAX_HEADER_BYTES);
            MultipartParser.Part part;
            while ((part = parser.nextPart()) != null) {
                byte[] data = IO.readFully(part.getInputStream());
                parts.add(new Part(part.getHeaders(), data));
            }
        } catch (IOException | RuntimeException e) {
            // keep what we have
        }
        return parts;
    }

    /** Reads a header block from {@code in}, leaving it positioned at the body. Malformed → what was read. */
    private static List<MimeHeader> readHeaders(InputStream in) {
        LineReader reader = new LineReader(in, false, MAX_LINE);
        List<MimeHeader> headers = new ArrayList<>();
        try {
            headerParser().read(reader, headers);
        } catch (IOException | RuntimeException e) {
            // lenient: use the headers parsed before the error
        }
        return Collections.unmodifiableList(headers);
    }

    private static MimeHeaderParser headerParser() {
        return new MimeHeaderParser().setAllowFoldedLines(true).setMaxTotalHeaderSize(MAX_HEADER_BYTES);
    }

    /** First header value by case-insensitive name, unfolded, or null. */
    private static String header(List<MimeHeader> headers, String name) {
        MimeHeader h = MimeHeader.getFirst(headers, name);
        return h == null ? null : h.getValue().replaceAll("\\r?\\n", "");
    }

    /** Undoes base64 or quoted-printable {@code Content-Transfer-Encoding}; other encodings are returned as is. */
    private static byte[] decode(List<MimeHeader> headers, byte[] body) {
        String cte = header(headers, "Content-Transfer-Encoding");
        if (cte == null) return body;
        String enc = cte.trim().toLowerCase(Locale.ROOT);
        if (enc.equals("base64")) {
            try {
                return Base64.getMimeDecoder().decode(body);
            } catch (IllegalArgumentException e) {
                return body;
            }
        }
        if (enc.equals("quoted-printable")) return decodeQuotedPrintable(body);
        return body;
    }

    static byte[] decodeQuotedPrintable(byte[] in) {
        ByteArrayOutputStream out = new ByteArrayOutputStream(in.length);
        for (int i = 0; i < in.length; i++) {
            byte b = in[i];
            if (b != '=') {
                out.write(b);
                continue;
            }
            if (i + 2 < in.length && in[i + 1] == '\r' && in[i + 2] == '\n') {
                i += 2; // soft line break
            } else if (i + 1 < in.length && in[i + 1] == '\n') {
                i += 1;
            } else if (i + 2 < in.length && hex(in[i + 1]) >= 0 && hex(in[i + 2]) >= 0) {
                out.write(hex(in[i + 1]) * 16 + hex(in[i + 2]));
                i += 2;
            } else {
                out.write(b);
            }
        }
        return out.toByteArray();
    }

    private static int hex(byte c) {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    }

    /** Converts bare LF (and bare CR) line endings to CRLF, as {@link MultipartParser} expects CRLF. */
    static byte[] toCrlf(byte[] in) {
        ByteArrayOutputStream out = null;
        for (int i = 0; i < in.length; i++) {
            byte b = in[i];
            boolean bareLf = b == '\n' && (i == 0 || in[i - 1] != '\r');
            boolean bareCr = b == '\r' && (i + 1 >= in.length || in[i + 1] != '\n');
            if ((bareLf || bareCr) && out == null) {
                out = new ByteArrayOutputStream(in.length + in.length / 32 + 16);
                out.write(in, 0, i);
            }
            if (out == null) continue;
            if (bareLf || bareCr) {
                out.write('\r');
                out.write('\n');
            } else {
                out.write(b);
            }
        }
        return out == null ? in : out.toByteArray();
    }

    /**
     * Appends a blank line. {@link MimeHeaderParser} drops a header that is still pending at end of input, so a
     * header block that isn't followed by a blank line (the last DSN field group, a headers-only part) needs one.
     */
    private static byte[] withTerminator(byte[] in) {
        byte[] out = new byte[in.length + 4];
        System.arraycopy(in, 0, out, 0, in.length);
        out[in.length] = '\r';
        out[in.length + 1] = '\n';
        out[in.length + 2] = '\r';
        out[in.length + 3] = '\n';
        return out;
    }

    /** Drops a leading mbox {@code From } separator line, which some pipes prepend. */
    private static byte[] stripMboxFromLine(byte[] in) {
        if (in.length < 5 || in[0] != 'F' || in[1] != 'r' || in[2] != 'o' || in[3] != 'm' || in[4] != ' ') return in;
        for (int i = 5; i < in.length; i++) {
            if (in[i] == '\n') {
                byte[] out = new byte[in.length - i - 1];
                System.arraycopy(in, i + 1, out, 0, out.length);
                return out;
            }
        }
        return in;
    }

    private static String trimToNull(String s) {
        if (s == null) return null;
        String t = s.trim();
        return t.isEmpty() ? null : t;
    }

    private static String limit(String s) {
        return s.length() <= MAX_DIAGNOSTIC ? s : s.substring(0, MAX_DIAGNOSTIC);
    }
}
