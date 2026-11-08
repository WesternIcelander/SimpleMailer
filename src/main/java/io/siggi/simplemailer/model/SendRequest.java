package io.siggi.simplemailer.model;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Body of {@code POST /v1/messages} (PLAN.md §3, §3a). Field names match the JSON.
 *
 * <p>Either structured ({@code subject}/{@code text}/{@code html}, envelope = {@code to ∪ cc ∪ bcc}) or {@code raw}
 * (envelope = {@code recipients}). {@link #validate()} checks the rules that don't need configuration or uploaded
 * files, including that every {@code cid:} URL in {@code html} names an inline attachment; size limits and upload
 * matching are checked where that information is available.
 */
public final class SendRequest {
    public String id;
    public String from;
    public List<String> to;
    public List<String> cc;
    public List<String> bcc;
    public String subject;
    public String text;
    public String html;
    public Map<String, String> headers;
    public String raw;
    /** Envelope recipients for {@code raw} messages. */
    public List<String> recipients;
    public boolean requireTls;
    public boolean verifyCertificate;
    public String callbackUrl;
    public List<Attachment> attachments;

    /** One attachment; exactly one of {@link #part}, {@link #content}, {@link #url} is set (PLAN.md §3a). */
    public static final class Attachment {
        /** Name of the {@code multipart/form-data} file part holding the data. */
        public String part;
        /** Base64 data (JSON requests). */
        public String content;
        /** URL fetched after the POST returns. */
        public String url;
        public String filename;
        public String contentType;
        public boolean inline;
        /** Explicit Content-ID for inline parts; defaults to {@link #filename}. */
        public String cid;

        /** The Content-ID used for {@code cid:} references (only meaningful when {@link #inline}). */
        public String effectiveCid() {
            return cid != null && !cid.isBlank() ? cid : filename;
        }
    }

    // Deliberately simple syntax check: local@domain, no whitespace/angle brackets, domain with a dot or an
    // address literal. Full RFC 5321 parsing isn't needed: the receiving MX is the final judge.
    private static final Pattern ADDRESS = Pattern.compile(
            "^[^\\s@<>()\\[\\],;:\".]+(?:\\.[^\\s@<>()\\[\\],;:\".]+)*@"
                    + "(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+"
                    + "|\\[[0-9A-Fa-f:.]+])$");
    private static final Pattern UUID_PATTERN = Pattern.compile(
            "^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$");
    /**
     * A {@code cid:} URL used as an attribute value ({@code src="cid:…"}, {@code href=cid:…}) or a CSS
     * {@code url(cid:…)}. Group 1 is the (still percent-encoded) Content-ID. Plain text that merely mentions
     * "cid:" is not matched.
     */
    private static final Pattern CID_REFERENCE = Pattern.compile(
            "(?:=\\s*[\"']?|url\\(\\s*[\"']?)cid:([^\"'\\s<>)]*)", Pattern.CASE_INSENSITIVE);
    private static final Pattern HEADER_NAME = Pattern.compile("^[!-9;-~]+$");
    /** Headers the server writes itself; callers can't override them through {@code headers}. */
    private static final Set<String> RESERVED_HEADERS = Set.of(
            "from", "to", "cc", "bcc", "subject", "date", "message-id", "mime-version",
            "content-type", "content-transfer-encoding", "dkim-signature", "return-path");

    public boolean isRaw() {
        return raw != null;
    }

    public boolean isStructured() {
        return subject != null || text != null || html != null;
    }

    /** True for a syntactically valid email address (see {@link #ADDRESS}). */
    public static boolean isValidAddress(String address) {
        return address != null && address.length() <= 254 && ADDRESS.matcher(address).matches()
                && address.indexOf('@') <= 64;
    }

    /** True for the canonical 8-4-4-4-12 hex UUID form. */
    public static boolean isValidUuid(String id) {
        if (id == null || !UUID_PATTERN.matcher(id).matches()) return false;
        try {
            UUID.fromString(id);
            return true;
        } catch (IllegalArgumentException e) {
            return false;
        }
    }

    /** Lower-cased domain part of an address (text after the last {@code @}). */
    public static String domainOf(String address) {
        int at = address.lastIndexOf('@');
        return (at < 0 ? address : address.substring(at + 1)).toLowerCase(Locale.ROOT);
    }

    /**
     * Envelope recipients: {@code to ∪ cc ∪ bcc} for structured messages, {@code recipients} for raw ones. Order is
     * preserved and duplicates (compared case-insensitively) are dropped, so the list index is a stable recipient
     * index for the job.
     */
    public List<String> envelopeRecipients() {
        Map<String, String> seen = new LinkedHashMap<>();
        if (isRaw()) {
            addAll(seen, recipients);
        } else {
            addAll(seen, to);
            addAll(seen, cc);
            addAll(seen, bcc);
        }
        return new ArrayList<>(seen.values());
    }

    private static void addAll(Map<String, String> seen, List<String> addresses) {
        if (addresses == null) return;
        for (String a : addresses) {
            if (a == null) continue;
            String trimmed = a.trim();
            seen.putIfAbsent(trimmed.toLowerCase(Locale.ROOT), trimmed);
        }
    }

    /** Returns validation errors (empty if valid). */
    public List<String> validate() {
        List<String> errors = new ArrayList<>();
        if (id == null || id.isBlank()) {
            errors.add("id is required");
        } else if (!isValidUuid(id)) {
            errors.add("id must be a UUID");
        }

        boolean structured = isStructured();
        if (isRaw() && structured) {
            errors.add("use either raw or subject/text/html, not both");
        } else if (!isRaw() && !structured) {
            errors.add("one of raw or subject/text/html is required");
        }

        if (isRaw()) {
            if (raw.isEmpty()) errors.add("raw must not be empty");
            if (hasEntries(to) || hasEntries(cc) || hasEntries(bcc)) {
                errors.add("to/cc/bcc are not used with raw; list envelope recipients in recipients");
            }
            if (headers != null && !headers.isEmpty()) errors.add("headers are not used with raw");
            if (attachments != null && !attachments.isEmpty()) errors.add("attachments are not used with raw");
            checkAddresses(errors, "recipients", recipients);
        } else {
            if (hasEntries(recipients)) errors.add("recipients is only used with raw; use to/cc/bcc");
            checkAddresses(errors, "to", to);
            checkAddresses(errors, "cc", cc);
            checkAddresses(errors, "bcc", bcc);
            checkHeaders(errors);
            checkAttachments(errors);
            checkCidReferences(errors);
        }

        if (from == null || from.isBlank()) {
            errors.add("from is required");
        } else if (!isValidAddress(from.trim())) {
            errors.add("from is not a valid address");
        }
        if (envelopeRecipients().isEmpty()) {
            errors.add(isRaw() ? "recipients must list at least one address" : "at least one of to/cc/bcc is required");
        }
        if (callbackUrl != null && !callbackUrl.isBlank()) {
            String lower = callbackUrl.trim().toLowerCase(Locale.ROOT);
            if (!lower.startsWith("https://") && !lower.startsWith("http://")) {
                errors.add("callbackUrl must be an http or https URL");
            }
        }
        return errors;
    }

    private static boolean hasEntries(List<String> list) {
        return list != null && !list.isEmpty();
    }

    private static void checkAddresses(List<String> errors, String field, List<String> addresses) {
        if (addresses == null) return;
        for (String a : addresses) {
            if (a == null || !isValidAddress(a.trim())) {
                errors.add(field + ": invalid address '" + a + "'");
            }
        }
    }

    private void checkHeaders(List<String> errors) {
        if (headers == null) return;
        headers.forEach((name, value) -> {
            if (name == null || !HEADER_NAME.matcher(name).matches()) {
                errors.add("headers: invalid header name '" + name + "'");
                return;
            }
            if (RESERVED_HEADERS.contains(name.toLowerCase(Locale.ROOT))) {
                errors.add("headers: " + name + " can't be set through headers");
            }
            if (value == null || value.indexOf('\r') >= 0 || value.indexOf('\n') >= 0) {
                errors.add("headers: value of " + name + " must be a single line");
            }
        });
    }

    private void checkAttachments(List<String> errors) {
        if (attachments == null) return;
        Set<String> cids = new LinkedHashSet<>();
        for (int i = 0; i < attachments.size(); i++) {
            Attachment a = attachments.get(i);
            String where = "attachments[" + i + "]";
            if (a == null) {
                errors.add(where + " is null");
                continue;
            }
            int sources = (a.part != null ? 1 : 0) + (a.content != null ? 1 : 0) + (a.url != null ? 1 : 0);
            if (sources != 1) errors.add(where + ": exactly one of part, content or url is required");
            if (a.filename == null || a.filename.isBlank()) errors.add(where + ": filename is required");
            if (a.inline) {
                String cid = a.effectiveCid();
                if (cid != null && !cid.isBlank()) {
                    if (!isValidCid(cid)) {
                        errors.add(where + ": cid '" + cid + "' must not contain '<', '>' or control characters");
                    } else if (!cids.add(cid)) {
                        errors.add(where + ": duplicate inline cid '" + cid + "'");
                    }
                }
            }
        }
    }

    /**
     * Checks that every {@code cid:} URL in {@link #html} names an inline attachment (PLAN.md §3a). A {@code cid:}
     * URL is the percent-encoded Content-ID (RFC 2392), so it is decoded before comparing; an undecoded exact match
     * is accepted too.
     */
    private void checkCidReferences(List<String> errors) {
        if (html == null) return;
        Set<String> cids = new LinkedHashSet<>();
        if (attachments != null) {
            for (Attachment a : attachments) {
                if (a == null || !a.inline) continue;
                String cid = a.effectiveCid();
                if (cid != null && !cid.isBlank()) cids.add(cid.trim());
            }
        }
        Set<String> reported = new LinkedHashSet<>();
        for (String ref : cidReferences(html)) {
            String decoded = percentDecode(ref);
            if (cids.contains(ref) || (decoded != null && cids.contains(decoded))) continue;
            if (reported.add(ref)) {
                errors.add("html: cid:" + ref + " does not match any inline attachment");
            }
        }
    }

    /** The Content-IDs referenced by {@code cid:} URLs in an HTML body, as written (not percent-decoded). */
    public static List<String> cidReferences(String html) {
        List<String> refs = new ArrayList<>();
        Matcher m = CID_REFERENCE.matcher(html);
        while (m.find()) refs.add(m.group(1));
        return refs;
    }

    private static boolean isValidCid(String cid) {
        for (int i = 0; i < cid.length(); i++) {
            char c = cid.charAt(i);
            if (c < 0x20 || c == 0x7f || c == '<' || c == '>') return false;
        }
        return true;
    }

    /** Decodes {@code %XX} escapes as UTF-8; {@code null} if the escapes are malformed. */
    private static String percentDecode(String s) {
        if (s.indexOf('%') < 0) return s;
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int i = 0;
        while (i < s.length()) {
            if (s.charAt(i) == '%') {
                if (i + 2 >= s.length()) return null;
                int hi = Character.digit(s.charAt(i + 1), 16);
                int lo = Character.digit(s.charAt(i + 2), 16);
                if (hi < 0 || lo < 0) return null;
                out.write((hi << 4) | lo);
                i += 3;
            } else {
                int end = s.indexOf('%', i);
                if (end < 0) end = s.length();
                out.writeBytes(s.substring(i, end).getBytes(StandardCharsets.UTF_8));
                i = end;
            }
        }
        return out.toString(StandardCharsets.UTF_8);
    }
}
