package io.siggi.simplemailer.model;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.regex.Pattern;

/**
 * Body of {@code POST /v1/messages} (PLAN.md §3, §3a). Field names match the JSON.
 *
 * <p>Either structured ({@code subject}/{@code text}/{@code html}, envelope = {@code to ∪ cc ∪ bcc}) or {@code raw}
 * (envelope = {@code recipients}). {@link #validate()} checks the rules that don't need configuration or uploaded
 * files; size limits and {@code cid:} matching are checked where that information is available.
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
                if (cid != null && !cid.isBlank() && !cids.add(cid)) {
                    errors.add(where + ": duplicate inline cid '" + cid + "'");
                }
            }
        }
    }
}
