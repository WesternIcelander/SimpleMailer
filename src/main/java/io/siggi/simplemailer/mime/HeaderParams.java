package io.siggi.simplemailer.mime;

import java.io.ByteArrayOutputStream;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.TreeMap;

/**
 * Parser and formatter for structured MIME header values with parameters, such as
 * {@code Content-Type: multipart/report; report-type=delivery-status; boundary="a+b"} (RFC 2045 §5.1).
 *
 * <p>Unlike SiggiTools' {@code MimeHeaderMap}, values are never URL-decoded: quoted strings are unquoted (with
 * backslash escapes), tokens are kept verbatim, and RFC 822 comments are skipped. RFC 2231 extended parameters
 * ({@code name*=charset'lang'%XX..} and continuations {@code name*0}, {@code name*1*}, ...) are decoded.
 * Parameter names are case-insensitive. Parsing is lenient: malformed input never throws.
 */
public final class HeaderParams {
    /** RFC 2045 tspecials. A parameter value containing any of these (or space/CTL) must be quoted. */
    private static final String TSPECIALS = "()<>@,;:\\\"/[]?=";

    private final String value;
    private final Map<String, String> params;

    private HeaderParams(String value, Map<String, String> params) {
        this.value = value;
        this.params = Collections.unmodifiableMap(params);
    }

    /** The main value before the first {@code ;}, trimmed, e.g. {@code multipart/report}. Never null. */
    public String value() {
        return value;
    }

    /** The main value lowercased, convenient for media-type comparisons. */
    public String lowerValue() {
        return value.toLowerCase(Locale.ROOT);
    }

    /** A parameter by case-insensitive name, or null. */
    public String get(String name) {
        return params.get(name);
    }

    /** All parameters, keyed case-insensitively, lowercase names. */
    public Map<String, String> params() {
        return params;
    }

    /** Parses a header value. A null input is treated as empty. */
    public static HeaderParams parse(String header) {
        if (header == null) header = "";
        Parser p = new Parser(header);
        String value = p.readMainValue();
        // name (lowercase, without '*' suffixes) -> pieces
        Map<String, String> plain = new LinkedHashMap<>();
        Map<String, Map<Integer, Piece>> continued = new LinkedHashMap<>();
        Map<String, Piece> extended = new LinkedHashMap<>();
        while (p.skipToParam()) {
            String rawName = p.readName();
            if (rawName.isEmpty()) {
                p.skipBadParam();
                continue;
            }
            p.skipCfws();
            if (!p.consume('=')) {
                p.skipBadParam();
                continue;
            }
            p.skipCfws();
            String v = p.readParamValue();
            String name = rawName.toLowerCase(Locale.ROOT);
            boolean ext = name.endsWith("*");
            if (ext) name = name.substring(0, name.length() - 1);
            int star = name.indexOf('*');
            if (star >= 0) {
                String base = name.substring(0, star);
                String idx = name.substring(star + 1);
                int n;
                try {
                    n = Integer.parseInt(idx);
                } catch (NumberFormatException e) {
                    continue;
                }
                if (n < 0 || (idx.length() > 1 && idx.charAt(0) == '0')) continue;
                continued.computeIfAbsent(base, k -> new TreeMap<>()).putIfAbsent(n, new Piece(v, ext));
            } else if (ext) {
                extended.putIfAbsent(name, new Piece(v, true));
            } else {
                plain.putIfAbsent(name, v);
            }
        }

        Map<String, String> result = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
        for (Map.Entry<String, String> e : plain.entrySet()) {
            result.put(e.getKey(), e.getValue());
        }
        for (Map.Entry<String, Map<Integer, Piece>> e : continued.entrySet()) {
            String decoded = joinContinuations(e.getValue());
            if (decoded != null) result.put(e.getKey(), decoded);
        }
        for (Map.Entry<String, Piece> e : extended.entrySet()) {
            String decoded = decodeExtended(e.getValue().text);
            if (decoded != null) result.put(e.getKey(), decoded);
        }
        return new HeaderParams(value, result);
    }

    private record Piece(String text, boolean extended) {
    }

    /** Joins RFC 2231 continuations {@code name*0..name*N}, stopping at the first gap. */
    private static String joinContinuations(Map<Integer, Piece> pieces) {
        Charset charset = null;
        ByteArrayOutputStream pending = new ByteArrayOutputStream();
        StringBuilder sb = new StringBuilder();
        int expected = 0;
        for (Map.Entry<Integer, Piece> e : pieces.entrySet()) {
            if (e.getKey() != expected) break;
            Piece piece = e.getValue();
            String text = piece.text;
            if (expected == 0 && piece.extended) {
                int q1 = text.indexOf('\'');
                int q2 = q1 < 0 ? -1 : text.indexOf('\'', q1 + 1);
                if (q2 < 0) return null;
                charset = charsetOrDefault(text.substring(0, q1));
                text = text.substring(q2 + 1);
            }
            if (piece.extended) {
                // Percent-decoded bytes may be split across segments, so keep accumulating them.
                percentDecode(text, pending);
            } else {
                flush(pending, charset, sb);
                sb.append(text);
            }
            expected++;
        }
        if (expected == 0) return null;
        flush(pending, charset, sb);
        return sb.toString();
    }

    private static void flush(ByteArrayOutputStream pending, Charset charset, StringBuilder sb) {
        if (pending.size() == 0) return;
        sb.append(pending.toString(charset == null ? StandardCharsets.US_ASCII : charset));
        pending.reset();
    }

    /** Decodes {@code charset'lang'%XX...}. Returns null if the charset/language prefix is missing. */
    private static String decodeExtended(String text) {
        int q1 = text.indexOf('\'');
        int q2 = q1 < 0 ? -1 : text.indexOf('\'', q1 + 1);
        if (q2 < 0) return null;
        Charset charset = charsetOrDefault(text.substring(0, q1));
        text = text.substring(q2 + 1);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        percentDecode(text, out);
        return out.toString(charset);
    }

    private static Charset charsetOrDefault(String name) {
        if (name.isEmpty()) return StandardCharsets.US_ASCII;
        try {
            return Charset.forName(name);
        } catch (RuntimeException e) {
            return StandardCharsets.UTF_8;
        }
    }

    private static void percentDecode(String text, ByteArrayOutputStream out) {
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            if (c == '%' && i + 2 < text.length() && hex(text.charAt(i + 1)) >= 0 && hex(text.charAt(i + 2)) >= 0) {
                out.write(hex(text.charAt(i + 1)) * 16 + hex(text.charAt(i + 2)));
                i += 2;
            } else {
                int cp = text.codePointAt(i);
                byte[] b = new String(Character.toChars(cp)).getBytes(StandardCharsets.UTF_8);
                out.write(b, 0, b.length);
                i += Character.charCount(cp) - 1;
            }
        }
    }

    private static int hex(char c) {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    }

    // ---- formatting ----

    /** True if {@code s} is a non-empty RFC 2045 token (printable US-ASCII, no space, no tspecials). */
    public static boolean isToken(String s) {
        if (s == null || s.isEmpty()) return false;
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c <= 32 || c >= 127 || TSPECIALS.indexOf(c) >= 0) return false;
        }
        return true;
    }

    /**
     * Formats a parameter value: as-is if it is a token, otherwise as a quoted string. CR and LF are dropped,
     * since they can't appear in a quoted string. Non-ASCII values need RFC 2231 encoding, done by the caller.
     */
    public static String quote(String s) {
        if (isToken(s)) return s;
        StringBuilder sb = new StringBuilder(s.length() + 2).append('"');
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == '\r' || c == '\n') continue;
            if (c == '"' || c == '\\') sb.append('\\');
            sb.append(c);
        }
        return sb.append('"').toString();
    }

    /** Formats {@code value; name=param; ...}, quoting parameter values as needed. */
    public static String format(String value, Map<String, String> params) {
        StringBuilder sb = new StringBuilder(value);
        for (Map.Entry<String, String> e : params.entrySet()) {
            sb.append("; ").append(e.getKey()).append('=').append(quote(e.getValue()));
        }
        return sb.toString();
    }

    @Override
    public String toString() {
        return format(value, params);
    }

    // ---- tokenizer ----

    private static final class Parser {
        private final String s;
        private int pos;

        Parser(String s) {
            this.s = s;
        }

        boolean atEnd() {
            return pos >= s.length();
        }

        boolean consume(char c) {
            if (!atEnd() && s.charAt(pos) == c) {
                pos++;
                return true;
            }
            return false;
        }

        /** Main value: everything up to the first ';' outside quotes, with comments removed. */
        String readMainValue() {
            StringBuilder sb = new StringBuilder();
            while (!atEnd()) {
                char c = s.charAt(pos);
                if (c == ';') break;
                if (c == '(') {
                    skipComment();
                    continue;
                }
                if (c == '"') {
                    sb.append(readQuoted());
                    continue;
                }
                sb.append(c);
                pos++;
            }
            return sb.toString().trim();
        }

        /** Advances past the next ';' (and whitespace/comments). False when there are no more parameters. */
        boolean skipToParam() {
            while (!atEnd()) {
                skipCfws();
                if (consume(';')) {
                    skipCfws();
                    if (!atEnd() && s.charAt(pos) != ';') return true;
                } else if (!atEnd()) {
                    // Stray characters: skip to the next ';'.
                    skipBadParam();
                }
            }
            return false;
        }

        void skipBadParam() {
            while (!atEnd() && s.charAt(pos) != ';') {
                char c = s.charAt(pos);
                if (c == '"') readQuoted();
                else if (c == '(') skipComment();
                else pos++;
            }
        }

        String readName() {
            int start = pos;
            while (!atEnd()) {
                char c = s.charAt(pos);
                if (c <= 32 || c >= 127 || (TSPECIALS.indexOf(c) >= 0)) break;
                pos++;
            }
            return s.substring(start, pos);
        }

        String readParamValue() {
            if (!atEnd() && s.charAt(pos) == '"') {
                String v = readQuoted();
                skipCfws();
                return v;
            }
            int start = pos;
            while (!atEnd()) {
                char c = s.charAt(pos);
                // Lenient: allow tspecials other than ';' inside unquoted values (common in the wild),
                // but stop at whitespace, ';' and comments.
                if (c == ';' || c == '(' || c == ' ' || c == '\t' || c == '\r' || c == '\n') break;
                pos++;
            }
            String v = s.substring(start, pos);
            skipCfws();
            return v;
        }

        /** Reads a quoted string starting at '"'; returns its unescaped content. Unterminated runs to the end. */
        String readQuoted() {
            pos++; // opening quote
            StringBuilder sb = new StringBuilder();
            while (!atEnd()) {
                char c = s.charAt(pos++);
                if (c == '"') return sb.toString();
                if (c == '\\' && !atEnd()) {
                    sb.append(s.charAt(pos++));
                } else if (c == '\r' || c == '\n') {
                    // Folding whitespace inside a quoted string: drop the line break.
                } else {
                    sb.append(c);
                }
            }
            return sb.toString();
        }

        void skipCfws() {
            while (!atEnd()) {
                char c = s.charAt(pos);
                if (c == ' ' || c == '\t' || c == '\r' || c == '\n') {
                    pos++;
                } else if (c == '(') {
                    skipComment();
                } else {
                    return;
                }
            }
        }

        /** Skips a (possibly nested) comment starting at '('. */
        void skipComment() {
            int depth = 0;
            while (!atEnd()) {
                char c = s.charAt(pos++);
                if (c == '\\') {
                    if (!atEnd()) pos++;
                } else if (c == '(') {
                    depth++;
                } else if (c == ')') {
                    if (--depth == 0) return;
                }
            }
        }
    }
}
