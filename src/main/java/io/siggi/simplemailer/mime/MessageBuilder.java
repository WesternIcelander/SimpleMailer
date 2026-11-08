package io.siggi.simplemailer.mime;

import io.siggi.simplemailer.model.SendRequest;
import io.siggi.tools.io.mimeheader.MimeHeader;
import io.siggi.tools.io.multipart.MultipartBuilder.ByteSegment;
import io.siggi.tools.io.multipart.MultipartBuilder.Segment;
import io.siggi.tools.io.multipart.MultipartBuilder.StreamSupplier;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.SequenceInputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;

/**
 * Builds the RFC 5322 message for a structured send request (PLAN.md §3a, §5).
 *
 * <p>Writes {@code Date}, {@code Message-ID} ({@code <uuid@heloName>}), {@code From}, {@code To}, {@code Cc},
 * {@code Subject}, caller headers, {@code MIME-Version} and the content headers. Bcc is never written. Non-ASCII
 * header text is RFC 2047 encoded and headers are folded at whitespace to 78 columns where possible. Text and HTML
 * bodies are UTF-8, quoted-printable. Attachment filenames are RFC 2231 encoded when they aren't plain ASCII.
 *
 * <p>The MIME tree is {@code multipart/mixed} [ {@code multipart/related} [ {@code multipart/alternative} [text,
 * html], inline parts… ], attachments… ], dropping any layer that isn't needed. Every line of the output ends in
 * CRLF and no line is longer than 998 characters; SMTP dot-stuffing is left to the SMTP client.
 */
public final class MessageBuilder {
    /** Preferred maximum line length (RFC 5322 §2.1.1). */
    static final int FOLD_AT = 78;
    /** Hard maximum line length, excluding CRLF (RFC 5322 §2.1.1). */
    static final int MAX_LINE = 998;
    /** Maximum quoted-printable line length, including a trailing soft-break {@code =} (RFC 2045 §6.7). */
    static final int QP_LINE = 76;
    /**
     * Maximum length of one encoded-word. RFC 2047 allows 75; a little less keeps {@code Subject: } plus one word
     * within {@link #FOLD_AT}.
     */
    static final int ENCODED_WORD_MAX = 68;

    private static final DateTimeFormatter DATE_FORMAT =
            DateTimeFormatter.ofPattern("EEE, d MMM yyyy HH:mm:ss Z", Locale.US);

    /** An attachment or inline part. The content is read (and base64-encoded) when the message is streamed. */
    public record Attachment(String filename, String contentType, boolean inline, String contentId,
                             StreamSupplier source, long length) {
        public Attachment {
            Objects.requireNonNull(filename, "filename");
            Objects.requireNonNull(source, "source");
            if (length < 0) throw new IllegalArgumentException("length < 0");
        }

        public static Attachment of(String filename, String contentType, boolean inline, String contentId, byte[] data) {
            return new Attachment(filename, contentType, inline, contentId,
                    () -> new java.io.ByteArrayInputStream(data), data.length);
        }

        public static Attachment of(String filename, String contentType, boolean inline, String contentId, Path file)
                throws IOException {
            return new Attachment(filename, contentType, inline, contentId, () -> Files.newInputStream(file),
                    Files.size(file));
        }
    }

    private String messageId;
    private ZonedDateTime date;
    private String from;
    private final List<String> to = new ArrayList<>();
    private final List<String> cc = new ArrayList<>();
    private String subject;
    private String text;
    private String html;
    private final Map<String, String> extraHeaders = new LinkedHashMap<>();
    private final List<Attachment> attachments = new ArrayList<>();
    private String boundaryPrefix;

    /**
     * Starts a builder from a structured request: From, To, Cc, Subject, text, html and headers. Bcc is ignored.
     * Attachments must be added separately with {@link #attachment}, since their content lives elsewhere.
     */
    public static MessageBuilder fromRequest(SendRequest req, String heloName) {
        MessageBuilder b = new MessageBuilder()
                .messageId("<" + req.id.toLowerCase(Locale.ROOT) + "@" + heloName + ">")
                .from(req.from == null ? null : req.from.trim())
                .subject(req.subject)
                .text(req.text)
                .html(req.html);
        if (req.to != null) req.to.forEach(a -> b.to(a.trim()));
        if (req.cc != null) req.cc.forEach(a -> b.cc(a.trim()));
        if (req.headers != null) req.headers.forEach(b::header);
        return b;
    }

    public MessageBuilder messageId(String messageId) {
        this.messageId = messageId;
        return this;
    }

    /** The {@code Date} header; defaults to now. */
    public MessageBuilder date(ZonedDateTime date) {
        this.date = date;
        return this;
    }

    public MessageBuilder from(String from) {
        this.from = from;
        return this;
    }

    public MessageBuilder to(String address) {
        to.add(address);
        return this;
    }

    public MessageBuilder cc(String address) {
        cc.add(address);
        return this;
    }

    public MessageBuilder subject(String subject) {
        this.subject = subject;
        return this;
    }

    public MessageBuilder text(String text) {
        this.text = text;
        return this;
    }

    public MessageBuilder html(String html) {
        this.html = html;
        return this;
    }

    /** An additional header. Non-ASCII words in the value are RFC 2047 encoded. */
    public MessageBuilder header(String name, String value) {
        extraHeaders.put(name, value);
        return this;
    }

    public MessageBuilder attachment(Attachment attachment) {
        attachments.add(attachment);
        return this;
    }

    /** Fixed boundaries ({@code prefix-mixed}, {@code prefix-related}, ...), for reproducible output in tests. */
    MessageBuilder boundaryPrefix(String prefix) {
        this.boundaryPrefix = prefix;
        return this;
    }

    // ---- building ----

    /** A built message: its top-level headers and a body streamed on demand. */
    public static final class Message {
        private final List<MimeHeader> headers;
        private final byte[] headerBytes;
        private final Segment body;

        private Message(List<MimeHeader> headers, Segment body) {
            this.headers = List.copyOf(headers);
            StringBuilder sb = new StringBuilder();
            for (MimeHeader h : headers) sb.append(h).append("\r\n");
            sb.append("\r\n");
            // UTF-8 only matters for internationalised (SMTPUTF8) addresses; everything else is ASCII.
            this.headerBytes = sb.toString().getBytes(StandardCharsets.UTF_8);
            this.body = body;
        }

        public List<MimeHeader> headers() {
            return headers;
        }

        /** Total size in bytes. */
        public long length() {
            return headerBytes.length + body.length();
        }

        public InputStream openStream() throws IOException {
            return new SequenceInputStream(new java.io.ByteArrayInputStream(headerBytes), body.open());
        }

        public void writeTo(OutputStream out) throws IOException {
            try (InputStream in = openStream()) {
                in.transferTo(out);
            }
        }

        /** Writes the message to {@code file} atomically (temp file + rename). */
        public void writeTo(Path file) throws IOException {
            Path tmp = file.resolveSibling(file.getFileName() + ".tmp");
            try (OutputStream out = Files.newOutputStream(tmp)) {
                writeTo(out);
            }
            Files.move(tmp, file, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
        }

        /** The whole message in memory (tests and small messages only). */
        public byte[] toBytes() throws IOException {
            ByteArrayOutputStream out = new ByteArrayOutputStream((int) Math.min(length(), Integer.MAX_VALUE));
            writeTo(out);
            return out.toByteArray();
        }
    }

    public Message build() {
        if (from == null || from.isBlank()) throw new IllegalStateException("from is required");
        List<MimeHeader> headers = new ArrayList<>();
        headers.add(new MimeHeader("Date", DATE_FORMAT.format(date != null ? date : ZonedDateTime.now())));
        if (messageId != null) headers.add(new MimeHeader("Message-ID", messageId));
        headers.add(addressHeader("From", List.of(from)));
        if (!to.isEmpty()) headers.add(addressHeader("To", to));
        if (!cc.isEmpty()) headers.add(addressHeader("Cc", cc));
        if (subject != null) headers.add(unstructuredHeader("Subject", subject));
        for (Map.Entry<String, String> e : extraHeaders.entrySet()) {
            headers.add(encodedHeader(e.getKey(), e.getValue(), false));
        }
        headers.add(new MimeHeader("MIME-Version", "1.0"));

        Part body = bodyPart();
        headers.addAll(body.headers);
        return new Message(headers, body.content);
    }

    /** A MIME entity: its content headers and its (already encoded) content. */
    private record Part(List<MimeHeader> headers, Segment content) {
    }

    private Part bodyPart() {
        List<Attachment> inline = attachments.stream().filter(Attachment::inline).toList();
        List<Attachment> regular = attachments.stream().filter(a -> !a.inline()).toList();

        Part content;
        if (text != null && html != null) {
            MimeMultipart alt = multipart("alternative");
            addTo(alt, textPart("plain", text));
            addTo(alt, textPart("html", html));
            content = wrap(alt);
        } else if (html != null) {
            content = textPart("html", html);
        } else {
            content = textPart("plain", text == null ? "" : text);
        }

        if (!inline.isEmpty()) {
            MimeMultipart related = multipart("related");
            addTo(related, content);
            for (Attachment a : inline) addTo(related, attachmentPart(a));
            content = wrap(related);
        }
        if (!regular.isEmpty()) {
            MimeMultipart mixed = multipart("mixed");
            addTo(mixed, content);
            for (Attachment a : regular) addTo(mixed, attachmentPart(a));
            content = wrap(mixed);
        }
        return content;
    }

    private MimeMultipart multipart(String subtype) {
        return new MimeMultipart(subtype, boundaryPrefix == null ? null : boundaryPrefix + "-" + subtype);
    }

    private static void addTo(MimeMultipart mp, Part part) {
        mp.addPart(part.headers, part.content);
    }

    private static Part wrap(MimeMultipart mp) {
        mp.complete();
        return new Part(List.of(new MimeHeader("Content-Type", mp.contentType())),
                new io.siggi.tools.io.multipart.MultipartBuilder.StreamSegment(mp::openStream, mp.length()));
    }

    private static Part textPart(String subtype, String content) {
        return new Part(List.of(
                new MimeHeader("Content-Type", "text/" + subtype + "; charset=utf-8"),
                new MimeHeader("Content-Transfer-Encoding", "quoted-printable")),
                new ByteSegment(quotedPrintable(content).getBytes(StandardCharsets.US_ASCII)));
    }

    private static Part attachmentPart(Attachment a) {
        String type = a.contentType() == null || a.contentType().isBlank()
                ? "application/octet-stream" : a.contentType().trim();
        HeaderParams parsed = HeaderParams.parse(type);
        String mediaType = parsed.value().isEmpty() ? "application/octet-stream" : parsed.lowerValue();
        if (!isAsciiPrintable(mediaType) || mediaType.indexOf('/') < 0) mediaType = "application/octet-stream";

        StringBuilder contentType = new StringBuilder(mediaType);
        for (Map.Entry<String, String> p : parsed.params().entrySet()) {
            if (p.getKey().equals("name")) continue;
            if (HeaderParams.isToken(p.getKey())) appendParam(contentType, p.getKey(), p.getValue());
        }
        appendParam(contentType, "name", a.filename());

        StringBuilder disposition = new StringBuilder(a.inline() ? "inline" : "attachment");
        appendParam(disposition, "filename", a.filename());

        List<MimeHeader> headers = new ArrayList<>();
        headers.add(new MimeHeader("Content-Type", contentType.toString()));
        headers.add(new MimeHeader("Content-Disposition", disposition.toString()));
        if (a.inline() && a.contentId() != null && !a.contentId().isBlank()) {
            headers.add(new MimeHeader("Content-ID", "<" + stripCrLf(a.contentId().trim()) + ">"));
        }
        headers.add(new MimeHeader("Content-Transfer-Encoding", "base64"));
        return new Part(headers, MimeMultipart.base64Segment(a.source(), a.length()));
    }

    // ---- headers ----

    /** An address header: plain addresses, comma separated, folded between addresses. */
    static MimeHeader addressHeader(String name, List<String> addresses) {
        List<String> items = new ArrayList<>(addresses.size());
        for (int i = 0; i < addresses.size(); i++) {
            String a = stripCrLf(addresses.get(i));
            items.add(i < addresses.size() - 1 ? a + "," : a);
        }
        return new MimeHeader(name, fold(name, items));
    }

    /** An unstructured header such as {@code Subject}: every word that needs it is RFC 2047 encoded. */
    static MimeHeader unstructuredHeader(String name, String value) {
        return encodedHeader(name, value, true);
    }

    /**
     * Encodes and folds a header value. Runs of words containing non-ASCII characters become RFC 2047
     * encoded-words. With {@code unstructured}, words that look like encoded-words or that are too long to fold are
     * encoded too; otherwise they are left alone, since the header may be structured (e.g. {@code Reply-To}).
     */
    static MimeHeader encodedHeader(String name, String value, boolean unstructured) {
        String[] words = stripCrLf(value).split(" ", -1);
        List<String> out = new ArrayList<>();
        int i = 0;
        while (i < words.length) {
            if (!needsEncoding(words[i], unstructured)) {
                out.add(words[i++]);
                continue;
            }
            int j = i;
            StringBuilder run = new StringBuilder(words[j++]);
            // Absorb following words into the run while they also need encoding, so the spaces between them are
            // kept inside the encoded text (whitespace between adjacent encoded-words is dropped when decoding).
            while (j < words.length && needsEncoding(words[j], unstructured)) {
                run.append(' ').append(words[j++]);
            }
            out.addAll(encodeWords(run.toString()));
            i = j;
        }
        String folded = fold(name, out);
        String[] lines = folded.split("\r\n", -1);
        for (int k = 0; k < lines.length; k++) {
            if (lines[k].length() + (k == 0 ? name.length() + 2 : 0) > MAX_LINE) {
                throw new IllegalArgumentException("header " + name + " has a line longer than " + MAX_LINE + " characters");
            }
        }
        return new MimeHeader(name, folded);
    }

    private static boolean needsEncoding(String word, boolean unstructured) {
        if (!isAsciiPrintable(word)) return true;
        if (!unstructured) return false;
        return word.length() > FOLD_AT - 2 || (word.contains("=?") && word.contains("?="));
    }

    private static boolean isAsciiPrintable(String s) {
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c < 0x20 && c != '\t' || c >= 0x7f) return false;
        }
        return true;
    }

    private static String stripCrLf(String s) {
        return s.replace("\r", "").replace("\n", "");
    }

    /**
     * Joins {@code words} with single spaces, breaking the line (CRLF + the space) before a word that would take
     * the line past {@link #FOLD_AT}. A word is never split, so a single long word can still exceed it.
     */
    static String fold(String name, List<String> words) {
        StringBuilder sb = new StringBuilder();
        int lineLength = name.length() + 2;
        boolean lineHasWord = false;
        for (int i = 0; i < words.size(); i++) {
            String w = words.get(i);
            if (i > 0) {
                // Never fold before an empty word: that could leave a whitespace-only line.
                if (lineHasWord && !w.isEmpty() && lineLength + 1 + w.length() > FOLD_AT) {
                    sb.append("\r\n");
                    lineLength = 0;
                }
                sb.append(' ');
                lineLength++;
            }
            sb.append(w);
            lineLength += w.length();
            lineHasWord = lineHasWord || !w.isEmpty();
        }
        return sb.toString();
    }

    /**
     * Encodes text as one or more RFC 2047 encoded-words in UTF-8, each at most {@link #ENCODED_WORD_MAX}
     * characters, never splitting a character. Uses Q encoding (with the restricted character set allowed in
     * phrases) unless most characters are non-ASCII, then B encoding.
     */
    static List<String> encodeWords(String text) {
        int total = text.codePointCount(0, text.length());
        int nonAscii = (int) text.codePoints().filter(c -> c >= 0x80).count();
        // Q keeps mostly-Latin text readable; B is more compact when most characters are non-ASCII.
        boolean useQ = nonAscii * 2 <= total;
        String prefix = useQ ? "=?UTF-8?Q?" : "=?UTF-8?B?";
        int budget = ENCODED_WORD_MAX - prefix.length() - 2;

        List<String> result = new ArrayList<>();
        StringBuilder payload = new StringBuilder();
        ByteArrayOutputStream chunk = new ByteArrayOutputStream();
        for (int i = 0; i < text.length(); ) {
            int cp = text.codePointAt(i);
            i += Character.charCount(cp);
            byte[] bytes = new String(Character.toChars(cp)).getBytes(StandardCharsets.UTF_8);
            if (useQ) {
                String enc = qEncode(bytes);
                if (payload.length() + enc.length() > budget && payload.length() > 0) {
                    result.add(prefix + payload + "?=");
                    payload.setLength(0);
                }
                payload.append(enc);
            } else {
                if (4 * ((chunk.size() + bytes.length + 2) / 3) > budget && chunk.size() > 0) {
                    result.add(prefix + Base64.getEncoder().encodeToString(chunk.toByteArray()) + "?=");
                    chunk.reset();
                }
                chunk.write(bytes, 0, bytes.length);
            }
        }
        if (useQ && payload.length() > 0) result.add(prefix + payload + "?=");
        if (!useQ && chunk.size() > 0) result.add(prefix + Base64.getEncoder().encodeToString(chunk.toByteArray()) + "?=");
        return result;
    }

    /** Characters Q encoding may leave as-is in any header position (RFC 2047 §5 rule 3), plus space as {@code _}. */
    private static boolean qChar(int b) {
        return b >= 'A' && b <= 'Z' || b >= 'a' && b <= 'z' || b >= '0' && b <= '9'
                || b == '!' || b == '*' || b == '+' || b == '-' || b == '/' || b == ' ';
    }

    private static String qEncode(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte value : bytes) {
            int b = value & 0xff;
            if (b == ' ') sb.append('_');
            else if (qChar(b)) sb.append((char) b);
            else sb.append('=').append(HEX[b >> 4]).append(HEX[b & 15]);
        }
        return sb.toString();
    }

    private static final char[] HEX = "0123456789ABCDEF".toCharArray();

    // ---- RFC 2231 parameters ----

    /** RFC 2231 attribute-char that needs no percent-encoding (a token char other than {@code * ' %}). */
    private static boolean attrChar(int b) {
        return b >= 'A' && b <= 'Z' || b >= 'a' && b <= 'z' || b >= '0' && b <= '9'
                || "!#$&+-.^_`|~".indexOf(b) >= 0;
    }

    /**
     * Appends {@code ; name=value} to a header value, each parameter on its own folded line. Printable ASCII that
     * fits is written as a token or quoted string; anything else uses RFC 2231 {@code name*=UTF-8''%XX…}, split into
     * continuations {@code name*0*}, {@code name*1*}, … to keep lines short.
     */
    static void appendParam(StringBuilder header, String name, String value) {
        value = stripCrLf(value);
        String simple = HeaderParams.quote(value);
        if (isAsciiPrintable(value) && simple.length() + name.length() + 2 <= FOLD_AT) {
            header.append(";\r\n ").append(name).append('=').append(simple);
            return;
        }
        List<String> pieces = new ArrayList<>();
        StringBuilder piece = new StringBuilder("UTF-8''");
        int budget = FOLD_AT - 1 - name.length() - 6; // " name*NN*=" ... ";"
        for (int i = 0; i < value.length(); ) {
            int cp = value.codePointAt(i);
            i += Character.charCount(cp);
            StringBuilder enc = new StringBuilder();
            for (byte raw : new String(Character.toChars(cp)).getBytes(StandardCharsets.UTF_8)) {
                int b = raw & 0xff;
                if (attrChar(b)) enc.append((char) b);
                else enc.append('%').append(HEX[b >> 4]).append(HEX[b & 15]);
            }
            if (piece.length() + enc.length() > budget && piece.length() > (pieces.isEmpty() ? 7 : 0)) {
                pieces.add(piece.toString());
                piece.setLength(0);
            }
            piece.append(enc);
        }
        pieces.add(piece.toString());
        if (pieces.size() == 1) {
            header.append(";\r\n ").append(name).append("*=").append(pieces.get(0));
        } else {
            for (int i = 0; i < pieces.size(); i++) {
                header.append(";\r\n ").append(name).append('*').append(i).append("*=").append(pieces.get(i));
            }
        }
    }

    // ---- quoted-printable ----

    /**
     * Quoted-printable encodes text as UTF-8 (RFC 2045 §6.7). Line breaks of any kind become CRLF hard breaks;
     * lines are soft-broken to at most {@link #QP_LINE} characters; trailing whitespace, {@code =}, controls and
     * non-ASCII are escaped. A {@code .} or {@code From } at the start of a line is escaped too, so the encoded text
     * survives SMTP and mbox handling unchanged. The result always ends in CRLF.
     */
    public static String quotedPrintable(String text) {
        String normalised = text.replace("\r\n", "\n").replace('\r', '\n');
        if (normalised.endsWith("\n")) normalised = normalised.substring(0, normalised.length() - 1);
        StringBuilder out = new StringBuilder(normalised.length() + 16);
        String[] lines = normalised.split("\n", -1);
        for (String line : lines) {
            encodeQpLine(line.getBytes(StandardCharsets.UTF_8), out);
            out.append("\r\n");
        }
        return out.toString();
    }

    private static void encodeQpLine(byte[] line, StringBuilder out) {
        int col = 0;
        for (int i = 0; i < line.length; i++) {
            int b = line[i] & 0xff;
            boolean last = i == line.length - 1;
            String enc;
            if ((b == ' ' || b == '\t') && last) {
                enc = escape(b);
            } else if (col == 0 && (b == '.' || b == 'F' && startsWith(line, i, "From "))) {
                enc = escape(b);
            } else if (b == ' ' || b == '\t' || b >= 33 && b <= 126 && b != '=') {
                enc = String.valueOf((char) b);
            } else {
                enc = escape(b);
            }
            // Room is needed for the soft break '=' unless this is the last character on the line.
            int limit = last ? QP_LINE : QP_LINE - 1;
            if (col + enc.length() > limit) {
                out.append("=\r\n");
                col = 0;
                if (b == '.' || b == 'F' && startsWith(line, i, "From ")) enc = escape(b);
            }
            out.append(enc);
            col += enc.length();
        }
    }

    private static boolean startsWith(byte[] line, int offset, String prefix) {
        if (line.length - offset < prefix.length()) return false;
        for (int k = 0; k < prefix.length(); k++) {
            if (line[offset + k] != prefix.charAt(k)) return false;
        }
        return true;
    }

    private static String escape(int b) {
        return "=" + HEX[b >> 4] + HEX[b & 15];
    }
}
