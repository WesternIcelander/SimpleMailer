package io.siggi.simplemailer.mime;

import io.siggi.simplemailer.config.Config;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.Clock;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * DKIM signer (RFC 6376): {@code a=rsa-sha256}, {@code c=relaxed/relaxed}, one RSA key per signing domain loaded
 * from a PEM file (PLAN.md §2, §7 {@code dkim: {domain: {selector, keyFile}}}).
 *
 * <p>{@link #sign} reads a complete CRLF message, keeps only the header block in memory and streams the body through
 * relaxed body canonicalisation into SHA-256, so large messages are not buffered. It returns the
 * {@code DKIM-Signature} header field (ending in CRLF) that is to be prepended to the unchanged message.
 */
public final class DkimSigner {
    /** Upper bound on the header block read into memory. */
    public static final int MAX_HEADER_BYTES = 1024 * 1024;

    /**
     * Header fields signed when present (RFC 6376 §5.4.1). Every present instance is signed. {@code From} is always
     * in {@code h=} (it is required) and is listed once more than it occurs, so a second {@code From} can't be added.
     */
    public static final List<String> SIGNED_HEADERS = List.of(
            "From", "Sender", "Reply-To", "Subject", "Date", "Message-ID", "To", "Cc",
            "MIME-Version", "Content-Type", "Content-Transfer-Encoding", "Content-ID", "Content-Description",
            "Resent-Date", "Resent-From", "Resent-Sender", "Resent-To", "Resent-Cc", "Resent-Message-ID",
            "In-Reply-To", "References",
            "List-Id", "List-Help", "List-Unsubscribe", "List-Unsubscribe-Post", "List-Subscribe", "List-Post",
            "List-Owner", "List-Archive");

    private static final int FOLD_WIDTH = 76;

    private final String domain;
    private final String selector;
    private final PrivateKey key;
    private final Clock clock;

    public DkimSigner(String domain, String selector, PrivateKey key) {
        this(domain, selector, key, Clock.systemUTC());
    }

    public DkimSigner(String domain, String selector, PrivateKey key, Clock clock) {
        if (domain == null || domain.isBlank()) throw new IllegalArgumentException("domain required");
        if (selector == null || selector.isBlank()) throw new IllegalArgumentException("selector required");
        if (!(key instanceof RSAPrivateKey)) throw new IllegalArgumentException("DKIM key must be an RSA key");
        this.domain = domain.toLowerCase(Locale.ROOT);
        this.selector = selector;
        this.key = key;
        this.clock = clock;
    }

    public String domain() {
        return domain;
    }

    public String selector() {
        return selector;
    }

    /** Signs the message in {@code file}; see {@link #sign(InputStream)}. */
    public String sign(Path file) throws IOException {
        try (InputStream in = Files.newInputStream(file)) {
            return sign(in);
        }
    }

    /** Signs the message bytes; see {@link #sign(InputStream)}. */
    public String sign(byte[] message) throws IOException {
        return sign(new ByteArrayInputStream(message));
    }

    /**
     * Reads the whole message from {@code in} (not closed) and returns the {@code DKIM-Signature} header field,
     * folded and ending in CRLF, to be placed in front of the message.
     */
    public String sign(InputStream in) throws IOException {
        in = new java.io.BufferedInputStream(in, 16384);
        List<HeaderField> headers = parseHeaders(readHeaderBlock(in));
        String bodyHash = Base64.getEncoder().encodeToString(bodyHash(in));

        List<String> h = new ArrayList<>();
        Map<String, Integer> counts = new LinkedHashMap<>();
        for (HeaderField f : headers) counts.merge(f.lowerName(), 1, Integer::sum);
        for (String name : SIGNED_HEADERS) {
            int n = counts.getOrDefault(name.toLowerCase(Locale.ROOT), 0);
            if (name.equals("From")) {
                if (n == 0) throw new IOException("message has no From header");
                n++; // oversign
            }
            for (int i = 0; i < n; i++) h.add(name);
        }

        long now = clock.instant().getEpochSecond();
        List<String> tags = List.of(
                "v=1", "a=rsa-sha256", "c=relaxed/relaxed", "d=" + domain, "s=" + selector, "t=" + now,
                "h=" + String.join(":", h), "bh=" + bodyHash);
        String prefix = foldTags(tags); // "DKIM-Signature: ...; b="

        ByteArrayOutputStream signed = new ByteArrayOutputStream();
        for (HeaderField f : selectHeaders(headers, h)) {
            signed.writeBytes(relaxedHeader(f.raw()).getBytes(StandardCharsets.ISO_8859_1));
            signed.writeBytes(CRLF);
        }
        signed.writeBytes(relaxedHeader(prefix).getBytes(StandardCharsets.ISO_8859_1));

        byte[] sig;
        try {
            Signature rsa = Signature.getInstance("SHA256withRSA");
            rsa.initSign(key);
            rsa.update(signed.toByteArray());
            sig = rsa.sign();
        } catch (GeneralSecurityException e) {
            throw new IOException("DKIM signing failed", e);
        }
        return prefix + foldBase64(Base64.getEncoder().encodeToString(sig), lastLineLength(prefix)) + "\r\n";
    }

    /**
     * The lower-case domain of the (first) address in the message's {@code From} header, or {@code null} if the
     * message has no {@code From} header or no domain can be found in it. Reads only the header block from
     * {@code in} (not closed).
     */
    public static String fromDomain(InputStream in) throws IOException {
        for (HeaderField f : parseHeaders(readHeaderBlock(in))) {
            if (f.lowerName().equals("from")) return addressDomain(f.raw().substring(f.raw().indexOf(':') + 1));
        }
        return null;
    }

    /** {@link #fromDomain(InputStream)} of a message file. */
    public static String fromDomain(Path file) throws IOException {
        try (InputStream in = new java.io.BufferedInputStream(Files.newInputStream(file), 8192)) {
            return fromDomain(in);
        }
    }

    /**
     * The domain of the first address in an address-list header value, e.g. {@code "Doe, J" <j@Example.com>} →
     * {@code example.com}. Comments and quoted strings are skipped.
     */
    static String addressDomain(String value) {
        StringBuilder plain = new StringBuilder(); // the value without comments and quoted strings
        int depth = 0;
        boolean quoted = false;
        String angle = null;
        StringBuilder inAngle = null;
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (c == '\\' && (quoted || depth > 0)) {
                i++;
                continue;
            }
            if (quoted) {
                if (c == '"') quoted = false;
                continue;
            }
            if (depth > 0) {
                if (c == '(') depth++;
                else if (c == ')') depth--;
                continue;
            }
            if (c == '"') {
                quoted = true;
            } else if (c == '(') {
                depth++;
            } else if (inAngle != null) {
                if (c == '>') {
                    angle = inAngle.toString();
                    break;
                }
                inAngle.append(c);
            } else if (c == '<') {
                inAngle = new StringBuilder();
            } else if (c == ',') {
                break; // first address only
            } else {
                plain.append(c);
            }
        }
        String addr = (angle != null ? angle : plain.toString()).replaceAll("[\\s\\r\\n]+", "");
        int at = addr.lastIndexOf('@');
        if (at < 0 || at == addr.length() - 1) return null;
        String domain = addr.substring(at + 1).toLowerCase(Locale.ROOT);
        if (domain.startsWith("[")) return null; // address literal
        return domain;
    }

    // ---- canonicalisation ----

    private static final byte[] CRLF = {'\r', '\n'};

    /**
     * Relaxed header canonicalisation (RFC 6376 §3.4.2) of one raw header field (name, colon, value, possibly
     * folded; without the final CRLF). The result has no trailing CRLF.
     */
    public static String relaxedHeader(String rawField) {
        int colon = rawField.indexOf(':');
        if (colon < 0) throw new IllegalArgumentException("not a header field: " + rawField);
        String name = rawField.substring(0, colon).strip().toLowerCase(Locale.ROOT);
        String value = rawField.substring(colon + 1).replace("\r\n", "").replace("\n", "").replace("\r", "");
        StringBuilder sb = new StringBuilder(value.length());
        boolean wsp = false;
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (c == ' ' || c == '\t') {
                wsp = true;
            } else {
                if (wsp && !sb.isEmpty()) sb.append(' ');
                wsp = false;
                sb.append(c);
            }
        }
        return name + ":" + sb;
    }

    /** SHA-256 of the relaxed-canonicalised body read from {@code in} (RFC 6376 §3.4.4). */
    public static byte[] bodyHash(InputStream in) throws IOException {
        MessageDigest md;
        try {
            md = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
        try (RelaxedBodyOutputStream out = new RelaxedBodyOutputStream(new DigestSink(md))) {
            in.transferTo(out);
        }
        return md.digest();
    }

    /**
     * Writes the relaxed canonical form of the body bytes it receives (RFC 6376 §3.4.4): runs of WSP become one SP,
     * WSP at line ends is removed, trailing empty lines are dropped and a non-empty body ends in CRLF. Lines end at
     * CRLF (a bare LF is accepted too). {@link #close} finishes the body and closes the target.
     */
    public static final class RelaxedBodyOutputStream extends OutputStream {
        private final OutputStream target;
        private final byte[] buf = new byte[8192];
        private int len;
        private boolean pendingWsp;
        private boolean pendingCr;
        private boolean lineHasContent;
        private long pendingEmptyLines;
        private boolean closed;

        public RelaxedBodyOutputStream(OutputStream target) {
            this.target = target;
        }

        @Override
        public void write(int b) throws IOException {
            b &= 0xff;
            if (pendingCr) {
                pendingCr = false;
                if (b == '\n') {
                    endLine();
                    return;
                }
                content('\r');
            }
            switch (b) {
                case '\r' -> pendingCr = true;
                case '\n' -> endLine();
                case ' ', '\t' -> pendingWsp = true;
                default -> content(b);
            }
        }

        @Override
        public void write(byte[] b, int off, int n) throws IOException {
            for (int i = 0; i < n; i++) write(b[off + i]);
        }

        private void content(int b) throws IOException {
            if (!lineHasContent) {
                for (; pendingEmptyLines > 0; pendingEmptyLines--) {
                    put('\r');
                    put('\n');
                }
                lineHasContent = true;
            }
            if (pendingWsp) {
                put(' ');
                pendingWsp = false;
            }
            put(b);
        }

        private void endLine() throws IOException {
            if (lineHasContent) {
                put('\r');
                put('\n');
            } else {
                pendingEmptyLines++;
            }
            lineHasContent = false;
            pendingWsp = false;
        }

        private void put(int b) throws IOException {
            if (len == buf.length) flushBuffer();
            buf[len++] = (byte) b;
        }

        private void flushBuffer() throws IOException {
            if (len > 0) target.write(buf, 0, len);
            len = 0;
        }

        @Override
        public void close() throws IOException {
            if (closed) return;
            closed = true;
            if (pendingCr) {
                pendingCr = false;
                content('\r');
            }
            if (lineHasContent) {
                put('\r');
                put('\n');
            }
            flushBuffer();
            target.close();
        }
    }

    private static final class DigestSink extends OutputStream {
        private final MessageDigest md;

        DigestSink(MessageDigest md) {
            this.md = md;
        }

        @Override
        public void write(int b) {
            md.update((byte) b);
        }

        @Override
        public void write(byte[] b, int off, int len) {
            md.update(b, off, len);
        }
    }

    // ---- header handling ----

    /** One header field as it appears in the message, without its final CRLF (folding CRLFs kept). */
    record HeaderField(String raw) {
        String lowerName() {
            int colon = raw.indexOf(':');
            return raw.substring(0, colon).strip().toLowerCase(Locale.ROOT);
        }
    }

    /** Reads up to and including the empty line that ends the header block; the stream is left at the body. */
    private static byte[] readHeaderBlock(InputStream in) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream(4096);
        int prev1 = -1, prev2 = -1;
        int b;
        while ((b = in.read()) != -1) {
            out.write(b);
            if (out.size() > MAX_HEADER_BYTES) throw new IOException("header block too large to DKIM sign");
            if (b == '\n' && (prev1 == '\n' || (prev1 == '\r' && prev2 == '\n'))) break;
            prev2 = prev1;
            prev1 = b;
        }
        return out.toByteArray();
    }

    static List<HeaderField> parseHeaders(byte[] block) {
        // ISO-8859-1 maps bytes 1:1 to chars, so 8-bit (e.g. RFC 6532 UTF-8) headers are hashed byte-exact.
        String text = new String(block, StandardCharsets.ISO_8859_1);
        List<HeaderField> fields = new ArrayList<>();
        StringBuilder current = null;
        int pos = 0;
        while (pos < text.length()) {
            int nl = text.indexOf('\n', pos);
            int end = nl < 0 ? text.length() : nl + 1;
            String line = text.substring(pos, end);
            pos = end;
            String bare = line.endsWith("\r\n") ? line.substring(0, line.length() - 2)
                    : line.endsWith("\n") ? line.substring(0, line.length() - 1) : line;
            if (bare.isEmpty()) break; // end of header block
            if ((bare.charAt(0) == ' ' || bare.charAt(0) == '\t') && current != null) {
                current.append("\r\n").append(bare);
            } else {
                if (current != null) fields.add(new HeaderField(current.toString()));
                current = bare.indexOf(':') > 0 ? new StringBuilder(bare) : null;
            }
        }
        if (current != null) fields.add(new HeaderField(current.toString()));
        return fields;
    }

    /**
     * The header fields named in {@code h}, in that order; for repeated names the instances are taken from the
     * bottom up (RFC 6376 §5.4.2). Names with no remaining instance contribute nothing.
     */
    static List<HeaderField> selectHeaders(List<HeaderField> headers, List<String> h) {
        Map<String, Integer> nextFromBottom = new LinkedHashMap<>();
        List<HeaderField> out = new ArrayList<>();
        for (String name : h) {
            String lower = name.toLowerCase(Locale.ROOT);
            int skip = nextFromBottom.getOrDefault(lower, 0);
            int seen = 0;
            for (int i = headers.size() - 1; i >= 0; i--) {
                if (headers.get(i).lowerName().equals(lower)) {
                    if (seen++ == skip) {
                        out.add(headers.get(i));
                        break;
                    }
                }
            }
            nextFromBottom.put(lower, skip + 1);
        }
        return out;
    }

    // ---- folding ----

    /** "DKIM-Signature: tag; tag; ...; b=" folded at {@link #FOLD_WIDTH}; the h= list folds at its colons. */
    private static String foldTags(List<String> tags) {
        StringBuilder sb = new StringBuilder("DKIM-Signature:");
        int lineLen = sb.length();
        List<String> pieces = new ArrayList<>(tags);
        pieces.add("b=");
        for (int i = 0; i < pieces.size(); i++) {
            String tag = pieces.get(i) + (i < pieces.size() - 1 ? ";" : "");
            List<String> parts = tag.startsWith("h=") ? splitKeep(tag, ':') : Collections.singletonList(tag);
            boolean first = true;
            for (String part : parts) {
                String sep = first ? " " : "";
                if (lineLen + sep.length() + part.length() > FOLD_WIDTH && lineLen > 1) {
                    sb.append("\r\n\t");
                    lineLen = 1;
                    sep = "";
                }
                sb.append(sep).append(part);
                lineLen += sep.length() + part.length();
                first = false;
            }
        }
        return sb.toString();
    }

    /** Splits after each {@code sep}, keeping it at the end of the piece: "a:b:c" → "a:", "b:", "c". */
    private static List<String> splitKeep(String s, char sep) {
        List<String> out = new ArrayList<>();
        int start = 0;
        for (int i = 0; i < s.length(); i++) {
            if (s.charAt(i) == sep) {
                out.add(s.substring(start, i + 1));
                start = i + 1;
            }
        }
        if (start < s.length()) out.add(s.substring(start));
        return out;
    }

    private static int lastLineLength(String s) {
        int nl = s.lastIndexOf('\n');
        return nl < 0 ? s.length() : s.length() - nl - 1 + 7; // a TAB counts as up to 8 columns
    }

    /** Base64 with FWS inserted so lines stay within {@link #FOLD_WIDTH} (FWS is allowed inside b=). */
    private static String foldBase64(String b64, int used) {
        StringBuilder sb = new StringBuilder(b64.length() + b64.length() / 32);
        int room = Math.max(8, FOLD_WIDTH - used);
        int pos = 0;
        while (pos < b64.length()) {
            int end = Math.min(b64.length(), pos + room);
            if (pos > 0) sb.append("\r\n\t");
            sb.append(b64, pos, end);
            pos = end;
            room = FOLD_WIDTH - 8;
        }
        return sb.toString();
    }

    // ---- keys ----

    /**
     * Loads an RSA private key from PEM: PKCS#8 ({@code BEGIN PRIVATE KEY}, as the plan specifies) or the
     * traditional PKCS#1 form ({@code BEGIN RSA PRIVATE KEY}) that older {@code openssl genrsa} writes. Encrypted
     * keys are not supported.
     */
    public static PrivateKey loadPrivateKey(Path pemFile) throws IOException {
        return parsePrivateKey(Files.readString(pemFile, StandardCharsets.US_ASCII));
    }

    public static PrivateKey parsePrivateKey(String pem) throws IOException {
        byte[] der;
        boolean pkcs1;
        if (pem.contains("-----BEGIN PRIVATE KEY-----")) {
            der = pemBody(pem, "PRIVATE KEY");
            pkcs1 = false;
        } else if (pem.contains("-----BEGIN RSA PRIVATE KEY-----")) {
            if (pem.contains("Proc-Type: 4,ENCRYPTED")) throw new IOException("encrypted PEM keys are not supported");
            der = pemBody(pem, "RSA PRIVATE KEY");
            pkcs1 = true;
        } else if (pem.contains("-----BEGIN ENCRYPTED PRIVATE KEY-----")) {
            throw new IOException("encrypted PEM keys are not supported");
        } else {
            throw new IOException("no PEM private key found");
        }
        if (pkcs1) der = pkcs1ToPkcs8(der);
        try {
            return KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(der));
        } catch (GeneralSecurityException e) {
            throw new IOException("not a valid RSA private key: " + e.getMessage(), e);
        }
    }

    private static byte[] pemBody(String pem, String label) throws IOException {
        String begin = "-----BEGIN " + label + "-----";
        String end = "-----END " + label + "-----";
        int a = pem.indexOf(begin);
        int b = pem.indexOf(end, a);
        if (a < 0 || b < 0) throw new IOException("malformed PEM (" + label + ")");
        String body = pem.substring(a + begin.length(), b).replaceAll("\\s+", "");
        try {
            return Base64.getDecoder().decode(body);
        } catch (IllegalArgumentException e) {
            throw new IOException("malformed PEM base64", e);
        }
    }

    /** Wraps a PKCS#1 RSAPrivateKey in a PKCS#8 PrivateKeyInfo (version 0, rsaEncryption, NULL params). */
    private static byte[] pkcs1ToPkcs8(byte[] pkcs1) {
        byte[] algId = {0x30, 0x0d, 0x06, 0x09, 0x2a, (byte) 0x86, 0x48, (byte) 0x86, (byte) 0xf7, 0x0d, 0x01, 0x01,
                0x01, 0x05, 0x00};
        byte[] version = {0x02, 0x01, 0x00};
        ByteArrayOutputStream content = new ByteArrayOutputStream();
        content.writeBytes(version);
        content.writeBytes(algId);
        content.write(0x04);
        writeDerLength(content, pkcs1.length);
        content.writeBytes(pkcs1);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(0x30);
        writeDerLength(out, content.size());
        out.writeBytes(content.toByteArray());
        return out.toByteArray();
    }

    private static void writeDerLength(ByteArrayOutputStream out, int len) {
        if (len < 0x80) {
            out.write(len);
        } else if (len < 0x100) {
            out.write(0x81);
            out.write(len);
        } else if (len < 0x10000) {
            out.write(0x82);
            out.write(len >> 8);
            out.write(len);
        } else {
            out.write(0x83);
            out.write(len >> 16);
            out.write(len >> 8);
            out.write(len);
        }
    }

    // ---- per-domain keys ----

    /** The configured signers, keyed by lower-case signing domain. */
    public static final class Keys {
        private final Map<String, DkimSigner> signers;

        public Keys(Map<String, DkimSigner> signers) {
            Map<String, DkimSigner> m = new LinkedHashMap<>();
            signers.forEach((d, s) -> m.put(d.toLowerCase(Locale.ROOT), s));
            this.signers = Collections.unmodifiableMap(m);
        }

        public static Keys none() {
            return new Keys(Map.of());
        }

        /** Loads every key in {@code dkim} config; an unreadable or invalid key file is an error. */
        public static Keys load(Map<String, Config.DkimKey> config) throws IOException {
            return load(config, Clock.systemUTC());
        }

        public static Keys load(Map<String, Config.DkimKey> config, Clock clock) throws IOException {
            Map<String, DkimSigner> m = new LinkedHashMap<>();
            if (config != null) {
                for (Map.Entry<String, Config.DkimKey> e : config.entrySet()) {
                    Config.DkimKey k = e.getValue();
                    PrivateKey key;
                    try {
                        key = loadPrivateKey(Path.of(k.keyFile));
                    } catch (IOException ex) {
                        throw new IOException("dkim." + e.getKey() + ": " + ex.getMessage(), ex);
                    }
                    m.put(e.getKey(), new DkimSigner(e.getKey(), k.selector, key, clock));
                }
            }
            return new Keys(m);
        }

        /** The signer for {@code domain} (case-insensitive), or {@code null} if none is configured. */
        public DkimSigner forDomain(String domain) {
            return domain == null ? null : signers.get(domain.toLowerCase(Locale.ROOT));
        }

        public Set<String> domains() {
            return signers.keySet();
        }
    }
}
