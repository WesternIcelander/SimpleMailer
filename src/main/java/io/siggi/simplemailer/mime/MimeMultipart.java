package io.siggi.simplemailer.mime;

import io.siggi.tools.io.mimeheader.MimeHeader;
import io.siggi.tools.io.multipart.MultipartBuilder;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.util.Base64;
import java.util.List;
import java.util.Map;

/**
 * A MIME multipart body ({@code multipart/mixed}, {@code related}, {@code alternative}, ...) built as a stream of
 * segments, so large attachments are streamed from disk rather than held in memory.
 *
 * <p>The output starts directly with the first delimiter line; the caller writes the {@link #contentType()} header
 * for it. Nested multiparts are added with {@link #addPart(List, MimeMultipart)}. Base64 content is encoded on the
 * fly by {@link #base64Segment}, whose length is known up front.
 */
public class MimeMultipart extends MultipartBuilder {
    /** Bytes of input per base64 output line: 57 bytes → 76 characters (RFC 2045 §6.8). */
    static final int BASE64_LINE_INPUT = 57;

    private final String subtype;

    /** @param subtype e.g. {@code mixed}, {@code related}, {@code alternative} */
    public MimeMultipart(String subtype) {
        this(subtype, null);
    }

    /** @param boundary the boundary to use, or null to generate one */
    public MimeMultipart(String subtype, String boundary) {
        super(boundary);
        if (subtype == null || !HeaderParams.isToken(subtype)) {
            throw new IllegalArgumentException("Invalid multipart subtype: " + subtype);
        }
        this.subtype = subtype;
    }

    public String subtype() {
        return subtype;
    }

    /** The value for this multipart's {@code Content-Type} header, e.g. {@code multipart/mixed; boundary="..."}. */
    public String contentType() {
        return "multipart/" + subtype + "; boundary=\"" + getBoundary() + "\"";
    }

    /** Adds a part with the given headers and body. */
    public MimeMultipart addPart(List<MimeHeader> headers, Segment body) {
        beginPart(headers);
        addSegment(body);
        return this;
    }

    /** Adds a part with the given headers and an in-memory body. */
    public MimeMultipart addPart(List<MimeHeader> headers, byte[] body) {
        return addPart(headers, new ByteSegment(body));
    }

    /** Adds a part with the given headers and a body read from {@code file} when the stream is opened. */
    public MimeMultipart addPart(List<MimeHeader> headers, File file) {
        return addPart(headers, new FileSegment(file));
    }

    /** Adds a nested multipart, with a {@code Content-Type} header for it followed by {@code extraHeaders}. */
    public MimeMultipart addPart(List<MimeHeader> extraHeaders, MimeMultipart child) {
        child.complete();
        List<MimeHeader> headers = new java.util.ArrayList<>(extraHeaders.size() + 1);
        headers.add(new MimeHeader("Content-Type", child.contentType()));
        headers.addAll(extraHeaders);
        return addPart(headers, new StreamSegment(child::openStream, child.length()));
    }

    /** Adds a nested multipart with only a {@code Content-Type} header. */
    public MimeMultipart addPart(MimeMultipart child) {
        return addPart(List.of(), child);
    }

    /** Builds a header list from {@code name, value} pairs in order. */
    public static List<MimeHeader> headers(Map<String, String> headers) {
        return headers.entrySet().stream().map(e -> new MimeHeader(e.getKey(), e.getValue())).toList();
    }

    // ---- base64 ----

    /**
     * Length of the base64 encoding of {@code n} bytes: lines of 76 characters separated by CRLF, with no CRLF
     * after the last line (the multipart delimiter supplies it).
     */
    public static long base64Length(long n) {
        if (n <= 0) return 0;
        long lines = (n + BASE64_LINE_INPUT - 1) / BASE64_LINE_INPUT;
        return 4 * ((n + 2) / 3) + 2 * (lines - 1);
    }

    /** A segment that base64-encodes {@code rawLength} bytes from {@code source} as it is read. */
    public static Segment base64Segment(StreamSupplier source, long rawLength) {
        return new StreamSegment(() -> new Base64EncodingInputStream(source.open(), rawLength), base64Length(rawLength));
    }

    /** A segment that base64-encodes a file as it is read. */
    public static Segment base64Segment(File file) {
        return base64Segment(() -> java.nio.file.Files.newInputStream(file.toPath()), file.length());
    }

    /** A segment that base64-encodes in-memory bytes. */
    public static Segment base64Segment(byte[] data) {
        return base64Segment(() -> new java.io.ByteArrayInputStream(data), data.length);
    }

    /**
     * Base64-encodes a stream line by line. Reads exactly {@code rawLength} bytes; if the source is shorter or
     * longer the declared segment length would be wrong, so that is an error.
     */
    static final class Base64EncodingInputStream extends InputStream {
        private final InputStream in;
        private long remaining;
        private final byte[] rawLine = new byte[BASE64_LINE_INPUT];
        private byte[] buffer = new byte[0];
        private int bufferPos;
        private boolean first = true;

        Base64EncodingInputStream(InputStream in, long rawLength) {
            this.in = in;
            this.remaining = rawLength;
        }

        private boolean fill() throws IOException {
            if (remaining <= 0) {
                if (in.read() != -1) throw new IOException("Base64 source is longer than its declared length");
                return false;
            }
            int want = (int) Math.min(BASE64_LINE_INPUT, remaining);
            int got = in.readNBytes(rawLine, 0, want);
            if (got != want) throw new IOException("Base64 source is shorter than its declared length");
            remaining -= want;
            byte[] encoded = Base64.getEncoder().encode(want == BASE64_LINE_INPUT ? rawLine : java.util.Arrays.copyOf(rawLine, want));
            if (first) {
                buffer = encoded;
                first = false;
            } else {
                buffer = new byte[encoded.length + 2];
                buffer[0] = '\r';
                buffer[1] = '\n';
                System.arraycopy(encoded, 0, buffer, 2, encoded.length);
            }
            bufferPos = 0;
            return true;
        }

        @Override
        public int read() throws IOException {
            if (bufferPos >= buffer.length && !fill()) return -1;
            return buffer[bufferPos++] & 0xff;
        }

        @Override
        public int read(byte[] b, int off, int len) throws IOException {
            if (len == 0) return 0;
            if (bufferPos >= buffer.length && !fill()) return -1;
            int n = Math.min(len, buffer.length - bufferPos);
            System.arraycopy(buffer, bufferPos, b, off, n);
            bufferPos += n;
            return n;
        }

        @Override
        public void close() throws IOException {
            in.close();
        }
    }
}
