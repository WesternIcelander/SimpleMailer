package io.siggi.simplemailer.mime;

import io.siggi.tools.io.LineEnding;
import io.siggi.tools.io.LineEndingConverterOutputStream;

import java.io.BufferedOutputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;

/**
 * {@code raw} passthrough (PLAN.md §3, §3a): the caller's RFC 5322 message is sent as-is, except that every line
 * ending ({@code CR}, {@code LF} or {@code CRLF}) is normalised to {@code CRLF} and a final {@code CRLF} is added if
 * the message doesn't end with one. Headers and body are otherwise left untouched; SMTP dot-stuffing is left to the
 * SMTP client.
 */
public final class RawMessage {
    private RawMessage() {
    }

    /** The message as UTF-8 bytes with {@code CRLF} line endings, ending in {@code CRLF}. */
    public static byte[] normalise(String raw) {
        ByteArrayOutputStream out = new ByteArrayOutputStream(raw.length() + raw.length() / 32 + 2);
        try {
            writeTo(raw, out);
        } catch (IOException e) {
            throw new UncheckedIOException(e); // ByteArrayOutputStream doesn't throw
        }
        return out.toByteArray();
    }

    /** Writes the normalised message (see {@link #normalise}) to {@code out}, which is not closed. */
    public static void writeTo(String raw, OutputStream out) throws IOException {
        BufferedOutputStream buffered = new BufferedOutputStream(out, 16384);
        try (OutputStream conv = new LineEndingConverterOutputStream(buffered, LineEnding.CRLF, false)) {
            conv.write(raw.getBytes(StandardCharsets.UTF_8));
            if (!raw.isEmpty()) {
                char last = raw.charAt(raw.length() - 1);
                if (last != '\r' && last != '\n') conv.write('\n');
            }
        }
        buffered.flush();
    }
}
