package io.siggi.simplemailer.mime;

import io.siggi.tools.io.mimeheader.MimeHeader;
import io.siggi.tools.io.multipart.MultipartBuilder;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Base64;
import java.util.List;
import java.util.Random;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class MimeMultipartTest {
    private static String read(MultipartBuilder mp) throws IOException {
        try (InputStream in = mp.openStream()) {
            byte[] bytes = in.readAllBytes();
            assertEquals(mp.length(), bytes.length, "declared length must match streamed bytes");
            return new String(bytes, StandardCharsets.UTF_8);
        }
    }

    @Test
    void simpleParts() throws IOException {
        MimeMultipart mp = new MimeMultipart("alternative", "BOUND");
        mp.addPart(List.of(new MimeHeader("Content-Type", "text/plain; charset=utf-8")), "hello".getBytes(StandardCharsets.UTF_8));
        mp.addPart(List.of(new MimeHeader("Content-Type", "text/html; charset=utf-8")), "<p>hi</p>".getBytes(StandardCharsets.UTF_8));
        assertEquals("multipart/alternative; boundary=\"BOUND\"", mp.contentType());
        assertEquals("--BOUND\r\n"
                + "Content-Type: text/plain; charset=utf-8\r\n\r\nhello"
                + "\r\n--BOUND\r\n"
                + "Content-Type: text/html; charset=utf-8\r\n\r\n<p>hi</p>"
                + "\r\n--BOUND--\r\n", read(mp));
    }

    @Test
    void contentTypeRoundTripsThroughHeaderParams() {
        MimeMultipart mp = new MimeMultipart("mixed");
        HeaderParams p = HeaderParams.parse(mp.contentType());
        assertEquals("multipart/mixed", p.value());
        assertEquals(mp.getBoundary(), p.get("boundary"));
    }

    @Test
    void nestedMultipartAndFile(@TempDir Path dir) throws IOException {
        Path file = dir.resolve("a.txt");
        Files.writeString(file, "file body");

        MimeMultipart alt = new MimeMultipart("alternative", "ALT");
        alt.addPart(List.of(new MimeHeader("Content-Type", "text/plain")), "t".getBytes(StandardCharsets.UTF_8));

        MimeMultipart mixed = new MimeMultipart("mixed", "MIX");
        mixed.addPart(alt);
        mixed.addPart(List.of(new MimeHeader("Content-Type", "text/plain")), file.toFile());

        assertEquals("--MIX\r\n"
                + "Content-Type: multipart/alternative; boundary=\"ALT\"\r\n\r\n"
                + "--ALT\r\nContent-Type: text/plain\r\n\r\nt\r\n--ALT--\r\n"
                + "\r\n--MIX\r\n"
                + "Content-Type: text/plain\r\n\r\nfile body"
                + "\r\n--MIX--\r\n", read(mixed));
        // Can be streamed more than once (retries resend the same bytes).
        assertEquals(read(mixed), read(mixed));
    }

    @Test
    void invalidSubtypeRejected() {
        assertThrows(IllegalArgumentException.class, () -> new MimeMultipart("a b"));
        assertThrows(IllegalArgumentException.class, () -> new MimeMultipart(null));
    }

    @Test
    void base64LengthAndEncoding() throws IOException {
        Random random = new Random(42);
        for (int n : new int[]{0, 1, 2, 3, 56, 57, 58, 113, 114, 115, 171, 1000, 100_000}) {
            byte[] data = new byte[n];
            random.nextBytes(data);
            MultipartBuilder.Segment seg = MimeMultipart.base64Segment(data);
            byte[] encoded;
            try (InputStream in = seg.open()) {
                encoded = in.readAllBytes();
            }
            assertEquals(seg.length(), encoded.length, "length for n=" + n);
            assertEquals(MimeMultipart.base64Length(n), encoded.length);
            String s = new String(encoded, StandardCharsets.US_ASCII);
            for (String line : s.split("\r\n", -1)) {
                assertTrue(line.length() <= 76, "line too long for n=" + n);
            }
            assertTrue(!s.endsWith("\r\n"));
            assertArrayEquals(data, Base64.getMimeDecoder().decode(s), "round trip for n=" + n);
            String expected = Base64.getMimeEncoder(76, "\r\n".getBytes(StandardCharsets.US_ASCII)).encodeToString(data);
            assertEquals(expected, s);
        }
    }

    @Test
    void base64FilePart(@TempDir Path dir) throws IOException {
        byte[] data = new byte[300];
        new Random(1).nextBytes(data);
        Path file = dir.resolve("bin");
        Files.write(file, data);
        MimeMultipart mp = new MimeMultipart("mixed", "B");
        mp.addPart(List.of(new MimeHeader("Content-Transfer-Encoding", "base64")), MimeMultipart.base64Segment(file.toFile()));
        String out = read(mp);
        String body = out.substring(out.indexOf("\r\n\r\n") + 4, out.indexOf("\r\n--B--"));
        assertArrayEquals(data, Base64.getMimeDecoder().decode(body));
    }

    @Test
    void base64SourceLengthMismatchIsAnError() {
        MultipartBuilder.Segment shorter = MimeMultipart.base64Segment(() -> new java.io.ByteArrayInputStream(new byte[10]), 20);
        assertThrows(IOException.class, () -> shorter.open().readAllBytes());
        MultipartBuilder.Segment longer = MimeMultipart.base64Segment(() -> new java.io.ByteArrayInputStream(new byte[30]), 20);
        assertThrows(IOException.class, () -> longer.open().readAllBytes());
    }
}
