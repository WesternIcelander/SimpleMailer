package io.siggi.simplemailer.mime;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

class RawMessageTest {
    private static String norm(String raw) {
        return new String(RawMessage.normalise(raw), StandardCharsets.UTF_8);
    }

    @Test
    void crlfIsUnchanged() {
        assertEquals("Subject: x\r\n\r\nbody\r\n", norm("Subject: x\r\n\r\nbody\r\n"));
    }

    @Test
    void lfAndCrBecomeCrlf() {
        assertEquals("A: 1\r\n\r\nb\r\nc\r\n", norm("A: 1\n\nb\rc\n"));
    }

    @Test
    void mixedLineEndings() {
        assertEquals("a\r\nb\r\nc\r\n\r\nd\r\n", norm("a\r\nb\nc\r\rd"));
    }

    @Test
    void lfCrIsTwoLineBreaks() {
        assertEquals("a\r\n\r\nb\r\n", norm("a\n\rb"));
    }

    @Test
    void finalCrlfAdded() {
        assertEquals("Subject: x\r\n\r\nbody\r\n", norm("Subject: x\r\n\r\nbody"));
        assertEquals("", norm(""));
    }

    @Test
    void contentPassedThrough() {
        String raw = "Subject: =?utf-8?q?caf=C3=A9?=\r\nX-Folded: a\r\n b\r\n\r\ncafé .\r\n.leading dot\r\n";
        assertArrayEquals(raw.getBytes(StandardCharsets.UTF_8), RawMessage.normalise(raw));
    }
}
