package io.siggi.simplemailer.mime;

import io.siggi.simplemailer.model.SendRequest;
import io.siggi.tools.io.mimeheader.MimeHeader;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class MessageBuilderTest {
    private static final ZonedDateTime DATE = ZonedDateTime.of(2026, 11, 8, 14, 5, 9, 0, ZoneOffset.ofHours(1));

    // ---- test helpers: decoders independent of the encoder ----

    private static final Pattern ENCODED_WORD = Pattern.compile("=\\?UTF-8\\?([QB])\\?([^?]*)\\?=");

    /** Unfolds a header value and decodes encoded-words (whitespace between adjacent ones is dropped). */
    static String decodeHeader(String value) {
        String unfolded = value.replace("\r\n", "");
        StringBuilder sb = new StringBuilder();
        Matcher m = ENCODED_WORD.matcher(unfolded);
        int last = 0;
        boolean prevEncoded = false;
        while (m.find()) {
            String between = unfolded.substring(last, m.start());
            if (!(prevEncoded && between.isBlank())) sb.append(between);
            byte[] bytes = m.group(1).equals("B")
                    ? Base64.getDecoder().decode(m.group(2))
                    : qpDecodeBytes(m.group(2).replace('_', ' '));
            sb.append(new String(bytes, StandardCharsets.UTF_8));
            last = m.end();
            prevEncoded = true;
        }
        sb.append(unfolded.substring(last));
        return sb.toString();
    }

    static byte[] qpDecodeBytes(String s) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == '=') {
                if (s.startsWith("\r\n", i + 1)) {
                    i += 2;
                } else {
                    out.write(Integer.parseInt(s.substring(i + 1, i + 3), 16));
                    i += 2;
                }
            } else {
                out.write(c);
            }
        }
        return out.toByteArray();
    }

    static String qpDecode(String s) {
        return new String(qpDecodeBytes(s), StandardCharsets.UTF_8);
    }

    private static void assertLinesValid(String s, int max) {
        assertTrue(s.endsWith("\r\n"), "must end in CRLF");
        String[] lines = s.split("\r\n", -1);
        for (String line : lines) {
            assertTrue(line.length() <= max, "line too long (" + line.length() + "): " + line);
            assertFalse(line.contains("\r") || line.contains("\n"), "bare CR or LF");
        }
    }

    private static String header(MessageBuilder.Message m, String name) {
        MimeHeader h = MimeHeader.getFirst(m.headers(), name);
        return h == null ? null : h.getValue();
    }

    // ---- quoted-printable ----

    @Test
    void qpPlainAscii() {
        assertEquals("Hello world\r\nsecond line\r\n", MessageBuilder.quotedPrintable("Hello world\nsecond line"));
        assertEquals("a=3Db\r\n", MessageBuilder.quotedPrintable("a=b"));
        assertEquals("\r\n", MessageBuilder.quotedPrintable(""));
    }

    @Test
    void qpNormalisesLineEndings() {
        assertEquals("a\r\nb\r\nc\r\n", MessageBuilder.quotedPrintable("a\r\nb\rc\n"));
    }

    @Test
    void qpEscapesNonAsciiTrailingWhitespaceDotsAndFrom() {
        assertEquals("caf=C3=A9\r\n", MessageBuilder.quotedPrintable("café"));
        assertEquals("trailing =20\r\ntab=09\r\n", MessageBuilder.quotedPrintable("trailing  \ntab\t"));
        assertEquals("=2E\r\n=2Ehidden\r\n", MessageBuilder.quotedPrintable(".\n.hidden"));
        assertEquals("=46rom me\r\nnot From here\r\n", MessageBuilder.quotedPrintable("From me\nnot From here"));
    }

    @Test
    void qpSoftBreaksLongLines() {
        String text = "x".repeat(200) + " " + "ü".repeat(60) + "\n" + "word ".repeat(40);
        String qp = MessageBuilder.quotedPrintable(text);
        assertLinesValid(qp, MessageBuilder.QP_LINE);
        assertEquals(text.replace("\n", "\r\n") + "\r\n", qpDecode(qp));
        assertTrue(qp.contains("=\r\n"));
    }

    @Test
    void qpRoundTripsAwkwardText() {
        String text = "Line with = signs and ümläuts and emoji 😀😀😀 " + "=".repeat(50) + "\n\n"
                + "  indented\ttabs\t\n" + ".\n" + "From the start\n" + "x".repeat(75) + " \n" + "y".repeat(76);
        String qp = MessageBuilder.quotedPrintable(text);
        assertLinesValid(qp, MessageBuilder.QP_LINE);
        assertEquals(text.replace("\n", "\r\n") + "\r\n", qpDecode(qp));
        for (String line : qp.split("\r\n")) {
            assertFalse(line.endsWith(" ") || line.endsWith("\t"), "trailing whitespace: " + line);
            assertFalse(line.startsWith(".") || line.startsWith("From "), "unsafe line start: " + line);
        }
    }

    // ---- RFC 2047 headers ----

    @Test
    void asciiSubjectIsNotEncoded() {
        MimeHeader h = MessageBuilder.unstructuredHeader("Subject", "Your invoice is ready");
        assertEquals("Your invoice is ready", h.getValue());
    }

    @Test
    void nonAsciiSubjectIsEncodedAndRoundTrips() {
        String subject = "Grüße aus München, Ihre Bestellung ist da";
        String v = MessageBuilder.unstructuredHeader("Subject", subject).getValue();
        assertTrue(v.startsWith("=?UTF-8?Q?Gr=C3=BC=C3=9Fe?= aus =?UTF-8?Q?M=C3=BCnchen=2C?="), v);
        assertTrue(v.replace("\r\n", "").endsWith(" Ihre Bestellung ist da"), v);
        assertEquals(subject, decodeHeader(v));
    }

    @Test
    void mostlyNonAsciiUsesBase64() {
        String subject = "日本語のメール件名です";
        String v = MessageBuilder.unstructuredHeader("Subject", subject).getValue();
        assertTrue(v.startsWith("=?UTF-8?B?"), v);
        assertEquals(subject, decodeHeader(v));
    }

    @Test
    void longEncodedSubjectIsSplitAndFolded() {
        String subject = ("Ünïcödé wörds everywhere 😀 ").repeat(12).trim();
        MimeHeader h = MessageBuilder.unstructuredHeader("Subject", subject);
        String line = h.toString() + "\r\n";
        assertLinesValid(line, MessageBuilder.FOLD_AT);
        Matcher m = ENCODED_WORD.matcher(h.getValue());
        int words = 0;
        while (m.find()) {
            words++;
            assertTrue(m.group().length() <= 75, "encoded-word too long: " + m.group());
        }
        assertTrue(words > 2);
        assertEquals(subject, decodeHeader(h.getValue()));
    }

    @Test
    void encodedWordsNeverSplitACharacter() {
        String text = "😀".repeat(40) + "é".repeat(40);
        for (String word : MessageBuilder.encodeWords(text)) {
            assertTrue(word.length() <= MessageBuilder.ENCODED_WORD_MAX);
            // Every encoded-word must decode to valid UTF-8 on its own.
            String d = decodeHeader(word);
            assertFalse(d.contains("�"), word);
        }
        assertEquals(text, decodeHeader(String.join(" ", MessageBuilder.encodeWords(text))));
    }

    @Test
    void subjectThatLooksEncodedIsEncoded() {
        String subject = "literally =?UTF-8?Q?abc?= here";
        String v = MessageBuilder.unstructuredHeader("Subject", subject).getValue();
        assertEquals(subject, decodeHeader(v));
        assertFalse(v.contains("=?UTF-8?Q?abc?="));
    }

    @Test
    void longAsciiSubjectFoldsAtSpaces() {
        String subject = "word ".repeat(50).trim();
        MimeHeader h = MessageBuilder.unstructuredHeader("Subject", subject);
        assertLinesValid(h + "\r\n", MessageBuilder.FOLD_AT);
        assertEquals(subject, h.getValue().replace("\r\n", ""));
    }

    @Test
    void structuredHeaderEncodesOnlyNonAsciiWords() {
        String v = MessageBuilder.encodedHeader("Reply-To", "Jörg Müller <joerg@example.com>", false).getValue();
        assertEquals("=?UTF-8?Q?J=C3=B6rg_M=C3=BCller?= <joerg@example.com>", v);
        String url = "<https://example.com/" + "u".repeat(120) + ">";
        assertEquals(url, MessageBuilder.encodedHeader("List-Unsubscribe", url, false).getValue());
    }

    @Test
    void headerLongerThan998IsRejected() {
        assertThrows(IllegalArgumentException.class,
                () -> MessageBuilder.encodedHeader("X-Long", "a".repeat(1000), false));
    }

    @Test
    void addressHeaderFoldsBetweenAddresses() {
        List<String> addrs = List.of("alice.longname@example.com", "bob.longername@example.org",
                "carol.longestname@example.net", "dave@example.com");
        MimeHeader h = MessageBuilder.addressHeader("To", addrs);
        assertLinesValid(h + "\r\n", MessageBuilder.FOLD_AT);
        assertEquals(String.join(", ", addrs), h.getValue().replace("\r\n", ""));
        assertTrue(h.getValue().contains("\r\n "));
    }

    // ---- RFC 2231 parameters ----

    @Test
    void asciiFilenameIsPlain() {
        StringBuilder sb = new StringBuilder("attachment");
        MessageBuilder.appendParam(sb, "filename", "terms.pdf");
        assertEquals("attachment;\r\n filename=terms.pdf", sb.toString());
        sb = new StringBuilder("attachment");
        MessageBuilder.appendParam(sb, "filename", "my \"terms\".pdf");
        assertEquals("attachment;\r\n filename=\"my \\\"terms\\\".pdf\"", sb.toString());
    }

    @Test
    void nonAsciiFilenameUsesRfc2231() {
        StringBuilder sb = new StringBuilder("attachment");
        MessageBuilder.appendParam(sb, "filename", "Rechnung März.pdf");
        assertEquals("attachment;\r\n filename*=UTF-8''Rechnung%20M%C3%A4rz.pdf", sb.toString());
        assertEquals("Rechnung März.pdf", HeaderParams.parse(sb.toString()).get("filename"));
    }

    @Test
    void longFilenameUsesContinuations() {
        String name = "Ein sehr langer Dateiname mit Ümlauten und 😀 Emoji, der umgebrochen werden muss "
                + "x".repeat(80) + ".pdf";
        StringBuilder sb = new StringBuilder("attachment");
        MessageBuilder.appendParam(sb, "filename", name);
        String v = sb.toString();
        assertTrue(v.contains("filename*0*=UTF-8''"), v);
        assertTrue(v.contains("filename*1*="), v);
        assertLinesValid("Content-Disposition: " + v + "\r\n", MessageBuilder.FOLD_AT);
        assertEquals(name, HeaderParams.parse(v).get("filename"));
    }

    // ---- whole messages ----

    private static SendRequest request() {
        SendRequest r = new SendRequest();
        r.id = "3F2504E0-4F89-11D3-9A0C-0305E82C3301";
        r.from = "sender@example.com";
        r.to = List.of("a@example.org", "b@example.net");
        r.cc = List.of("c@example.com");
        r.bcc = List.of("secret@example.com");
        r.subject = "Hällo";
        return r;
    }

    @Test
    void textOnlyMessage() throws IOException {
        SendRequest r = request();
        r.text = "Hi there.\nBye.";
        MessageBuilder.Message m = MessageBuilder.fromRequest(r, "mail.example.com").date(DATE).build();
        String s = new String(m.toBytes(), StandardCharsets.UTF_8);
        assertEquals(m.length(), m.toBytes().length);
        assertEquals("Date: Sun, 8 Nov 2026 14:05:09 +0100\r\n"
                + "Message-ID: <3f2504e0-4f89-11d3-9a0c-0305e82c3301@mail.example.com>\r\n"
                + "From: sender@example.com\r\n"
                + "To: a@example.org, b@example.net\r\n"
                + "Cc: c@example.com\r\n"
                + "Subject: =?UTF-8?Q?H=C3=A4llo?=\r\n"
                + "MIME-Version: 1.0\r\n"
                + "Content-Type: text/plain; charset=utf-8\r\n"
                + "Content-Transfer-Encoding: quoted-printable\r\n"
                + "\r\n"
                + "Hi there.\r\nBye.\r\n", s);
        assertFalse(s.contains("secret@example.com"), "Bcc must never appear in the message");
    }

    @Test
    void htmlOnlyAndEmptyBody() throws IOException {
        SendRequest r = request();
        r.html = "<p>Hi</p>";
        MessageBuilder.Message m = MessageBuilder.fromRequest(r, "h").date(DATE).build();
        assertEquals("text/html; charset=utf-8", header(m, "Content-Type"));

        r.html = null;
        m = MessageBuilder.fromRequest(r, "h").date(DATE).build();
        assertEquals("text/plain; charset=utf-8", header(m, "Content-Type"));
        assertTrue(new String(m.toBytes(), StandardCharsets.UTF_8).endsWith("\r\n\r\n\r\n"));
    }

    @Test
    void textAndHtmlMakeAlternative() throws IOException {
        SendRequest r = request();
        r.text = "plain ü";
        r.html = "<p>html ü</p>";
        Map<String, String> extra = new LinkedHashMap<>();
        extra.put("Reply-To", "Jörg <j@example.com>");
        extra.put("X-Campaign", "nov");
        r.headers = extra;
        MessageBuilder.Message m = MessageBuilder.fromRequest(r, "h").date(DATE).boundaryPrefix("B").build();
        String s = new String(m.toBytes(), StandardCharsets.UTF_8);
        assertEquals(m.length(), m.toBytes().length);
        assertEquals("multipart/alternative; boundary=\"B-alternative\"", header(m, "Content-Type"));
        assertNull(header(m, "Content-Transfer-Encoding"));
        assertEquals("=?UTF-8?Q?J=C3=B6rg?= <j@example.com>", header(m, "Reply-To"));
        assertEquals("nov", header(m, "X-Campaign"));
        assertTrue(s.contains("\r\n\r\n--B-alternative\r\n"
                + "Content-Type: text/plain; charset=utf-8\r\n"
                + "Content-Transfer-Encoding: quoted-printable\r\n\r\n"
                + "plain =C3=BC\r\n"
                + "\r\n--B-alternative\r\n"
                + "Content-Type: text/html; charset=utf-8\r\n"
                + "Content-Transfer-Encoding: quoted-printable\r\n\r\n"
                + "<p>html =C3=BC</p>\r\n"
                + "\r\n--B-alternative--\r\n"), s);
        // Caller headers come before MIME-Version / content headers.
        assertTrue(s.indexOf("X-Campaign:") < s.indexOf("MIME-Version:"));
        assertLinesValid(s, MessageBuilder.FOLD_AT);
    }

    @Test
    void attachmentsAndInlinePartsNestCorrectly(@TempDir Path dir) throws IOException {
        Path pdf = dir.resolve("doc.bin");
        byte[] pdfBytes = new byte[1000];
        for (int i = 0; i < pdfBytes.length; i++) pdfBytes[i] = (byte) i;
        Files.write(pdf, pdfBytes);
        byte[] png = "PNGDATA".getBytes(StandardCharsets.US_ASCII);

        MessageBuilder.Message m = new MessageBuilder()
                .from("s@example.com").to("r@example.com").subject("files")
                .text("t").html("<img src=\"cid:logo.png\">")
                .attachment(MessageBuilder.Attachment.of("logo.png", "image/png", true, "logo.png", png))
                .attachment(MessageBuilder.Attachment.of("Prüfbericht.pdf", "application/pdf", false, null, pdf))
                .date(DATE).boundaryPrefix("B").build();
        byte[] bytes = m.toBytes();
        assertEquals(m.length(), bytes.length);
        String s = new String(bytes, StandardCharsets.UTF_8);
        assertLinesValid(s, MessageBuilder.FOLD_AT);

        assertEquals("multipart/mixed; boundary=\"B-mixed\"", header(m, "Content-Type"));
        int mixed = s.indexOf("--B-mixed\r\nContent-Type: multipart/related; boundary=\"B-related\"");
        int related = s.indexOf("--B-related\r\nContent-Type: multipart/alternative; boundary=\"B-alternative\"");
        int inline = s.indexOf("--B-related\r\nContent-Type: image/png;\r\n name=logo.png\r\n"
                + "Content-Disposition: inline;\r\n filename=logo.png\r\n"
                + "Content-ID: <logo.png>\r\n"
                + "Content-Transfer-Encoding: base64\r\n\r\n"
                + Base64.getEncoder().encodeToString(png) + "\r\n--B-related--");
        int attachment = s.indexOf("--B-mixed\r\nContent-Type: application/pdf;\r\n name*=UTF-8''Pr%C3%BCfbericht.pdf\r\n"
                + "Content-Disposition: attachment;\r\n filename*=UTF-8''Pr%C3%BCfbericht.pdf\r\n"
                + "Content-Transfer-Encoding: base64\r\n\r\n");
        assertTrue(mixed >= 0 && related > mixed && inline > related && attachment > inline, s);
        assertTrue(s.endsWith("\r\n--B-mixed--\r\n"));

        String b64 = s.substring(attachment).split("\r\n\r\n", 2)[1];
        b64 = b64.substring(0, b64.indexOf("\r\n--B-mixed--"));
        assertEquals(Base64.getEncoder().encodeToString(pdfBytes), b64.replace("\r\n", ""));
    }

    /** Top-level type plus the content types of the direct children, in order ("|" separated). */
    private static String shape(MessageBuilder.Message m) throws IOException {
        String s = new String(m.toBytes(), StandardCharsets.UTF_8);
        StringBuilder sb = new StringBuilder(header(m, "Content-Type").split(";")[0]);
        Matcher bm = Pattern.compile("boundary=\"([^\"]+)\"").matcher(header(m, "Content-Type"));
        if (bm.find()) {
            String delim = "\r\n--" + bm.group(1) + "\r\n";
            int i = 0;
            while ((i = s.indexOf(delim, i)) >= 0) {
                i += delim.length();
                String partHead = s.substring(i, s.indexOf("\r\n\r\n", i));
                Matcher ct = Pattern.compile("Content-Type: ([^;\r\n]+)").matcher(partHead);
                assertTrue(ct.find(), partHead);
                sb.append('|').append(ct.group(1));
            }
        }
        return sb.toString();
    }

    @Test
    void treeShapeDropsUnneededLayers() throws IOException {
        byte[] png = "PNG".getBytes(StandardCharsets.US_ASCII);
        java.util.function.Supplier<MessageBuilder> base = () -> new MessageBuilder()
                .from("s@example.com").to("r@example.com").date(DATE).boundaryPrefix("B");
        MessageBuilder.Attachment logo = MessageBuilder.Attachment.of("logo.png", "image/png", true, "logo.png", png);
        MessageBuilder.Attachment file = MessageBuilder.Attachment.of("a.pdf", "application/pdf", false, null, png);

        // text only
        assertEquals("text/plain", shape(base.get().text("t").build()));
        // html + inline: related [html, image]
        assertEquals("multipart/related|text/html|image/png",
                shape(base.get().html("<img src=\"cid:logo.png\">").attachment(logo).build()));
        // text + html + inline: related [alternative, image]
        assertEquals("multipart/related|multipart/alternative|image/png",
                shape(base.get().text("t").html("<img src=\"cid:logo.png\">").attachment(logo).build()));
        // text + file: mixed [text, pdf]
        assertEquals("multipart/mixed|text/plain|application/pdf",
                shape(base.get().text("t").attachment(file).build()));
        // text + html + file: mixed [alternative, pdf]
        assertEquals("multipart/mixed|multipart/alternative|application/pdf",
                shape(base.get().text("t").html("<p>h</p>").attachment(file).build()));
        // html + inline + file: mixed [related, pdf]
        assertEquals("multipart/mixed|multipart/related|application/pdf",
                shape(base.get().html("<img src=\"cid:logo.png\">").attachment(logo).attachment(file).build()));
        // text + html + inline + files: mixed [related, pdf, pdf]
        assertEquals("multipart/mixed|multipart/related|application/pdf|application/pdf",
                shape(base.get().text("t").html("<img src=\"cid:logo.png\">")
                        .attachment(logo).attachment(file).attachment(file).build()));
    }

    @Test
    void writeToFileMatchesStream(@TempDir Path dir) throws IOException {
        SendRequest r = request();
        r.text = "body";
        MessageBuilder.Message m = MessageBuilder.fromRequest(r, "h").date(DATE).build();
        Path out = dir.resolve("x.eml");
        m.writeTo(out);
        assertEquals(m.length(), Files.size(out));
        assertEquals(new String(m.toBytes(), StandardCharsets.UTF_8), Files.readString(out));
        assertFalse(Files.exists(dir.resolve("x.eml.tmp")));
    }

    @Test
    void attachmentContentTypeKeepsParametersAndDefaults() throws IOException {
        MessageBuilder.Message m = new MessageBuilder()
                .from("s@example.com").to("r@example.com").text("t")
                .attachment(MessageBuilder.Attachment.of("a.txt", "Text/Plain; charset=\"iso-8859-1\"; name=old", false, null, new byte[]{'x'}))
                .attachment(MessageBuilder.Attachment.of("b", null, false, null, new byte[0]))
                .boundaryPrefix("B").build();
        String s = new String(m.toBytes(), StandardCharsets.UTF_8);
        assertTrue(s.contains("Content-Type: text/plain;\r\n charset=iso-8859-1;\r\n name=a.txt\r\n"), s);
        assertTrue(s.contains("Content-Type: application/octet-stream;\r\n name=b\r\n"), s);
        assertEquals(m.length(), m.toBytes().length);
    }

    @Test
    void fromIsRequired() {
        assertThrows(IllegalStateException.class, () -> new MessageBuilder().to("a@example.com").build());
    }
}
