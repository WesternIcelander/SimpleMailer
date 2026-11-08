package io.siggi.simplemailer.mime;

import io.siggi.simplemailer.config.Config;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class DkimSignerTest {
    private static KeyPair keys;
    private static final Clock CLOCK = Clock.fixed(Instant.ofEpochSecond(1700000000L), ZoneOffset.UTC);

    @BeforeAll
    static void generate() throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
        g.initialize(2048);
        keys = g.generateKeyPair();
    }

    private static final String MESSAGE = """
            From: Alice <alice@example.com>\r
            To: bob@example.net,\r
             \tcarol@example.org\r
            Subject:   Hello    there  \r
            Date: Mon, 13 Nov 2023 22:13:20 +0000\r
            Message-ID: <abc@mail.example.com>\r
            X-Unsigned: whatever\r
            MIME-Version: 1.0\r
            Content-Type: text/plain; charset=utf-8\r
            \r
            Hi Bob,  \r
            \r
            a  line\twith   spaces\r
            \r
            \r
            """;

    // ---- canonicalisation (RFC 6376 §3.4.6 example) ----

    @Test
    void relaxedHeaderMatchesRfcExample() {
        assertEquals("a:X", DkimSigner.relaxedHeader("A: X"));
        assertEquals("b:Y Z", DkimSigner.relaxedHeader("B : Y\t\r\n\tZ  "));
    }

    @Test
    void relaxedBodyMatchesRfcExample() throws IOException {
        assertEquals(" C\r\nD E\r\n", relaxedBody(" C \r\nD \t E\r\n\r\n\r\n"));
    }

    @Test
    void relaxedBodyEdgeCases() throws IOException {
        assertEquals("", relaxedBody(""));
        assertEquals("", relaxedBody("\r\n\r\n  \r\n"));
        assertEquals("x\r\n", relaxedBody("x"));                  // CRLF added
        assertEquals("x\r\n\r\ny\r\n", relaxedBody("x\r\n \t\r\ny  "));
        assertEquals("a\rb\r\n", relaxedBody("a\rb\r\n"));         // lone CR is content
        assertEquals("a\r\r\n", relaxedBody("a\r"));        // trailing lone CR is content
        assertEquals("a\r\nb\r\n", relaxedBody("a\nb\n"));         // bare LF tolerated
    }

    @Test
    void emptyBodyHashIsKnownValue() throws IOException {
        // SHA-256 of the empty string: the relaxed body hash of an empty body.
        assertEquals("47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=",
                Base64.getEncoder().encodeToString(DkimSigner.bodyHash(new ByteArrayInputStream(new byte[0]))));
    }

    @Test
    void bodyHashOfLargeBodyMatchesSimpleComputation() throws Exception {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 20000; i++) sb.append("line ").append(i).append(" \t with  ws \r\n");
        byte[] expected = MessageDigest.getInstance("SHA-256")
                .digest(referenceRelaxedBody(sb.toString()).getBytes(StandardCharsets.ISO_8859_1));
        assertArrayEquals(expected, DkimSigner.bodyHash(new ByteArrayInputStream(
                sb.toString().getBytes(StandardCharsets.ISO_8859_1))));
    }

    // ---- signing ----

    @Test
    void signatureVerifiesWithIndependentVerifier() throws Exception {
        DkimSigner signer = new DkimSigner("Example.com", "sel1", keys.getPrivate(), CLOCK);
        String header = signer.sign(MESSAGE.getBytes(StandardCharsets.UTF_8));

        assertTrue(header.startsWith("DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=example.com;"));
        assertTrue(header.endsWith("\r\n"));
        for (String line : header.split("\r\n")) assertTrue(line.length() <= 78, line);
        Map<String, String> tags = tags(header);
        assertEquals("sel1", tags.get("s"));
        assertEquals("1700000000", tags.get("t"));
        assertEquals("From:From:Subject:Date:Message-ID:To:MIME-Version:Content-Type", tags.get("h"));

        assertTrue(verify(header + MESSAGE, keys.getPublic()));
    }

    @Test
    void tamperedMessageFailsVerification() throws Exception {
        DkimSigner signer = new DkimSigner("example.com", "sel1", keys.getPrivate(), CLOCK);
        String header = signer.sign(MESSAGE.getBytes(StandardCharsets.UTF_8));
        assertFalse(verify(header + MESSAGE.replace("Hello", "Hullo"), keys.getPublic()));
        assertFalse(verify(header + MESSAGE.replace("Hi Bob", "Hi Rob"), keys.getPublic()));
        // An extra From can't be prepended: From is oversigned.
        assertFalse(verify(header + "From: mallory@evil.test\r\n" + MESSAGE, keys.getPublic()));
        // Unsigned headers and whitespace changes are tolerated by relaxed/relaxed.
        assertTrue(verify(header + MESSAGE.replace("X-Unsigned: whatever", "X-Unsigned: other")
                .replace("a  line", "a line"), keys.getPublic()));
    }

    @Test
    void signsRepeatedHeadersBottomUpAndHandlesNoBody() throws Exception {
        String msg = "Received: x\r\nTo: a@x.com\r\nFrom: f@example.com\r\nTo: b@x.com\r\nSubject: s\r\n\r\n";
        DkimSigner signer = new DkimSigner("example.com", "s", keys.getPrivate(), CLOCK);
        String header = signer.sign(msg.getBytes(StandardCharsets.US_ASCII));
        assertEquals("From:From:Subject:To:To", tags(header).get("h"));
        assertEquals("47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=", tags(header).get("bh"));
        assertTrue(verify(header + msg, keys.getPublic()));
    }

    @Test
    void signingIsDeterministicAndSignsFiles(@TempDir Path dir) throws Exception {
        Path file = dir.resolve("m.eml");
        Files.writeString(file, MESSAGE);
        DkimSigner signer = new DkimSigner("example.com", "sel1", keys.getPrivate(), CLOCK);
        assertEquals(signer.sign(MESSAGE.getBytes(StandardCharsets.UTF_8)), signer.sign(file));
    }

    @Test
    void fromDomainIsTakenFromTheFromHeader() throws IOException {
        assertEquals("example.com", DkimSigner.fromDomain(new java.io.ByteArrayInputStream(MESSAGE.getBytes())));
        assertEquals("example.com", DkimSigner.addressDomain(" \"Doe, J <x@evil.test>\" <j@Example.COM>"));
        assertEquals("example.com", DkimSigner.addressDomain(" j@example.com (Jane <x@evil.test>)"));
        assertEquals("example.com", DkimSigner.addressDomain(" =?UTF-8?Q?J=C3=B6rg?=\r\n <j@example.com>"));
        assertEquals("a.test", DkimSigner.addressDomain(" a@a.test, b@b.test"));
        assertNull(DkimSigner.addressDomain(" undisclosed"));
        assertNull(DkimSigner.fromDomain(new java.io.ByteArrayInputStream("Subject: x\r\n\r\nFrom: a@b.c\r\n".getBytes())));
    }

    @Test
    void messageWithoutFromIsRejected() {
        DkimSigner signer = new DkimSigner("example.com", "s", keys.getPrivate(), CLOCK);
        assertThrows(IOException.class, () -> signer.sign("Subject: x\r\n\r\nbody\r\n".getBytes()));
    }

    // ---- known vector: RFC 8463 Appendix A (rsa-sha256, relaxed/relaxed) ----

    private static final String RFC8463_RSA_KEY = """
            -----BEGIN RSA PRIVATE KEY-----
            MIICXQIBAAKBgQDkHlOQoBTzWRiGs5V6NpP3idY6Wk08a5qhdR6wy5bdOKb2jLQi
            Y/J16JYi0Qvx/byYzCNb3W91y3FutACDfzwQ/BC/e/8uBsCR+yz1Lxj+PL6lHvqM
            KrM3rG4hstT5QjvHO9PzoxZyVYLzBfO2EeC3Ip3G+2kryOTIKT+l/K4w3QIDAQAB
            AoGAH0cxOhFZDgzXWhDhnAJDw5s4roOXN4OhjiXa8W7Y3rhX3FJqmJSPuC8N9vQm
            6SVbaLAE4SG5mLMueHlh4KXffEpuLEiNp9Ss3O4YfLiQpbRqE7Tm5SxKjvvQoZZe
            zHorimOaChRL2it47iuWxzxSiRMv4c+j70GiWdxXnxe4UoECQQDzJB/0U58W7RZy
            6enGVj2kWF732CoWFZWzi1FicudrBFoy63QwcowpoCazKtvZGMNlPWnC7x/6o8Gc
            uSe0ga2xAkEA8C7PipPm1/1fTRQvj1o/dDmZp243044ZNyxjg+/OPN0oWCbXIGxy
            WvmZbXriOWoSALJTjExEgraHEgnXssuk7QJBALl5ICsYMu6hMxO73gnfNayNgPxd
            WFV6Z7ULnKyV7HSVYF0hgYOHjeYe9gaMtiJYoo0zGN+L3AAtNP9huqkWlzECQE1a
            licIeVlo1e+qJ6Mgqr0Q7Aa7falZ448ccbSFYEPD6oFxiOl9Y9se9iYHZKKfIcst
            o7DUw1/hz2Ck4N5JrgUCQQCyKveNvjzkkd8HjYs0SwM0fPjK16//5qDZ2UiDGnOe
            uEzxBDAr518Z8VFbR41in3W4Y3yCDgQlLlcETrS+zYcL
            -----END RSA PRIVATE KEY-----
            """;

    /** p= of test._domainkey.football.example.com (RFC 8463 A.2). */
    private static final String RFC8463_RSA_PUBLIC =
            "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDkHlOQoBTzWR"
            + "iGs5V6NpP3idY6Wk08a5qhdR6wy5bdOKb2jLQiY/J16JYi0Qvx/byYzCNb3W91y3FutAC"
            + "DfzwQ/BC/e/8uBsCR+yz1Lxj+PL6lHvqMKrM3rG4hstT5QjvHO9PzoxZyVYLzBfO2EeC3"
            + "Ip3G+2kryOTIKT+l/K4w3QIDAQAB";

    private static final String RFC8463_SIGNATURE = "DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;\r\n"
            + " d=football.example.com; i=@football.example.com;\r\n"
            + " q=dns/txt; s=test; t=1528637909; h=from : to : subject :\r\n"
            + " date : message-id : from : subject : date;\r\n"
            + " bh=2jUSOH9NhtVGCQWNr9BrIAPreKQjO6Sn7XIkfJVOzv8=;\r\n"
            + " b=F45dVWDfMbQDGHJFlXUNB2HKfbCeLRyhDXgFpEL8GwpsRe0IeIixNTe3\r\n"
            + " DhCVlUrSjV4BwcVcOF6+FF3Zo9Rpo1tFOeS9mPYQTnGdaSGsgeefOsk2Jz\r\n"
            + " dA+L10TeYt9BgDfQNZtKdN1WO//KgIqXP7OdEFE4LjFYNcUxZQ4FADY+8=";

    private static final String RFC8463_B = "F45dVWDfMbQDGHJFlXUNB2HKfbCeLRyhDXgFpEL8GwpsRe0IeIixNTe3"
            + "DhCVlUrSjV4BwcVcOF6+FF3Zo9Rpo1tFOeS9mPYQTnGdaSGsgeefOsk2Jz"
            + "dA+L10TeYt9BgDfQNZtKdN1WO//KgIqXP7OdEFE4LjFYNcUxZQ4FADY+8=";

    private static final String RFC8463_BH = "2jUSOH9NhtVGCQWNr9BrIAPreKQjO6Sn7XIkfJVOzv8=";

    private static final String RFC8463_MESSAGE = """
            From: Joe SixPack <joe@football.example.com>\r
            To: Suzie Q <suzie@shopping.example.net>\r
            Subject: Is dinner ready?\r
            Date: Fri, 11 Jul 2003 21:00:37 -0700 (PDT)\r
            Message-ID: <20030712040037.46341.5F8J@football.example.com>\r
            \r
            Hi.\r
            \r
            We lost the game.  Are you hungry yet?\r
            \r
            Joe.\r
            \r
            """;

    private static PublicKey rfc8463PublicKey() throws Exception {
        return java.security.KeyFactory.getInstance("RSA")
                .generatePublic(new java.security.spec.X509EncodedKeySpec(Base64.getDecoder().decode(RFC8463_RSA_PUBLIC)));
    }

    @Test
    void rfc8463KnownVectorIsReproducedExactly() throws Exception {
        byte[] msg = RFC8463_MESSAGE.getBytes(StandardCharsets.US_ASCII);
        int split = RFC8463_MESSAGE.indexOf("\r\n\r\n") + 4;

        // Body hash, with the signer's streaming relaxed canonicaliser.
        byte[] bh = DkimSigner.bodyHash(new ByteArrayInputStream(msg, split, msg.length - split));
        assertEquals(RFC8463_BH, Base64.getEncoder().encodeToString(bh));

        // Header hash input, with the signer's header parsing, bottom-up selection and relaxed canonicaliser.
        List<DkimSigner.HeaderField> headers = DkimSigner.parseHeaders(
                RFC8463_MESSAGE.substring(0, split).getBytes(StandardCharsets.US_ASCII));
        List<String> h = List.of("from", "to", "subject", "date", "message-id", "from", "subject", "date");
        StringBuilder data = new StringBuilder();
        for (DkimSigner.HeaderField f : DkimSigner.selectHeaders(headers, h)) {
            data.append(DkimSigner.relaxedHeader(f.raw())).append("\r\n");
        }
        String sigWithoutB = RFC8463_SIGNATURE.substring(0, RFC8463_SIGNATURE.indexOf("b=F45") + 2);
        data.append(DkimSigner.relaxedHeader(sigWithoutB));

        // RSASSA-PKCS1-v1_5 is deterministic: signing with the RFC's key must give the RFC's b= byte for byte.
        PrivateKey key = DkimSigner.parsePrivateKey(RFC8463_RSA_KEY);
        Signature rsa = Signature.getInstance("SHA256withRSA");
        rsa.initSign(key);
        rsa.update(data.toString().getBytes(StandardCharsets.US_ASCII));
        assertEquals(RFC8463_B, Base64.getEncoder().encodeToString(rsa.sign()));

        // And the reference verifier used above accepts the published signed message.
        assertTrue(verify(RFC8463_SIGNATURE + "\r\n" + RFC8463_MESSAGE, rfc8463PublicKey()));
        assertFalse(verify(RFC8463_SIGNATURE + "\r\n" + RFC8463_MESSAGE.replace("hungry", "angry"),
                rfc8463PublicKey()));
    }

    @Test
    void signerWithRfc8463KeyVerifiesAgainstPublishedPublicKey() throws Exception {
        Clock clock = Clock.fixed(Instant.ofEpochSecond(1528637909L), ZoneOffset.UTC);
        DkimSigner signer = new DkimSigner("football.example.com", "test",
                DkimSigner.parsePrivateKey(RFC8463_RSA_KEY), clock);
        String header = signer.sign(RFC8463_MESSAGE.getBytes(StandardCharsets.US_ASCII));
        Map<String, String> t = tags(header);
        assertEquals(RFC8463_BH, t.get("bh"));
        assertEquals("1528637909", t.get("t"));
        assertEquals("From:From:Subject:Date:Message-ID:To", t.get("h"));
        assertTrue(verify(header + RFC8463_MESSAGE, rfc8463PublicKey()));
    }

    // ---- keys ----

    @Test
    void loadsPkcs8AndPkcs1PemKeys(@TempDir Path dir) throws Exception {
        byte[] pkcs8 = keys.getPrivate().getEncoded();
        Path p8 = dir.resolve("k8.pem");
        Files.writeString(p8, pem("PRIVATE KEY", pkcs8));
        assertArrayEquals(pkcs8, DkimSigner.loadPrivateKey(p8).getEncoded());

        // PKCS#1 body = the OCTET STRING inside PKCS#8: skip SEQ hdr, version (3), algId (15), OCTET STRING hdr.
        byte[] pkcs1 = extractPkcs1(pkcs8);
        Path p1 = dir.resolve("k1.pem");
        Files.writeString(p1, pem("RSA PRIVATE KEY", pkcs1));
        PrivateKey loaded = DkimSigner.loadPrivateKey(p1);
        assertArrayEquals(pkcs8, loaded.getEncoded());

        assertThrows(IOException.class, () -> DkimSigner.parsePrivateKey("nothing here"));
        assertThrows(IOException.class, () -> DkimSigner.parsePrivateKey(
                "-----BEGIN ENCRYPTED PRIVATE KEY-----\nAAAA\n-----END ENCRYPTED PRIVATE KEY-----\n"));
        assertThrows(IOException.class, () -> DkimSigner.parsePrivateKey(
                "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n"));
    }

    @Test
    void keysPerDomainFromConfig(@TempDir Path dir) throws Exception {
        Path p8 = dir.resolve("k.pem");
        Files.writeString(p8, pem("PRIVATE KEY", keys.getPrivate().getEncoded()));
        Map<String, Config.DkimKey> cfg = new LinkedHashMap<>();
        cfg.put("example.com", new Config.DkimKey("mail2026", p8.toString()));
        DkimSigner.Keys k = DkimSigner.Keys.load(cfg, CLOCK);
        assertNotNull(k.forDomain("EXAMPLE.com"));
        assertEquals("mail2026", k.forDomain("example.com").selector());
        assertNull(k.forDomain("other.com"));
        assertNull(k.forDomain(null));

        cfg.put("broken.com", new Config.DkimKey("s", dir.resolve("missing.pem").toString()));
        IOException e = assertThrows(IOException.class, () -> DkimSigner.Keys.load(cfg, CLOCK));
        assertTrue(e.getMessage().contains("broken.com"));
    }

    // ---- independent reference implementation (non-streaming, straight from RFC 6376) ----

    private static String relaxedBody(String body) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try (DkimSigner.RelaxedBodyOutputStream r = new DkimSigner.RelaxedBodyOutputStream(out)) {
            r.write(body.getBytes(StandardCharsets.ISO_8859_1));
        }
        return out.toString(StandardCharsets.ISO_8859_1);
    }

    private static String referenceRelaxedBody(String body) {
        String s = body.replaceAll("[ \t]+\r\n", "\r\n").replaceAll("[ \t]+", " ");
        while (s.endsWith("\r\n\r\n")) s = s.substring(0, s.length() - 2);
        if (s.equals("\r\n")) s = "";
        return s;
    }

    private static String referenceRelaxedHeader(String field) {
        int c = field.indexOf(':');
        String name = field.substring(0, c).trim().toLowerCase(Locale.ROOT);
        String value = field.substring(c + 1).replace("\r\n", "").replaceAll("[ \t]+", " ").trim();
        return name + ":" + value;
    }

    private static Map<String, String> tags(String dkimHeader) {
        String value = dkimHeader.substring(dkimHeader.indexOf(':') + 1).replaceAll("\\s+", "");
        Map<String, String> m = new LinkedHashMap<>();
        for (String t : value.split(";")) {
            if (t.isEmpty()) continue;
            int eq = t.indexOf('=');
            m.put(t.substring(0, eq), t.substring(eq + 1));
        }
        return m;
    }

    /** Verifies the first header (a DKIM-Signature) of {@code message} as a receiver would. */
    private static boolean verify(String message, PublicKey key) throws Exception {
        int split = message.indexOf("\r\n\r\n");
        String headerBlock = message.substring(0, split + 2);
        String body = message.substring(split + 4);
        List<String> fields = new ArrayList<>();
        for (String line : headerBlock.split("\r\n")) {
            if (line.startsWith(" ") || line.startsWith("\t")) {
                fields.set(fields.size() - 1, fields.get(fields.size() - 1) + "\r\n" + line);
            } else {
                fields.add(line);
            }
        }
        String sigField = fields.get(0);
        Map<String, String> t = tags(sigField);
        if (!t.get("a").equals("rsa-sha256") || !t.get("c").equals("relaxed/relaxed")) return false;

        byte[] bh = MessageDigest.getInstance("SHA-256")
                .digest(referenceRelaxedBody(body).getBytes(StandardCharsets.ISO_8859_1));
        if (!Base64.getEncoder().encodeToString(bh).equals(t.get("bh"))) return false;

        StringBuilder data = new StringBuilder();
        Map<String, Integer> used = new LinkedHashMap<>();
        for (String name : t.get("h").split(":")) {
            String lower = name.toLowerCase(Locale.ROOT);
            int skip = used.getOrDefault(lower, 0);
            used.put(lower, skip + 1);
            int seen = 0;
            for (int i = fields.size() - 1; i >= 1; i--) {
                String f = fields.get(i);
                if (f.substring(0, f.indexOf(':')).trim().equalsIgnoreCase(name) && seen++ == skip) {
                    data.append(referenceRelaxedHeader(f)).append("\r\n");
                    break;
                }
            }
        }
        // The signature field with the b= value removed (everything after "b=" up to ';' or the end).
        String withoutB = sigField.replaceAll("(?s)(\\bb=)[^;]*", "$1");
        data.append(referenceRelaxedHeader(withoutB));

        Signature rsa = Signature.getInstance("SHA256withRSA");
        rsa.initVerify(key);
        rsa.update(data.toString().getBytes(StandardCharsets.ISO_8859_1));
        return rsa.verify(Base64.getDecoder().decode(t.get("b")));
    }

    private static String pem(String label, byte[] der) {
        return "-----BEGIN " + label + "-----\n"
                + Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(der)
                + "\n-----END " + label + "-----\n";
    }

    private static byte[] extractPkcs1(byte[] pkcs8) {
        int pos = 1;
        pos += lengthBytes(pkcs8, pos);            // outer SEQUENCE header
        pos += 3;                                  // INTEGER 0
        pos += 2 + (pkcs8[pos + 1] & 0xff);        // AlgorithmIdentifier SEQUENCE
        pos++;                                     // OCTET STRING tag
        int len = readLength(pkcs8, pos);
        pos += lengthBytes(pkcs8, pos);
        byte[] out = new byte[len];
        System.arraycopy(pkcs8, pos, out, 0, len);
        return out;
    }

    private static int lengthBytes(byte[] der, int pos) {
        int b = der[pos] & 0xff;
        return b < 0x80 ? 1 : 1 + (b & 0x7f);
    }

    private static int readLength(byte[] der, int pos) {
        int b = der[pos] & 0xff;
        if (b < 0x80) return b;
        int len = 0;
        for (int i = 0; i < (b & 0x7f); i++) len = (len << 8) | (der[pos + 1 + i] & 0xff);
        return len;
    }
}
