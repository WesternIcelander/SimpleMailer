package io.siggi.simplemailer.mime;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AttachmentFetcherTest {
    @TempDir
    Path dir;

    private TestHttpServer server;
    private Path target;

    @BeforeEach
    void start() throws Exception {
        server = new TestHttpServer();
        target = dir.resolve("0");
    }

    @AfterEach
    void stop() throws Exception {
        server.close();
    }

    private static byte[] bytes(int n) {
        byte[] b = new byte[n];
        for (int i = 0; i < n; i++) b[i] = (byte) (i * 31);
        return b;
    }

    private AttachmentFetcher.FetchException refused(AttachmentFetcher fetcher, String url, long max) {
        AttachmentFetcher.FetchException e = assertThrows(AttachmentFetcher.FetchException.class,
                () -> fetcher.fetch(url, target, max));
        assertFalse(Files.exists(target), "no file is left behind");
        return e;
    }

    // ---- successful downloads ----

    @Test
    void fetchesWithContentLength() throws Exception {
        byte[] body = bytes(5000);
        server.ok("/invoice.pdf", "application/pdf", body);
        AttachmentFetcher.Result r = server.fetcher().fetch(server.url("/invoice.pdf"), target, 10_000);
        assertArrayEquals(body, Files.readAllBytes(target));
        assertEquals(5000, r.size());
        assertEquals("application/pdf", r.contentType());
    }

    @Test
    void fetchesChunkedBody() throws Exception {
        server.route("/c", "HTTP/1.1 200 OK\r\nContent-Type: text/plain; charset=utf-8\r\n"
                + "Transfer-Encoding: chunked\r\n\r\n5;ext=1\r\nhello\r\n7\r\n, world\r\n0\r\nX-Trailer: y\r\n\r\n");
        AttachmentFetcher.Result r = server.fetcher().fetch(server.url("/c"), target, 100);
        assertEquals("hello, world", Files.readString(target));
        assertEquals("text/plain; charset=utf-8", r.contentType());
    }

    @Test
    void fetchesCloseDelimitedBodyAndSkipsInterimResponses() throws Exception {
        server.route("/e?x=1", "HTTP/1.1 100 Continue\r\n\r\nHTTP/1.0 200 OK\r\n\r\nuntil close");
        AttachmentFetcher.Result r = server.fetcher().fetch(server.url("/e?x=1"), target, 100);
        assertEquals("until close", Files.readString(target));
        assertNull(r.contentType());
        assertEquals(List.of("/e?x=1"), server.requests);
    }

    @Test
    void followsUpToThreeRedirects() throws Exception {
        server.redirect("/r1", server.url("/r2"));
        server.redirect("/r2", "/r3");                    // relative Location
        server.redirect("/r3", "final.bin");
        server.ok("/final.bin", "application/octet-stream", bytes(10));
        AttachmentFetcher.Result r = server.fetcher().fetch(server.url("/r1"), target, 100);
        assertArrayEquals(bytes(10), Files.readAllBytes(target));
        assertEquals("/final.bin", r.finalUrl().getPath());
    }

    // ---- refusals ----

    @Test
    void refusesMoreThanThreeRedirects() {
        server.redirect("/r1", "/r2");
        server.redirect("/r2", "/r3");
        server.redirect("/r3", "/r4");
        server.redirect("/r4", "/r5");
        server.ok("/r5", "text/plain", bytes(1));
        assertTrue(refused(server.fetcher(), server.url("/r1"), 100).getMessage().contains("redirects"));
        assertFalse(server.requests.contains("/r5"));
    }

    @Test
    void refusesRedirectToLoopback() {
        server.ok("/secret", "text/plain", "internal".getBytes(StandardCharsets.UTF_8));
        server.redirect("/r", "http://127.0.0.1:" + server.port() + "/secret");
        AttachmentFetcher.FetchException e = refused(server.fetcher(), server.url("/r"), 100);
        assertTrue(e.getMessage().contains("non-public address"), e.getMessage());
        assertEquals(List.of("/r"), server.requests, "the loopback target is never contacted");
    }

    @Test
    void refusesRedirectToHostResolvingToPrivateAddress() {
        server.redirect("/r", "http://" + TestHttpServer.PRIVATE_HOST + ":" + server.port() + "/x");
        assertTrue(refused(server.fetcher(), server.url("/r"), 100).getMessage().contains("10.1.2.3"));
    }

    @Test
    void refusesPrivateAndLoopbackUrlsDirectly() {
        AttachmentFetcher f = server.fetcher();
        refused(f, "http://127.0.0.1:" + server.port() + "/", 100);
        refused(f, "http://localhost:" + server.port() + "/", 100);
        refused(f, "http://[::1]:" + server.port() + "/", 100);
        refused(f, "http://169.254.169.254/latest/meta-data/", 100);
        assertEquals(0, server.hits.get());
    }

    @Test
    void refusesHttpUnlessAllowed() {
        AttachmentFetcher httpsOnly = server.fetcher(false, List.of(), Duration.ofSeconds(5));
        assertTrue(refused(httpsOnly, server.url("/x"), 100).getMessage().contains("only https"));
        refused(httpsOnly, "ftp://cdn.test/x", 100);
        // and a redirect from https to http is refused the same way (checked per hop); covered by check()
        assertEquals(0, server.hits.get());
    }

    @Test
    void refusesUserInfo() {
        refused(server.fetcher(), "http://user:pw@" + TestHttpServer.PUBLIC_HOST + ":" + server.port() + "/x", 100);
    }

    @Test
    void appliesAllowlistToEveryHop() throws Exception {
        server.ok("/x", "text/plain", bytes(3));
        AttachmentFetcher wildcard = server.fetcher(true, List.of("*.test"), Duration.ofSeconds(5));
        wildcard.fetch(server.url("/x"), target, 100);
        Files.delete(target);

        AttachmentFetcher other = server.fetcher(true, List.of("cdn.example.com"), Duration.ofSeconds(5));
        assertTrue(refused(other, server.url("/x"), 100).getMessage().contains("allowlist"));

        AttachmentFetcher exact = server.fetcher(true, List.of("CDN.test"), Duration.ofSeconds(5));
        server.redirect("/away", "http://elsewhere.test/x");
        assertTrue(refused(exact, server.url("/away"), 100).getMessage().contains("allowlist"));

        assertTrue(wildcard.isAllowedHost("a.b.test"));
        assertFalse(wildcard.isAllowedHost("test"));
        assertFalse(wildcard.isAllowedHost("evil-test"));
    }

    @Test
    void refusesOversizeByContentLength() {
        server.ok("/big", "application/octet-stream", bytes(2000));
        assertTrue(refused(server.fetcher(), server.url("/big"), 1999).getMessage().contains("larger than 1999"));
    }

    @Test
    void refusesOversizeWithoutContentLength() {
        byte[] head = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n".getBytes(StandardCharsets.ISO_8859_1);
        StringBuilder chunks = new StringBuilder();
        for (int i = 0; i < 10; i++) chunks.append("100\r\n").append("a".repeat(256)).append("\r\n");
        chunks.append("0\r\n\r\n");
        byte[] raw = new byte[head.length + chunks.length()];
        System.arraycopy(head, 0, raw, 0, head.length);
        System.arraycopy(chunks.toString().getBytes(StandardCharsets.ISO_8859_1), 0, raw, head.length, chunks.length());
        server.route("/chunked", raw);
        refused(server.fetcher(), server.url("/chunked"), 1000);

        server.route("/close", "HTTP/1.0 200 OK\r\n\r\n" + "b".repeat(1001));
        refused(server.fetcher(), server.url("/close"), 1000);
    }

    @Test
    void failsOnErrorStatusAndTruncatedBody() {
        assertTrue(refused(server.fetcher(), server.url("/missing"), 100).getMessage().contains("HTTP 404"));
        server.route("/short", "HTTP/1.1 200 OK\r\nContent-Length: 50\r\n\r\nonly a few bytes");
        refused(server.fetcher(), server.url("/short"), 100);
    }

    @Test
    void timesOut() {
        server.route("/slow", new TestHttpServer.Stalled(
                "HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\n12345".getBytes(StandardCharsets.ISO_8859_1),
                Duration.ofSeconds(3), "67890".getBytes(StandardCharsets.ISO_8859_1)));
        AttachmentFetcher f = server.fetcher(true, List.of(), Duration.ofMillis(500));
        long start = System.nanoTime();
        assertTrue(refused(f, server.url("/slow"), 100).getMessage().contains("timed out"));
        assertTrue(System.nanoTime() - start < Duration.ofSeconds(2).toNanos());
    }

    // ---- address classification ----

    @Test
    void classifiesAddresses() throws Exception {
        for (String blocked : Arrays.asList("0.0.0.0", "10.0.0.1", "100.64.0.1", "127.0.0.1", "127.1.2.3",
                "169.254.169.254", "172.16.0.1", "172.31.255.255", "192.0.0.8", "192.168.1.1", "198.18.0.1",
                "224.0.0.1", "240.0.0.1", "255.255.255.255", "::", "::1", "fe80::1", "fc00::1", "fd12::1",
                "ff02::1", "::ffff:127.0.0.1", "::ffff:10.0.0.1", "::127.0.0.1", "64:ff9b::a00:1", "2002:a00:1::1",
                "2001:db8::1", "fec0::1")) {
            assertTrue(AttachmentFetcher.isBlockedAddress(InetAddress.getByName(blocked)), blocked);
        }
        for (String allowed : Arrays.asList("8.8.8.8", "1.1.1.1", "203.0.113.10", "100.128.0.1", "172.32.0.1",
                "2606:4700::1111", "64:ff9b::808:808", "2002:808:808::1")) {
            assertFalse(AttachmentFetcher.isBlockedAddress(InetAddress.getByName(allowed)), allowed);
        }
    }

    @Test
    void sanitisesContentType() {
        assertEquals("image/png", AttachmentFetcher.mediaType(" image/png "));
        assertEquals("text/plain; charset=utf-8", AttachmentFetcher.mediaType("text/plain; charset=utf-8"));
        assertNull(AttachmentFetcher.mediaType("garbage"));
        assertNull(AttachmentFetcher.mediaType(""));
    }
}
