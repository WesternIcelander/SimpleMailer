package io.siggi.simplemailer.inbound;

import io.siggi.simplemailer.Main;
import io.siggi.simplemailer.config.Config;
import io.siggi.simplemailer.model.Job;
import io.siggi.simplemailer.model.JobStatus;
import io.siggi.simplemailer.model.RecipientResult;
import io.siggi.simplemailer.model.SendRequest;
import io.siggi.simplemailer.smtp.SmtpClient;
import io.siggi.simplemailer.smtp.SmtpResponse;
import io.siggi.simplemailer.smtp.TlsPolicy;
import io.siggi.simplemailer.store.JobStore;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import javax.net.ssl.SSLContext;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class InboundSmtpServerTest {
    private static final String DOMAIN = "bounces.example.com";
    private static final Duration TIMEOUT = Duration.ofSeconds(10);

    @TempDir
    Path dataDir;

    private JobStore store;
    private VerpAddress verp;
    private BounceProcessor processor;
    private InboundSmtpServer server;

    @BeforeEach
    void setUp() throws Exception {
        store = new JobStore(dataDir);
        verp = new VerpAddress(DOMAIN, "bounce-secret");
        processor = new BounceProcessor(dataDir, store, verp, null);
    }

    @AfterEach
    void tearDown() throws Exception {
        if (server != null) server.close();
    }

    private InboundSmtpServer start(long maxBytes, int maxPerAddress, SSLContext tls) throws IOException {
        server = new InboundSmtpServer(processor, new InboundSmtpServer.Options("mx.bounces.test", maxBytes, 50,
                maxPerAddress, TIMEOUT, Duration.ofMinutes(1), tls));
        server.start(new ServerSocket(0, 50, InetAddress.getLoopbackAddress()));
        return server;
    }

    private SmtpClient connect() throws IOException {
        return SmtpClient.connect(new InetSocketAddress(InetAddress.getLoopbackAddress(), server.port()),
                "localhost", TIMEOUT, TIMEOUT);
    }

    private Job deliveredJob(String... rcpts) throws Exception {
        SendRequest req = new SendRequest();
        req.id = UUID.randomUUID().toString();
        req.from = "sender@example.test";
        req.to = List.of(rcpts);
        req.subject = "hi";
        req.text = "hello";
        Job job = Job.create(req, "hash", Instant.now(), JobStatus.QUEUED);
        store.create(job.id, "hash", () -> job);
        return store.update(job.id, j -> {
            Instant now = Instant.now();
            for (RecipientResult r : j.recipients) r.markDelivered(now, "mx.test", 250, "OK", true);
            j.recomputeStatus(now);
        }).orElseThrow();
    }

    private static String dsn(String address, String rcpt) {
        return """
                From: MAILER-DAEMON@mx.example.org
                To: %s
                Subject: Undelivered Mail Returned to Sender
                Message-ID: <dsn-%s@mx.example.org>
                MIME-Version: 1.0
                Content-Type: multipart/report; report-type=delivery-status; boundary="BND"

                --BND
                Content-Type: text/plain

                Your message could not be delivered.
                .a line starting with a dot

                --BND
                Content-Type: message/delivery-status

                Reporting-MTA: dns; mx.example.org

                Final-Recipient: rfc822; %s
                Action: failed
                Status: 5.1.1
                Diagnostic-Code: smtp; 550 5.1.1 user unknown

                --BND--
                """.formatted(address, UUID.randomUUID(), rcpt).replace("\n", "\r\n");
    }

    private static InputStream bytes(String s) {
        return new ByteArrayInputStream(s.getBytes(StandardCharsets.UTF_8));
    }

    @Test
    void acceptsBounceForKnownJobAndMarksRecipientBounced() throws Exception {
        start(1_000_000, 10, null);
        Job job = deliveredJob("a@x.test");
        String address = verp.encode(job.id, 0);
        try (SmtpClient c = connect()) {
            assertEquals(220, c.greeting().code());
            assertEquals(250, c.ehlo("mx.example.org").code());
            assertEquals(1_000_000L, c.maxMessageSize());
            assertFalse(c.supports("STARTTLS"));
            assertEquals(250, c.mail("").code());
            assertEquals(250, c.rcpt(address).code());
            SmtpResponse r = c.data(bytes(dsn(address, "a@x.test")));
            assertEquals(250, r.code(), r.toString());
            c.quit();
        }
        Job after = store.get(job.id).orElseThrow();
        assertEquals(JobStatus.BOUNCED, after.status);
        assertEquals(RecipientResult.Status.BOUNCED, after.recipient(0).status);
        assertEquals(1, after.bounces.size());
        Job.BounceRecord rec = after.bounces.get(0);
        assertEquals("smtp", rec.source);
        assertEquals("5.1.1", rec.status);
        // dot-stuffing was undone and line endings are CRLF
        String stored = Files.readString(dataDir.resolve(rec.file), StandardCharsets.UTF_8);
        assertTrue(stored.contains("\r\n.a line starting with a dot\r\n"), stored);
        assertFalse(stored.contains(".."));
        assertTrue(stored.endsWith("--BND--\r\n"));
    }

    @Test
    void rejectsEverythingButValidBounceAddresses() throws Exception {
        start(1_000_000, 10, null);
        Job job = deliveredJob("a@x.test");
        String good = verp.encode(job.id, 0);
        String badTag = good.replaceFirst("\\.[0-9a-f]{16}@", ".0000000000000000@");
        String otherDomain = good.replace(DOMAIN, "elsewhere.test");
        String unknownJob = verp.encode(UUID.randomUUID().toString(), 0);
        String unknownIndex = verp.encode(job.id, 5);
        try (SmtpClient c = connect()) {
            c.ehlo("relay.test");
            assertEquals(250, c.mail("spammer@relay.test").code());
            for (String rcpt : List.of("victim@gmail.com", "postmaster@" + DOMAIN, badTag, otherDomain, unknownJob,
                    unknownIndex)) {
                SmtpResponse r = c.rcpt(rcpt);
                assertEquals(550, r.code(), rcpt + " -> " + r);
            }
            // no valid recipient, so no DATA
            assertEquals(554, c.command("DATA").code());
            assertEquals(250, c.rcpt(good).code());
            c.quit();
        }
        assertTrue(store.get(job.id).orElseThrow().bounces.isEmpty());
    }

    @Test
    void enforcesCommandSequence() throws Exception {
        start(1_000_000, 10, null);
        Job job = deliveredJob("a@x.test");
        try (SmtpClient c = connect()) {
            assertEquals(503, c.mail("").code());
            assertEquals(501, c.command("EHLO").code());
            assertEquals(250, c.command("HELO client.test").code());
            assertEquals(503, c.rcpt(verp.encode(job.id, 0)).code());
            assertEquals(503, c.command("DATA").code());
            assertEquals(250, c.mail("").code());
            assertEquals(503, c.mail("").code());
            assertEquals(250, c.rset().code());
            assertEquals(503, c.rcpt(verp.encode(job.id, 0)).code());
            assertEquals(250, c.noop().code());
            assertEquals(500, c.command("BOGUS").code());
            assertEquals(502, c.command("VRFY postmaster").code());
            assertEquals(502, c.command("STARTTLS").code());
            assertEquals(501, c.command("MAIL FROM:nobrackets").code());
            assertEquals(555, c.command("MAIL FROM:<> AUTH=x").code());
            assertEquals(221, c.command("QUIT").code());
        }
    }

    @Test
    void enforcesSizeLimit() throws Exception {
        start(2000, 10, null);
        Job job = deliveredJob("a@x.test");
        String address = verp.encode(job.id, 0);
        try (SmtpClient c = connect()) {
            c.ehlo("mx.example.org");
            assertEquals(552, c.command("MAIL FROM:<> SIZE=2001").code());
            assertEquals(250, c.command("MAIL FROM:<> SIZE=100 BODY=8BITMIME").code());
            assertEquals(250, c.rcpt(address).code());
            String big = dsn(address, "a@x.test") + "x".repeat(3000) + "\r\n";
            assertEquals(552, c.data(bytes(big)).code());
            // the session is still in sync and usable
            assertEquals(250, c.noop().code());
            assertEquals(250, c.mail("").code());
            assertEquals(250, c.rcpt(address).code());
            assertEquals(250, c.data(bytes(dsn(address, "a@x.test"))).code());
            c.quit();
        }
        Job after = store.get(job.id).orElseThrow();
        assertEquals(1, after.bounces.size());
        assertEquals(JobStatus.BOUNCED, after.status);
    }

    @Test
    void dropsOverlongCommandLines() throws Exception {
        start(1_000_000, 10, null);
        try (Socket s = new Socket(InetAddress.getLoopbackAddress(), server.port())) {
            s.setSoTimeout(10_000);
            InputStream in = s.getInputStream();
            OutputStream out = s.getOutputStream();
            assertTrue(readLine(in).startsWith("220 "));
            out.write(("NOOP " + "x".repeat(5000) + "\r\n").getBytes(StandardCharsets.US_ASCII));
            out.flush();
            assertTrue(readLine(in).startsWith("500 "));
            String after;
            try {
                after = readLine(in);
            } catch (java.net.SocketException e) {
                after = null; // reset: the server closed with our unread bytes still queued
            }
            assertNull(after, "connection should be closed");
        }
    }

    @Test
    void dropsClientAfterTooManyErrors() throws Exception {
        start(1_000_000, 10, null);
        try (SmtpClient c = connect()) {
            SmtpResponse r = null;
            for (int i = 0; i < InboundSmtpServer.MAX_ERRORS; i++) r = c.command("BOGUS");
            assertEquals(421, r.code(), r.toString());
        }
    }

    @Test
    void limitsConnectionsPerAddress() throws Exception {
        start(1_000_000, 1, null);
        try (SmtpClient first = connect()) {
            assertEquals(220, first.greeting().code());
            try (SmtpClient second = connect()) {
                assertEquals(421, second.greeting().code());
            }
            assertEquals(250, first.noop().code());
        }
        // the slot is released once the first connection is gone
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5);
        while (true) {
            try (SmtpClient again = connect()) {
                if (again.greeting().code() == 220) break;
            }
            if (System.nanoTime() > deadline) throw new AssertionError("connection slot not released");
            Thread.sleep(20);
        }
    }

    @Test
    void offersStartTlsWhenCertificateConfigured() throws Exception {
        Path[] pem = writePemCertificate(dataDir, "mx.bounces.test");
        start(1_000_000, 10, InboundSmtpServer.loadTlsContext(pem[0], pem[1]));
        Job job = deliveredJob("a@x.test");
        String address = verp.encode(job.id, 0);
        try (SmtpClient c = connect()) {
            c.ehlo("mx.example.org");
            assertTrue(c.supports("STARTTLS"));
            // a client that starts a transaction and then upgrades must say EHLO again afterwards
            assertEquals(250, c.mail("").code());
            TlsPolicy.Result tls = new TlsPolicy(true, false).negotiate(c, "mx.example.org");
            assertTrue(tls.encrypted(), tls.toString());
            assertFalse(c.supports("STARTTLS"), "STARTTLS must not be offered again inside TLS");
            assertEquals(503, c.command("STARTTLS").code());
            assertEquals(250, c.mail("").code(), "transaction state is reset by STARTTLS");
            assertEquals(250, c.rcpt(address).code());
            assertEquals(250, c.data(bytes(dsn(address, "a@x.test"))).code());
            c.quit();
        }
        assertEquals(JobStatus.BOUNCED, store.get(job.id).orElseThrow().status);
    }

    @Test
    void rejectsPlaintextPipelinedAfterStartTls() throws Exception {
        Path[] pem = writePemCertificate(dataDir, "mx.bounces.test");
        start(1_000_000, 10, InboundSmtpServer.loadTlsContext(pem[0], pem[1]));
        try (Socket s = new Socket(InetAddress.getLoopbackAddress(), server.port())) {
            s.setSoTimeout(10_000);
            InputStream in = s.getInputStream();
            OutputStream out = s.getOutputStream();
            readLine(in);
            out.write("EHLO x.test\r\n".getBytes(StandardCharsets.US_ASCII));
            out.flush();
            String line;
            while ((line = readLine(in)) != null && line.startsWith("250-")) {
                // skip extension lines
            }
            out.write("STARTTLS\r\nMAIL FROM:<>\r\n".getBytes(StandardCharsets.US_ASCII));
            out.flush();
            Thread.sleep(100);
            String reply = readLine(in);
            assertNotNull(reply);
            // either the injected command was seen before the reply (554), or the reply came first; never a 250
            assertTrue(reply.startsWith("554 ") || reply.startsWith("220 "), reply);
        }
    }

    @Test
    void mainStartsSmtpIntakeOnlyWhenEnabled() throws Exception {
        Config config = new Config();
        config.dataDir = dataDir.resolve("main").toString();
        config.apiKeys = new ArrayList<>(List.of("sender-key"));
        config.bounces.domain = DOMAIN;
        config.bounces.secret = "bounce-secret";
        config.bounces.intake = new ArrayList<>(List.of("smtp"));
        config.heloName = "mx.bounces.test";
        try (Main main = Main.start(config, new ServerSocket(0, 50, InetAddress.getLoopbackAddress()),
                new ServerSocket(0, 50, InetAddress.getLoopbackAddress()))) {
            assertNotNull(main.inboundSmtpServer());
            try (SmtpClient c = SmtpClient.connect(new InetSocketAddress(InetAddress.getLoopbackAddress(),
                    main.inboundSmtpServer().port()), "localhost", TIMEOUT, TIMEOUT)) {
                assertEquals(220, c.greeting().code());
                assertTrue(c.greeting().message().contains("mx.bounces.test"));
                c.ehlo("x.test");
                assertEquals(250, c.mail("").code());
                assertEquals(550, c.rcpt("someone@example.org").code());
                c.quit();
            }
        }

        Config disabled = new Config();
        disabled.dataDir = dataDir.resolve("main2").toString();
        disabled.apiKeys = new ArrayList<>(List.of("sender-key"));
        try (Main main = Main.start(disabled, new ServerSocket(0, 50, InetAddress.getLoopbackAddress()), null)) {
            assertNull(main.inboundSmtpServer());
        }
    }

    // ---- helpers ----

    private static String readLine(InputStream in) throws IOException {
        StringBuilder sb = new StringBuilder();
        int b;
        while ((b = in.read()) != -1) {
            if (b == '\n') return sb.toString().replace("\r", "");
            sb.append((char) b);
        }
        return sb.isEmpty() ? null : sb.toString();
    }

    /** A self-signed certificate written as PEM files: {@code [cert, PKCS#8 key]}. */
    static Path[] writePemCertificate(Path dir, String hostName) throws Exception {
        Path ks = dir.resolve(hostName + ".p12");
        String keytool = Path.of(System.getProperty("java.home"), "bin", "keytool").toString();
        Process p = new ProcessBuilder(keytool, "-genkeypair", "-alias", "mx", "-keyalg", "RSA", "-keysize", "2048",
                "-dname", "CN=" + hostName, "-validity", "2", "-storetype", "PKCS12",
                "-keystore", ks.toString(), "-storepass", "changeit", "-keypass", "changeit")
                .redirectErrorStream(true).start();
        String output = new String(p.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        if (!p.waitFor(60, TimeUnit.SECONDS) || p.exitValue() != 0) throw new IOException("keytool: " + output);
        KeyStore store = KeyStore.getInstance("PKCS12");
        try (InputStream in = Files.newInputStream(ks)) {
            store.load(in, "changeit".toCharArray());
        }
        Base64.Encoder enc = Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.US_ASCII));
        Path cert = dir.resolve(hostName + ".crt");
        Path key = dir.resolve(hostName + ".key");
        Files.writeString(cert, "-----BEGIN CERTIFICATE-----\n"
                + enc.encodeToString(store.getCertificate("mx").getEncoded()) + "\n-----END CERTIFICATE-----\n");
        Files.writeString(key, "-----BEGIN PRIVATE KEY-----\n"
                + enc.encodeToString(store.getKey("mx", "changeit".toCharArray()).getEncoded())
                + "\n-----END PRIVATE KEY-----\n");
        return new Path[]{cert, key};
    }
}
