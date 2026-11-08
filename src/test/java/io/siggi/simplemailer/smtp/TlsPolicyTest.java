package io.siggi.simplemailer.smtp;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManagerFactory;
import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.Closeable;
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
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class TlsPolicyTest {
    private static final Duration TIMEOUT = Duration.ofSeconds(5);
    private static final char[] PASSWORD = "changeit".toCharArray();
    private static final String MX = "mx.test";

    @TempDir
    static Path tmp;
    private static SSLContext serverContext;
    /** Trusts only the self-signed test certificate. */
    private static SSLContext trustingContext;

    private TlsServer server;

    @BeforeAll
    static void createCertificate() throws Exception {
        Path ks = tmp.resolve("server.p12");
        String keytool = Path.of(System.getProperty("java.home"), "bin", "keytool").toString();
        Process p = new ProcessBuilder(keytool, "-genkeypair", "-alias", "mx", "-keyalg", "RSA", "-keysize", "2048",
                "-dname", "CN=" + MX, "-ext", "SAN=dns:" + MX, "-validity", "2", "-storetype", "PKCS12",
                "-keystore", ks.toString(), "-storepass", "changeit", "-keypass", "changeit")
                .redirectErrorStream(true).start();
        String output = new String(p.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        assertTrue(p.waitFor(60, TimeUnit.SECONDS));
        assertEquals(0, p.exitValue(), output);

        KeyStore store = KeyStore.getInstance("PKCS12");
        try (InputStream in = Files.newInputStream(ks)) {
            store.load(in, PASSWORD);
        }
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(store, PASSWORD);
        serverContext = SSLContext.getInstance("TLS");
        serverContext.init(kmf.getKeyManagers(), null, null);

        KeyStore trust = KeyStore.getInstance("PKCS12");
        trust.load(null, null);
        trust.setCertificateEntry("mx", store.getCertificate("mx"));
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(trust);
        trustingContext = SSLContext.getInstance("TLS");
        trustingContext.init(null, tmf.getTrustManagers(), null);
    }

    @BeforeEach
    void start() throws IOException {
        server = new TlsServer();
    }

    @AfterEach
    void stop() throws IOException {
        server.close();
    }

    private SmtpClient connect(String name) throws IOException {
        SmtpClient c = SmtpClient.connect(server.address(), name, TIMEOUT, TIMEOUT);
        assertTrue(c.ehlo("client.example.com").isPositive());
        return c;
    }

    private Result negotiate(boolean requireTls, boolean verify) throws IOException {
        return negotiate(requireTls, verify, trustingContext, MX);
    }

    private Result negotiate(boolean requireTls, boolean verify, SSLContext ctx, String name) throws IOException {
        SmtpClient c = connect(name);
        TlsPolicy.Result r = new TlsPolicy(requireTls, verify, ctx).negotiate(c, "client.example.com");
        return new Result(c, r);
    }

    private record Result(SmtpClient client, TlsPolicy.Result tls) {
    }

    @Test
    void opportunisticWithoutStartTlsStaysPlaintext() throws IOException {
        server.advertise = false;
        Result r = negotiate(false, false);
        assertEquals(TlsPolicy.Status.PLAINTEXT, r.tls().status());
        assertNull(r.tls().errorCode());
        // The connection is still usable.
        assertEquals(250, r.client().mail("a@b.test").code());
        r.client().quit();
        assertFalse(server.commands.contains("STARTTLS"));
    }

    @Test
    void requireTlsWithoutStartTlsFails() throws IOException {
        server.advertise = false;
        Result r = negotiate(true, false);
        assertEquals(TlsPolicy.Status.FAILED, r.tls().status());
        assertEquals(TlsPolicy.TLS_REQUIRED_NOT_AVAILABLE, r.tls().errorCode());
        assertFalse(r.tls().retryWithoutTls());
        r.client().quit();
    }

    @Test
    void startTlsRefused() throws IOException {
        server.startTlsReply = "454 4.7.0 TLS not available\r\n";
        Result opportunistic = negotiate(false, false);
        assertEquals(TlsPolicy.Status.PLAINTEXT, opportunistic.tls().status());
        opportunistic.client().quit();

        Result required = negotiate(true, false);
        assertEquals(TlsPolicy.TLS_REQUIRED_NOT_AVAILABLE, required.tls().errorCode());
        required.client().quit();
    }

    @Test
    void opportunisticUpgradesWithSelfSignedCertWhenNotVerifying() throws Exception {
        // Default trust store: the self-signed cert would not verify, but verification is off.
        Result r = negotiate(false, false, SSLContext.getDefault(), "unrelated.name");
        assertEquals(TlsPolicy.Status.ENCRYPTED, r.tls().status());
        assertFalse(r.tls().verified());
        assertNotNull(r.tls().protocol());
        assertNotNull(r.tls().cipherSuite());
        assertTrue(r.tls().ehlo().isPositive());
        assertFalse(r.client().supports("STARTTLS"), "extensions are re-read over TLS");
        sendMessage(r.client());
        assertEquals(List.of("EHLO client.example.com", "STARTTLS", "EHLO client.example.com",
                "MAIL FROM:<a@b.test>", "RCPT TO:<c@d.test>", "DATA", "QUIT"), server.commands);
        assertEquals(List.of(false, false, true, true, true, true, true), server.overTls);
    }

    @Test
    void requireAndVerifyWithTrustedCertificate() throws IOException {
        Result r = negotiate(true, true);
        assertEquals(TlsPolicy.Status.ENCRYPTED, r.tls().status());
        assertTrue(r.tls().verified());
        sendMessage(r.client());
        assertTrue(r.client().transcript().stream().anyMatch(l -> l.contains("certificate verified")));
    }

    @Test
    void verifyFailsForUntrustedCertificate() throws Exception {
        Result r = negotiate(true, true, SSLContext.getDefault(), MX);
        assertEquals(TlsPolicy.Status.FAILED, r.tls().status());
        assertEquals(TlsPolicy.TLS_CERT_INVALID, r.tls().errorCode());
        assertFalse(r.tls().retryWithoutTls());
    }

    @Test
    void verifyFailsForHostNameMismatch() throws IOException {
        Result r = negotiate(true, true, trustingContext, "other.test");
        assertEquals(TlsPolicy.TLS_CERT_INVALID, r.tls().errorCode());
    }

    @Test
    void opportunisticVerificationFailureAllowsPlaintextRetry() throws Exception {
        Result r = negotiate(false, true, SSLContext.getDefault(), MX);
        assertEquals(TlsPolicy.Status.FAILED, r.tls().status());
        assertEquals(TlsPolicy.TLS_CERT_INVALID, r.tls().errorCode());
        assertTrue(r.tls().retryWithoutTls());
    }

    @Test
    void handshakeFailure() throws IOException {
        server.breakHandshake = true;
        Result required = negotiate(true, false);
        assertEquals(TlsPolicy.TLS_REQUIRED_NOT_AVAILABLE, required.tls().errorCode());
        assertFalse(required.tls().retryWithoutTls());

        Result opportunistic = negotiate(false, false);
        assertEquals(TlsPolicy.TLS_HANDSHAKE_FAILED, opportunistic.tls().errorCode());
        assertTrue(opportunistic.tls().retryWithoutTls());
    }

    @Test
    void plaintextInjectedAfterStartTlsIsRejected() throws IOException {
        server.startTlsReply = "220 2.0.0 go ahead\r\n250 injected\r\n";
        Result r = negotiate(true, false);
        assertEquals(TlsPolicy.Status.FAILED, r.tls().status());
        assertEquals(TlsPolicy.TLS_REQUIRED_NOT_AVAILABLE, r.tls().errorCode());
    }

    @Test
    void plaintextDeliveryWithoutStartTls() throws IOException {
        server.advertise = false;
        Result r = negotiate(false, true);
        assertEquals(TlsPolicy.Status.PLAINTEXT, r.tls().status());
        assertFalse(r.tls().encrypted());
        sendMessage(r.client());
        assertEquals(List.of("EHLO client.example.com", "MAIL FROM:<a@b.test>", "RCPT TO:<c@d.test>", "DATA", "QUIT"),
                server.commands);
        assertFalse(server.overTls.contains(true));
    }

    @Test
    void opportunisticCertificateFailureThenPlaintextRetrySucceeds() throws Exception {
        Result failed = negotiate(false, true, SSLContext.getDefault(), MX);
        assertTrue(failed.tls().retryWithoutTls());
        failed.client().quit();

        // The caller reconnects to the same MX and sends without STARTTLS.
        server.commands.clear();
        server.overTls.clear();
        SmtpClient retry = connect(MX);
        sendMessage(retry);
        assertFalse(server.commands.contains("STARTTLS"));
        assertFalse(server.overTls.contains(true));
    }

    @Test
    void plaintextInjectedAfterStartTlsOpportunistic() throws IOException {
        server.startTlsReply = "220 2.0.0 go ahead\r\n250 injected\r\n";
        Result r = negotiate(false, false);
        assertEquals(TlsPolicy.Status.FAILED, r.tls().status());
        assertEquals(TlsPolicy.TLS_PROTOCOL_ERROR, r.tls().errorCode());
        assertTrue(r.tls().retryWithoutTls());
    }

    @Test
    void rejectionsOverTlsAreReturnedAsReplies() throws IOException {
        server.rcptReply = "550 5.1.1 no such user\r\n";
        Result r = negotiate(true, true);
        assertTrue(r.tls().encrypted());
        assertEquals(250, r.client().mail("a@b.test").code());
        SmtpResponse permanent = r.client().rcpt("c@d.test");
        assertEquals(550, permanent.code());
        assertTrue(permanent.isPermanentFailure());

        server.rcptReply = "451 4.3.0 try later\r\n";
        SmtpResponse temporary = r.client().rcpt("e@d.test");
        assertEquals(451, temporary.code());
        assertTrue(temporary.isTransientFailure());
        r.client().quit();
        assertTrue(server.overTls.get(server.overTls.size() - 1));
    }

    @Test
    void classifiesCertificateFailures() {
        assertTrue(TlsPolicy.isCertificateFailure(new javax.net.ssl.SSLHandshakeException("x",
                new java.security.cert.CertificateException("bad"))));
        assertFalse(TlsPolicy.isCertificateFailure(new javax.net.ssl.SSLHandshakeException("no ciphers")));
    }

    private void sendMessage(SmtpClient c) throws IOException {
        byte[] msg = "Subject: t\r\n\r\n.dot\r\n".getBytes(StandardCharsets.UTF_8);
        assertEquals(250, c.mail("a@b.test").code());
        assertEquals(250, c.rcpt("c@d.test").code());
        assertEquals(250, c.data(new ByteArrayInputStream(msg)).code());
        c.quit();
        assertArrayEquals(msg, server.lastMessage);
    }

    /** A tiny SMTP server that supports STARTTLS with the self-signed test certificate. */
    private static final class TlsServer implements Closeable {
        final ServerSocket serverSocket = new ServerSocket(0, 50, InetAddress.getLoopbackAddress());
        final List<String> commands = new CopyOnWriteArrayList<>();
        final List<Boolean> overTls = new CopyOnWriteArrayList<>();
        volatile boolean advertise = true;
        volatile String startTlsReply = "220 2.0.0 Ready to start TLS\r\n";
        volatile boolean breakHandshake;
        volatile String rcptReply = "250 OK\r\n";
        volatile byte[] lastMessage;

        TlsServer() throws IOException {
            Thread.ofVirtual().start(() -> {
                while (!serverSocket.isClosed()) {
                    try {
                        Socket s = serverSocket.accept();
                        Thread.ofVirtual().start(() -> handle(s));
                    } catch (IOException e) {
                        return;
                    }
                }
            });
        }

        InetSocketAddress address() {
            return new InetSocketAddress(InetAddress.getLoopbackAddress(), serverSocket.getLocalPort());
        }

        private void handle(Socket s) {
            Socket current = s;
            try {
                boolean tls = false;
                InputStream in = new BufferedInputStream(current.getInputStream());
                OutputStream out = current.getOutputStream();
                send(out, "220 mx.test ESMTP\r\n");
                String line;
                while ((line = readLine(in)) != null) {
                    commands.add(line);
                    overTls.add(tls);
                    String upper = line.toUpperCase();
                    if (upper.startsWith("EHLO")) {
                        send(out, advertise && !tls ? "250-mx.test\r\n250-SIZE 100000\r\n250 STARTTLS\r\n"
                                : "250-mx.test\r\n250 SIZE 100000\r\n");
                    } else if (upper.equals("STARTTLS")) {
                        send(out, startTlsReply);
                        if (!startTlsReply.startsWith("220") || startTlsReply.contains("injected")) continue;
                        if (breakHandshake) {
                            // Wait for the ClientHello, then answer with something that isn't TLS.
                            if (in.read() == -1) return;
                            out.write("this is not a TLS record\r\n".getBytes(StandardCharsets.US_ASCII));
                            out.flush();
                            return;
                        }
                        SSLSocket ssl = (SSLSocket) serverContext.getSocketFactory()
                                .createSocket(current, null, current.getPort(), true);
                        ssl.setUseClientMode(false);
                        current = ssl;
                        ssl.startHandshake();
                        tls = true;
                        in = new BufferedInputStream(ssl.getInputStream());
                        out = ssl.getOutputStream();
                    } else if (upper.equals("DATA")) {
                        send(out, "354 go\r\n");
                        lastMessage = readData(in);
                        send(out, "250 2.0.0 queued\r\n");
                    } else if (upper.equals("QUIT")) {
                        send(out, "221 bye\r\n");
                        return;
                    } else if (upper.startsWith("RCPT")) {
                        send(out, rcptReply);
                    } else if (upper.startsWith("MAIL")) {
                        send(out, "250 OK\r\n");
                    } else {
                        send(out, "502 unknown\r\n");
                    }
                }
            } catch (IOException ignored) {
            } finally {
                try {
                    current.close();
                } catch (IOException ignored) {
                }
            }
        }

        private static byte[] readData(InputStream in) throws IOException {
            ByteArrayOutputStream msg = new ByteArrayOutputStream();
            String line;
            while ((line = readLine(in)) != null && !line.equals(".")) {
                if (line.startsWith(".")) line = line.substring(1);
                msg.write((line + "\r\n").getBytes(StandardCharsets.UTF_8));
            }
            return msg.toByteArray();
        }

        private static void send(OutputStream out, String s) throws IOException {
            out.write(s.getBytes(StandardCharsets.UTF_8));
            out.flush();
        }

        private static String readLine(InputStream in) throws IOException {
            ByteArrayOutputStream buf = new ByteArrayOutputStream();
            int b;
            while ((b = in.read()) != -1) {
                if (b == '\n') {
                    String s = buf.toString(StandardCharsets.UTF_8);
                    return s.endsWith("\r") ? s.substring(0, s.length() - 1) : s;
                }
                buf.write(b);
            }
            return null;
        }

        @Override
        public void close() throws IOException {
            serverSocket.close();
        }
    }
}
