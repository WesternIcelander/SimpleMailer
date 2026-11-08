package io.siggi.simplemailer.smtp;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTimeoutPreemptively;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SmtpClientTest {
    private static final Duration TIMEOUT = Duration.ofSeconds(5);
    private FakeSmtpServer server;

    @BeforeEach
    void start() throws IOException {
        server = new FakeSmtpServer();
    }

    @AfterEach
    void stop() throws IOException {
        server.close();
    }

    private SmtpClient connect() throws IOException {
        return SmtpClient.connect(server.address(), "fake.test", TIMEOUT, TIMEOUT);
    }

    private static byte[] bytes(String s) {
        return s.getBytes(StandardCharsets.UTF_8);
    }

    @Test
    void fullTransaction() throws IOException {
        byte[] message = bytes("Subject: hi\r\n\r\nHello\r\n");
        try (SmtpClient c = connect()) {
            assertEquals(220, c.greeting().code());
            SmtpResponse ehlo = c.ehlo("mail.example.com");
            assertTrue(ehlo.isPositive());
            assertTrue(c.isExtended());
            assertTrue(c.supports("size"));
            assertTrue(c.supports("8BITMIME"));
            assertTrue(c.supports("PIPELINING"));
            assertFalse(c.supports("STARTTLS"));
            assertEquals(1000000, c.maxMessageSize());

            assertEquals(250, c.mail("bounce+x@bounces.example.com", message.length).code());
            assertEquals(250, c.rcpt("a@x.test").code());
            assertEquals(250, c.rcpt("b@x.test").code());
            SmtpResponse data = c.data(new ByteArrayInputStream(message));
            assertEquals(250, data.code());
            assertEquals("2.0.0", data.enhancedStatus());
            c.quit();
        }
        assertEquals(List.of("EHLO mail.example.com", "MAIL FROM:<bounce+x@bounces.example.com> SIZE=" + message.length,
                "RCPT TO:<a@x.test>", "RCPT TO:<b@x.test>", "DATA", "QUIT"), server.commands);
        assertArrayEquals(message, server.messages.get(0));
    }

    @Test
    void transcriptRecordsCommandsAndReplies() throws IOException {
        try (SmtpClient c = connect()) {
            c.ehlo("h");
            c.mail("");
            c.data(new ByteArrayInputStream(bytes("x\r\n")));
            List<String> t = c.transcript();
            assertEquals("C: EHLO h", t.get(0));
            assertTrue(t.get(1).startsWith("S: 250 fake.test hello"));
            assertEquals("C: MAIL FROM:<>", t.get(2));
            assertTrue(t.contains("C: <message>"));
            assertEquals("S: 250 2.0.0 queued", t.get(t.size() - 1));
        }
    }

    @Test
    void sizeOmittedWhenNotAdvertised() throws IOException {
        server.handler = cmd -> cmd.startsWith("EHLO") ? "250 fake.test\r\n" : FakeSmtpServer.defaultReply(cmd);
        try (SmtpClient c = connect()) {
            c.ehlo("h");
            assertEquals(-1, c.maxMessageSize());
            c.mail("a@b.test", 100);
        }
        assertEquals("MAIL FROM:<a@b.test>", server.commands.get(1));
    }

    @Test
    void heloFallback() throws IOException {
        server.handler = cmd -> cmd.startsWith("EHLO") ? "502 5.5.1 no\r\n" : FakeSmtpServer.defaultReply(cmd);
        try (SmtpClient c = connect()) {
            SmtpResponse r = c.ehlo("h");
            assertEquals(250, r.code());
            assertFalse(c.isExtended());
            assertTrue(c.extensions().isEmpty());
        }
        assertEquals(List.of("EHLO h", "HELO h"), server.commands.subList(0, 2));
    }

    @Test
    void failureRepliesAreReturned() throws IOException {
        server.handler = cmd -> {
            if (cmd.equals("RCPT TO:<bad@x.test>")) return "550-5.1.1 The email account that you tried to reach\r\n550 5.1.1 does not exist\r\n";
            if (cmd.equals("RCPT TO:<later@x.test>")) return "451 4.3.0 try later\r\n";
            return FakeSmtpServer.defaultReply(cmd);
        };
        try (SmtpClient c = connect()) {
            c.ehlo("h");
            c.mail("a@b.test");
            SmtpResponse bad = c.rcpt("bad@x.test");
            assertTrue(bad.isPermanentFailure());
            assertEquals("5.1.1", bad.enhancedStatus());
            assertEquals(2, bad.lines().size());
            assertEquals("5.1.1 The email account that you tried to reach 5.1.1 does not exist", bad.message());
            SmtpResponse later = c.rcpt("later@x.test");
            assertTrue(later.isTransientFailure());
            assertEquals("4.3.0", later.enhancedStatus());
        }
    }

    @Test
    void dataRejectedBeforeContent() throws IOException {
        server.handler = cmd -> cmd.equals("DATA") ? "554 5.5.1 no valid recipients\r\n" : FakeSmtpServer.defaultReply(cmd);
        try (SmtpClient c = connect()) {
            c.ehlo("h");
            c.mail("a@b.test");
            SmtpResponse r = c.data(new ByteArrayInputStream(bytes("x\r\n")));
            assertEquals(554, r.code());
            // The connection is still in sync.
            assertEquals(250, c.rset().code());
        }
        assertTrue(server.messages.isEmpty());
    }

    @Test
    void dotStuffing() throws IOException {
        String body = ".leading\r\n..two\r\nmid.dle\r\n.\r\n.\r\nend";
        try (SmtpClient c = connect()) {
            c.ehlo("h");
            c.mail("a@b.test");
            c.rcpt("c@d.test");
            assertEquals(250, c.data(new ByteArrayInputStream(bytes(body))).code());
        }
        assertEquals("..leading\r\n...two\r\nmid.dle\r\n..\r\n..\r\nend\r\n.\r\n",
                new String(server.rawData.get(0), StandardCharsets.UTF_8));
        // Missing final CRLF was added; otherwise the message is unchanged.
        assertEquals(body + "\r\n", new String(server.messages.get(0), StandardCharsets.UTF_8));
    }

    @Test
    void dotStuffingAcrossWriteBoundaries() throws IOException {
        for (String s : List.of("", "a", ".", "\r\n", ".\r\n.", "a\r\n.b\r\n", "a\r\n.\r\n", "a\n.b\n")) {
            String expected = stuffSlowly(s);
            for (int chunk = 1; chunk <= Math.max(1, s.length()); chunk++) {
                ByteArrayOutputStream out = new ByteArrayOutputStream();
                SmtpClient.DotStuffingOutputStream d = new SmtpClient.DotStuffingOutputStream(out);
                byte[] b = bytes(s);
                for (int i = 0; i < b.length; i += chunk) d.write(b, i, Math.min(chunk, b.length - i));
                d.finish();
                assertEquals(expected, out.toString(StandardCharsets.UTF_8), "input " + s.replace("\r", "\\r").replace("\n", "\\n") + " chunk " + chunk);
            }
        }
    }

    /** Reference implementation, byte at a time. */
    private static String stuffSlowly(String s) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        SmtpClient.DotStuffingOutputStream d = new SmtpClient.DotStuffingOutputStream(out);
        for (byte b : bytes(s)) d.write(b);
        d.finish();
        String r = out.toString(StandardCharsets.UTF_8);
        // Sanity: every line starting with '.' in the input is doubled and the terminator is present.
        assertTrue(r.endsWith("\r\n.\r\n") || r.equals(".\r\n"));
        return r;
    }

    @Test
    void largeMessageStreams() throws IOException {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 50000; i++) sb.append(i % 7 == 0 ? "." : "").append("line ").append(i).append("\r\n");
        byte[] message = bytes(sb.toString());
        try (SmtpClient c = connect()) {
            c.ehlo("h");
            c.mail("a@b.test");
            c.rcpt("c@d.test");
            assertEquals(250, c.data(new ByteArrayInputStream(message)).code());
        }
        assertArrayEquals(message, server.messages.get(0));
    }

    @Test
    void rejectsLineBreaksAndBadAddresses() throws IOException {
        try (SmtpClient c = connect()) {
            c.ehlo("h");
            assertThrows(IllegalArgumentException.class, () -> c.mail("a@b.test>\r\nRCPT TO:<x@y>"));
            assertThrows(IllegalArgumentException.class, () -> c.rcpt("a b@c.test"));
            assertThrows(IllegalArgumentException.class, () -> c.rcpt(""));
            assertThrows(IllegalArgumentException.class, () -> c.ehlo("h\r\nQUIT"));
            assertEquals(250, c.noop().code());
        }
    }

    @Test
    void readTimeout() throws IOException {
        server.handler = cmd -> cmd.startsWith("MAIL") ? null : FakeSmtpServer.defaultReply(cmd);
        assertTimeoutPreemptively(Duration.ofSeconds(5), () -> {
            try (SmtpClient c = SmtpClient.connect(server.address(), "fake.test", TIMEOUT, Duration.ofMillis(300))) {
                c.ehlo("h");
                assertThrows(SocketTimeoutException.class, () -> c.mail("a@b.test"));
            }
        });
    }

    @Test
    void greetingTimeout() {
        server.silent = true;
        assertTimeoutPreemptively(Duration.ofSeconds(5), () -> {
            assertThrows(SocketTimeoutException.class,
                    () -> SmtpClient.connect(server.address(), "fake.test", TIMEOUT, Duration.ofMillis(300)));
        });
    }

    @Test
    void writeTimeoutWhenServerStopsReading() throws Exception {
        // A server that answers DATA with 354 and then never reads: the client's writes eventually block.
        try (ServerSocket ss = new ServerSocket(0, 1, InetAddress.getLoopbackAddress())) {
            ss.setReceiveBufferSize(4096);
            Thread.ofVirtual().start(() -> {
                try (Socket s = ss.accept()) {
                    s.getOutputStream().write(bytes("220 x\r\n"));
                    InputStream in = s.getInputStream();
                    // Read "DATA\r\n" then reply 354 and stop reading.
                    ByteArrayOutputStream seen = new ByteArrayOutputStream();
                    while (!seen.toString(StandardCharsets.US_ASCII).endsWith("DATA\r\n")) seen.write(in.read());
                    s.getOutputStream().write(bytes("354 go\r\n"));
                    Thread.sleep(10_000);
                } catch (Exception ignored) {
                }
            });
            InputStream endless = new InputStream() {
                @Override
                public int read() {
                    return 'x';
                }

                @Override
                public int read(byte[] b, int off, int len) {
                    for (int i = 0; i < len; i++) b[off + i] = (byte) (i % 80 == 79 ? '\n' : 'x');
                    return len;
                }
            };
            assertTimeoutPreemptively(Duration.ofSeconds(8), () -> {
                InetSocketAddress addr = new InetSocketAddress(InetAddress.getLoopbackAddress(), ss.getLocalPort());
                try (SmtpClient c = SmtpClient.connect(addr, "x", TIMEOUT, Duration.ofMillis(500))) {
                    assertEquals(354, c.command("DATA").code() == 354 ? 354 : -1);
                }
            });
            // A second connection is not possible on this single-use server, so test the write timeout with a
            // direct DATA call on a fresh server below.
        }
        try (ServerSocket ss = new ServerSocket(0, 1, InetAddress.getLoopbackAddress())) {
            ss.setReceiveBufferSize(4096);
            Thread.ofVirtual().start(() -> {
                try (Socket s = ss.accept()) {
                    s.getOutputStream().write(bytes("220 x\r\n"));
                    InputStream in = s.getInputStream();
                    ByteArrayOutputStream seen = new ByteArrayOutputStream();
                    while (!seen.toString(StandardCharsets.US_ASCII).endsWith("DATA\r\n")) seen.write(in.read());
                    s.getOutputStream().write(bytes("354 go\r\n"));
                    Thread.sleep(10_000);
                } catch (Exception ignored) {
                }
            });
            InputStream endless = new InputStream() {
                @Override
                public int read() {
                    return 'x';
                }

                @Override
                public int read(byte[] b, int off, int len) {
                    for (int i = 0; i < len; i++) b[off + i] = (byte) (i % 80 == 79 ? '\n' : 'x');
                    return len;
                }
            };
            assertTimeoutPreemptively(Duration.ofSeconds(8), () -> {
                InetSocketAddress addr = new InetSocketAddress(InetAddress.getLoopbackAddress(), ss.getLocalPort());
                try (SmtpClient c = SmtpClient.connect(addr, "x", TIMEOUT, Duration.ofMillis(500))) {
                    assertThrows(SocketTimeoutException.class, () -> c.data(endless));
                }
            });
        }
    }

    @Test
    void connectionClosedMidReply() throws IOException {
        server.handler = cmd -> cmd.startsWith("EHLO") ? "250-partial\r\n" : null;
        try (SmtpClient c = connect()) {
            // The server keeps the socket open but the reply never finishes; close from the server side.
            server.close();
            assertThrows(IOException.class, () -> c.ehlo("h"));
        }
    }

    @Test
    void malformedReplies() throws IOException {
        for (String bad : List.of("hello\r\n", "25\r\n", "250x\r\n", "999 nope\r\n", "250-a\r\n251 b\r\n")) {
            server.handler = cmd -> cmd.startsWith("NOOP") ? bad : FakeSmtpServer.defaultReply(cmd);
            try (SmtpClient c = connect()) {
                assertThrows(SmtpClient.SmtpProtocolException.class, c::noop, bad);
            }
        }
    }

    @Test
    void closedClientRefusesCommands() throws IOException {
        SmtpClient c = connect();
        c.quit();
        assertThrows(IOException.class, c::noop);
    }

    @Test
    void responseHelpers() {
        SmtpResponse r = new SmtpResponse(250, "2.1.5 OK");
        assertTrue(r.isPositive());
        assertEquals("2.1.5", r.enhancedStatus());
        assertEquals("250 2.1.5 OK", r.toString());
        assertNull(new SmtpResponse(550, "no enhanced code").enhancedStatus());
        assertNull(new SmtpResponse(550, "2.0.0 mismatched class").enhancedStatus());
        assertTrue(new SmtpResponse(354, "go").isIntermediate());
        assertEquals("", new SmtpResponse(250, List.of()).message());
        assertThrows(IllegalArgumentException.class, () -> new SmtpResponse(199, "x"));
    }
}
