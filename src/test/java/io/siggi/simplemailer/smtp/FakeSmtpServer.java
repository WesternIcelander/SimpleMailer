package io.siggi.simplemailer.smtp;

import java.io.BufferedInputStream;
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
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.Function;

/**
 * A minimal in-process SMTP server for tests. Each received command line is passed to {@code handler}, which
 * returns the raw reply (one or more CRLF-terminated lines), or {@code null} to stay silent. After a 354 reply the
 * message is read up to {@code CRLF.CRLF}, un-dot-stuffed and recorded, and {@code dataReply} is sent.
 */
final class FakeSmtpServer implements Closeable {
    final ServerSocket serverSocket;
    final List<String> commands = new CopyOnWriteArrayList<>();
    final List<byte[]> messages = new CopyOnWriteArrayList<>();
    /** Raw DATA bytes as received on the wire, still dot-stuffed and including the terminator. */
    final List<byte[]> rawData = new CopyOnWriteArrayList<>();
    volatile String greeting = "220 fake.test ESMTP\r\n";
    volatile String dataReply = "250 2.0.0 queued\r\n";
    volatile Function<String, String> handler = FakeSmtpServer::defaultReply;
    /** If true, the server accepts the connection but never reads or writes anything. */
    volatile boolean silent;

    FakeSmtpServer() throws IOException {
        serverSocket = new ServerSocket(0, 50, InetAddress.getLoopbackAddress());
        Thread.ofVirtual().start(this::acceptLoop);
    }

    InetSocketAddress address() {
        return new InetSocketAddress(InetAddress.getLoopbackAddress(), serverSocket.getLocalPort());
    }

    static String defaultReply(String cmd) {
        String upper = cmd.toUpperCase();
        if (upper.startsWith("EHLO")) return "250-fake.test hello\r\n250-SIZE 1000000\r\n250-8BITMIME\r\n250 PIPELINING\r\n";
        if (upper.startsWith("HELO")) return "250 fake.test\r\n";
        if (upper.startsWith("MAIL")) return "250 2.1.0 OK\r\n";
        if (upper.startsWith("RCPT")) return "250 2.1.5 OK\r\n";
        if (upper.equals("DATA")) return "354 go ahead\r\n";
        if (upper.equals("QUIT")) return "221 2.0.0 bye\r\n";
        if (upper.equals("RSET") || upper.equals("NOOP")) return "250 2.0.0 OK\r\n";
        return "502 5.5.2 unknown command\r\n";
    }

    private void acceptLoop() {
        while (!serverSocket.isClosed()) {
            try {
                Socket s = serverSocket.accept();
                Thread.ofVirtual().start(() -> handle(s));
            } catch (IOException e) {
                return;
            }
        }
    }

    private void handle(Socket s) {
        try (s) {
            if (silent) {
                // Hold the connection open without reading until the client gives up.
                s.getInputStream().read(new byte[0]);
                while (!s.isClosed() && !serverSocket.isClosed()) Thread.sleep(50);
                return;
            }
            InputStream in = new BufferedInputStream(s.getInputStream());
            OutputStream out = s.getOutputStream();
            send(out, greeting);
            String line;
            while ((line = readLine(in)) != null) {
                commands.add(line);
                String reply = handler.apply(line);
                if (reply == null) continue;
                send(out, reply);
                if (reply.startsWith("354")) {
                    readData(in);
                    send(out, dataReply);
                }
                if (line.equalsIgnoreCase("QUIT")) return;
            }
        } catch (IOException | InterruptedException ignored) {
        }
    }

    private void readData(InputStream in) throws IOException {
        ByteArrayOutputStream raw = new ByteArrayOutputStream();
        ByteArrayOutputStream msg = new ByteArrayOutputStream();
        ByteArrayOutputStream lineBuf = new ByteArrayOutputStream();
        int b;
        while ((b = in.read()) != -1) {
            raw.write(b);
            lineBuf.write(b);
            if (b != '\n') continue;
            byte[] l = lineBuf.toByteArray();
            lineBuf.reset();
            if (l.length == 3 && l[0] == '.' && l[1] == '\r') break;
            int off = l.length > 0 && l[0] == '.' ? 1 : 0;
            msg.write(l, off, l.length - off);
        }
        rawData.add(raw.toByteArray());
        messages.add(msg.toByteArray());
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
                byte[] bytes = buf.toByteArray();
                int len = bytes.length > 0 && bytes[bytes.length - 1] == '\r' ? bytes.length - 1 : bytes.length;
                return new String(bytes, 0, len, StandardCharsets.UTF_8);
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
