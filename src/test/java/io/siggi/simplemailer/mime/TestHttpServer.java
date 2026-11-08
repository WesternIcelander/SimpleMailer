package io.siggi.simplemailer.mime;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * A tiny scripted HTTP server on 127.0.0.1 for the attachment fetch tests. Each path maps to the raw bytes written
 * back (status line, headers and body) and the connection is then closed.
 *
 * <p>{@link #fetcher} builds an {@link AttachmentFetcher} whose resolver maps {@link #PUBLIC_HOST} to a public
 * documentation address ({@link #PUBLIC_IP}) and whose connector routes that address to this server, so the real
 * SSRF guard is in force: anything that really resolves to 127.0.0.1 is refused.
 */
final class TestHttpServer implements AutoCloseable {
    static final String PUBLIC_HOST = "cdn.test";
    static final String PUBLIC_IP = "203.0.113.10";
    /** Resolves to a private address. */
    static final String PRIVATE_HOST = "intranet.test";

    /** A response that is sent in pieces, with a delay before the rest. */
    record Stalled(byte[] first, Duration delay, byte[] rest) {
    }

    private final ServerSocket server;
    private final Map<String, Object> routes = new ConcurrentHashMap<>();
    final List<String> requests = new CopyOnWriteArrayList<>();
    final AtomicInteger hits = new AtomicInteger();

    TestHttpServer() throws IOException {
        server = new ServerSocket(0, 50, InetAddress.getLoopbackAddress());
        Thread.ofVirtual().start(this::acceptLoop);
    }

    int port() {
        return server.getLocalPort();
    }

    void route(String path, String raw) {
        routes.put(path, raw.getBytes(StandardCharsets.ISO_8859_1));
    }

    void route(String path, byte[] raw) {
        routes.put(path, raw);
    }

    void route(String path, Stalled stalled) {
        routes.put(path, stalled);
    }

    /** {@code 200 OK} with Content-Length and Content-Type. */
    void ok(String path, String contentType, byte[] body) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.writeBytes(("HTTP/1.1 200 OK\r\nContent-Type: " + contentType + "\r\nContent-Length: " + body.length
                + "\r\n\r\n").getBytes(StandardCharsets.ISO_8859_1));
        out.writeBytes(body);
        routes.put(path, out.toByteArray());
    }

    void redirect(String path, String location) {
        route(path, "HTTP/1.1 302 Found\r\nLocation: " + location + "\r\nContent-Length: 0\r\n\r\n");
    }

    String url(String path) {
        return "http://" + PUBLIC_HOST + ":" + port() + path;
    }

    AttachmentFetcher fetcher(boolean allowHttp, List<String> allowlist, Duration timeout) {
        return new AttachmentFetcher(allowHttp, allowlist, Duration.ofSeconds(5), timeout, this::resolve,
                this::connect, (javax.net.ssl.SSLSocketFactory) javax.net.ssl.SSLSocketFactory.getDefault());
    }

    AttachmentFetcher fetcher() {
        return fetcher(true, List.of(), Duration.ofSeconds(10));
    }

    private InetAddress[] resolve(String host) throws UnknownHostException {
        return switch (host) {
            case PUBLIC_HOST -> new InetAddress[]{InetAddress.getByName(PUBLIC_IP)};
            case PRIVATE_HOST -> new InetAddress[]{InetAddress.getByName("10.1.2.3")};
            default -> InetAddress.getAllByName(host);
        };
    }

    private Socket connect(InetAddress address, int port, int timeout) throws IOException {
        if (address.getHostAddress().equals(PUBLIC_IP) || address.isLoopbackAddress()) {
            // a loopback connect only happens if the guard let it through; tests assert that it never does
            Socket s = new Socket();
            s.connect(new java.net.InetSocketAddress(InetAddress.getLoopbackAddress(), port), timeout);
            return s;
        }
        throw new IOException("test connector: no route to " + address.getHostAddress());
    }

    private void acceptLoop() {
        while (!server.isClosed()) {
            try {
                Socket s = server.accept();
                Thread.ofVirtual().start(() -> handle(s));
            } catch (IOException e) {
                return;
            }
        }
    }

    private void handle(Socket s) {
        try (s) {
            InputStream in = s.getInputStream();
            String requestLine = readLine(in);
            String line;
            while ((line = readLine(in)) != null && !line.isEmpty()) {
                // skip request headers
            }
            hits.incrementAndGet();
            String path = requestLine == null ? "" : requestLine.split(" ")[1];
            requests.add(path);
            OutputStream out = s.getOutputStream();
            Object response = routes.get(path);
            if (response == null) {
                out.write("HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n".getBytes(StandardCharsets.ISO_8859_1));
            } else if (response instanceof byte[] raw) {
                out.write(raw);
            } else if (response instanceof Stalled st) {
                out.write(st.first);
                out.flush();
                Thread.sleep(st.delay.toMillis());
                out.write(st.rest);
            }
            out.flush();
        } catch (IOException | InterruptedException ignored) {
        }
    }

    private static String readLine(InputStream in) throws IOException {
        ByteArrayOutputStream b = new ByteArrayOutputStream();
        int c;
        while ((c = in.read()) >= 0 && c != '\n') b.write(c);
        if (c < 0 && b.size() == 0) return null;
        String s = b.toString(StandardCharsets.ISO_8859_1);
        return s.endsWith("\r") ? s.substring(0, s.length() - 1) : s;
    }

    @Override
    public void close() throws IOException {
        server.close();
    }
}
