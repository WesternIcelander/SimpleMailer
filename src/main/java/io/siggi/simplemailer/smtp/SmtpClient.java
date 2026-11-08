package io.siggi.simplemailer.smtp;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.ByteArrayOutputStream;
import java.io.Closeable;
import java.io.EOFException;
import java.io.FilterOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;

/**
 * A minimal SMTP client for one connection to one mail exchanger (RFC 5321, PLAN.md §5).
 *
 * <p>Commands return the server's {@link SmtpResponse} rather than throwing on 4xx/5xx replies, so the caller can
 * classify them per recipient. Network failures, timeouts and protocol violations (e.g. a malformed reply) throw
 * {@link IOException}; after one the connection is unusable and should be {@link #close() closed}.
 *
 * <p>Timeouts: {@code connectTimeout} bounds the TCP connect; {@code readTimeout} bounds each wait for a reply and
 * also each blocking write (a watchdog closes the socket if the server stops reading), so a stalled server can't
 * hold a delivery thread forever.
 *
 * <p>{@link #data(InputStream)} expects a message with CRLF line endings (as produced by {@code MessageBuilder} and
 * {@code RawMessage}) and applies SMTP dot-stuffing (RFC 5321 §4.5.2) while streaming it.
 *
 * <p>Not thread-safe: one client is used by one delivery task.
 */
public final class SmtpClient implements Closeable {
    /** Longest reply line accepted (RFC 5321 allows 512 octets; real servers sometimes send more). */
    public static final int MAX_REPLY_LINE = 4096;
    /** Most lines accepted in one multi-line reply. */
    public static final int MAX_REPLY_LINES = 200;
    /** Most transcript entries kept; later ones are dropped. */
    public static final int MAX_TRANSCRIPT_ENTRIES = 200;

    private static final ScheduledExecutorService WATCHDOG = Executors.newSingleThreadScheduledExecutor(r -> {
        Thread t = new Thread(r, "smtp-write-watchdog");
        t.setDaemon(true);
        return t;
    });

    private final String serverName;
    private final Duration readTimeout;
    private Socket socket;
    private InputStream in;
    private OutputStream out;
    private SmtpResponse greeting;
    private final Map<String, String> extensions = new LinkedHashMap<>();
    private boolean extended;
    private final List<String> transcript = new ArrayList<>();
    private boolean closed;

    /**
     * Wraps an already connected socket and reads the server greeting.
     *
     * @param socket      a connected socket
     * @param serverName  the mail exchanger's host name (used for logging, and later for TLS)
     * @param readTimeout limit for each reply wait and each blocking write
     */
    public SmtpClient(Socket socket, String serverName, Duration readTimeout) throws IOException {
        this.serverName = Objects.requireNonNull(serverName);
        this.readTimeout = Objects.requireNonNull(readTimeout);
        try {
            attach(socket);
            greeting = readResponse();
        } catch (IOException | RuntimeException e) {
            closeQuietly(socket);
            throw e;
        }
    }

    /**
     * Connects to {@code address} and reads the greeting. A non-2xx greeting (e.g. {@code 554}) does not throw;
     * check {@link #greeting()}.
     */
    public static SmtpClient connect(InetSocketAddress address, String serverName, Duration connectTimeout,
                                     Duration readTimeout) throws IOException {
        Socket socket = new Socket();
        try {
            socket.connect(address, timeoutMillis(connectTimeout));
        } catch (IOException | RuntimeException e) {
            closeQuietly(socket);
            throw e;
        }
        return new SmtpClient(socket, serverName, readTimeout);
    }

    /** Replaces the transport, e.g. with a TLS socket layered over the current one after {@code STARTTLS}. */
    void attach(Socket socket) throws IOException {
        socket.setSoTimeout(timeoutMillis(readTimeout));
        this.socket = socket;
        this.in = new BufferedInputStream(socket.getInputStream());
        this.out = new BufferedOutputStream(new WatchdogOutputStream(socket.getOutputStream()), 16384);
    }

    Socket socket() {
        return socket;
    }

    /**
     * True if the server has sent bytes that haven't been read yet. Checked right after the {@code 220} reply to
     * {@code STARTTLS}: anything already buffered was sent in plaintext before the handshake and could be injected
     * by an attacker (CVE-2011-0411 style), so it must not be treated as part of the TLS session.
     */
    boolean hasBufferedInput() throws IOException {
        return in.available() > 0;
    }

    /** Adds a free-form note (e.g. the negotiated TLS parameters) to the transcript. */
    void note(String entry) {
        record("-- " + entry);
    }

    public String serverName() {
        return serverName;
    }

    /** The server's opening reply. */
    public SmtpResponse greeting() {
        return greeting;
    }

    /**
     * Sends {@code EHLO heloName}; if the server rejects it with 500/502 (command not recognised/implemented),
     * falls back to {@code HELO}. On success the advertised extensions are available from {@link #extensions()}.
     */
    public SmtpResponse ehlo(String heloName) throws IOException {
        checkArgument(heloName, "HELO name");
        extensions.clear();
        extended = false;
        SmtpResponse r = command("EHLO " + heloName);
        if (r.isPositive()) {
            extended = true;
            List<String> lines = r.lines();
            for (int i = 1; i < lines.size(); i++) {
                String line = lines.get(i).trim();
                if (line.isEmpty()) continue;
                int sp = line.indexOf(' ');
                String keyword = (sp < 0 ? line : line.substring(0, sp)).toUpperCase(Locale.ROOT);
                String params = sp < 0 ? "" : line.substring(sp + 1).trim();
                extensions.putIfAbsent(keyword, params);
            }
            return r;
        }
        if (r.code() == 500 || r.code() == 502) {
            return command("HELO " + heloName);
        }
        return r;
    }

    /** True if the last successful {@code EHLO} reply was extended (not a {@code HELO} fallback). */
    public boolean isExtended() {
        return extended;
    }

    /** Extensions from the last {@code EHLO} reply: upper-cased keyword → parameters (empty if none). */
    public Map<String, String> extensions() {
        return Collections.unmodifiableMap(extensions);
    }

    public boolean supports(String extension) {
        return extensions.containsKey(extension.toUpperCase(Locale.ROOT));
    }

    /** The server's {@code SIZE} limit, 0 if it advertised {@code SIZE} without a limit, -1 if not advertised. */
    public long maxMessageSize() {
        String p = extensions.get("SIZE");
        if (p == null) return -1;
        if (p.isEmpty()) return 0;
        try {
            return Long.parseLong(p.split("\\s+")[0]);
        } catch (NumberFormatException e) {
            return 0;
        }
    }

    /** {@code MAIL FROM:<reversePath>}; an empty reverse path sends the null sender {@code <>}. */
    public SmtpResponse mail(String reversePath) throws IOException {
        return mail(reversePath, -1);
    }

    /**
     * {@code MAIL FROM:<reversePath>}, with {@code SIZE=messageSize} if the server advertised {@code SIZE} and
     * {@code messageSize >= 0}.
     */
    public SmtpResponse mail(String reversePath, long messageSize) throws IOException {
        String path = reversePath == null ? "" : reversePath;
        checkAddress(path, true);
        StringBuilder cmd = new StringBuilder("MAIL FROM:<").append(path).append('>');
        if (messageSize >= 0 && supports("SIZE")) cmd.append(" SIZE=").append(messageSize);
        return command(cmd.toString());
    }

    /** {@code RCPT TO:<forwardPath>}. */
    public SmtpResponse rcpt(String forwardPath) throws IOException {
        checkAddress(forwardPath, false);
        return command("RCPT TO:<" + forwardPath + ">");
    }

    /**
     * Sends {@code DATA}; if the server answers {@code 354}, streams {@code message} with dot-stuffing, terminates it
     * with {@code CRLF.CRLF} and returns the final reply. Otherwise returns the {@code DATA} reply without sending
     * anything. A message that doesn't end in CRLF gets one appended.
     */
    public SmtpResponse data(InputStream message) throws IOException {
        SmtpResponse r = command("DATA");
        if (r.code() != 354) return r;
        DotStuffingOutputStream dot = new DotStuffingOutputStream(out);
        message.transferTo(dot);
        dot.finish();
        out.flush();
        record("C: <message>");
        return readAndRecord();
    }

    public SmtpResponse rset() throws IOException {
        return command("RSET");
    }

    public SmtpResponse noop() throws IOException {
        return command("NOOP");
    }

    /** Sends {@code QUIT} and closes the connection. Errors are ignored; the mail transaction is already over. */
    public void quit() {
        try {
            if (!closed) command("QUIT");
        } catch (IOException ignored) {
        } finally {
            close();
        }
    }

    /**
     * Sends one command line (CRLF appended) and reads the reply. Public so higher layers (e.g. STARTTLS handling)
     * can issue commands the client has no dedicated method for.
     */
    public SmtpResponse command(String line) throws IOException {
        checkArgument(line, "command");
        ensureOpen();
        out.write(line.getBytes(StandardCharsets.UTF_8));
        out.write('\r');
        out.write('\n');
        out.flush();
        record("C: " + line);
        return readAndRecord();
    }

    /** A summary of the conversation: each command ({@code C:}) and reply ({@code S:}); message content omitted. */
    public List<String> transcript() {
        return Collections.unmodifiableList(transcript);
    }

    @Override
    public void close() {
        closed = true;
        closeQuietly(socket);
    }

    // ---- internals ----

    private SmtpResponse readAndRecord() throws IOException {
        SmtpResponse r = readResponse();
        record("S: " + r);
        return r;
    }

    private void record(String entry) {
        if (transcript.size() < MAX_TRANSCRIPT_ENTRIES) transcript.add(entry);
    }

    private SmtpResponse readResponse() throws IOException {
        ensureOpen();
        List<String> lines = new ArrayList<>();
        int code = -1;
        while (true) {
            String line = readLine();
            if (line.length() < 3) throw new SmtpProtocolException("malformed reply line: " + line);
            int c = parseCode(line);
            if (code == -1) code = c;
            else if (c != code) throw new SmtpProtocolException("reply code changed within a multi-line reply: " + line);
            char sep = line.length() > 3 ? line.charAt(3) : ' ';
            if (sep != ' ' && sep != '-') throw new SmtpProtocolException("malformed reply line: " + line);
            lines.add(line.length() > 4 ? line.substring(4) : "");
            if (sep == ' ') return new SmtpResponse(code, lines);
            if (lines.size() >= MAX_REPLY_LINES) throw new SmtpProtocolException("reply has too many lines");
        }
    }

    private static int parseCode(String line) throws SmtpProtocolException {
        int code = 0;
        for (int i = 0; i < 3; i++) {
            char ch = line.charAt(i);
            if (ch < '0' || ch > '9') throw new SmtpProtocolException("malformed reply line: " + line);
            code = code * 10 + (ch - '0');
        }
        if (code < 200 || code > 599) throw new SmtpProtocolException("reply code out of range: " + line);
        return code;
    }

    private String readLine() throws IOException {
        ByteArrayOutputStream buf = new ByteArrayOutputStream(128);
        while (true) {
            int b = in.read();
            if (b == -1) throw new EOFException("connection closed by " + serverName);
            if (b == '\n') break;
            if (buf.size() >= MAX_REPLY_LINE) throw new SmtpProtocolException("reply line too long");
            buf.write(b);
        }
        byte[] bytes = buf.toByteArray();
        int len = bytes.length;
        if (len > 0 && bytes[len - 1] == '\r') len--;
        return new String(bytes, 0, len, StandardCharsets.UTF_8);
    }

    private void ensureOpen() throws IOException {
        if (closed || socket == null || socket.isClosed()) throw new IOException("SMTP connection is closed");
    }

    private static void checkArgument(String s, String what) {
        Objects.requireNonNull(s, what);
        for (int i = 0; i < s.length(); i++) {
            char ch = s.charAt(i);
            if (ch == '\r' || ch == '\n' || ch == 0) throw new IllegalArgumentException(what + " contains a line break");
        }
    }

    private static void checkAddress(String address, boolean allowEmpty) {
        checkArgument(address, "address");
        if (address.isEmpty() && !allowEmpty) throw new IllegalArgumentException("empty address");
        for (int i = 0; i < address.length(); i++) {
            char ch = address.charAt(i);
            if (ch == '<' || ch == '>' || ch <= ' ' || ch == 0x7f) {
                throw new IllegalArgumentException("invalid character in address: " + address);
            }
        }
    }

    static int timeoutMillis(Duration d) {
        long ms = d.toMillis();
        if (ms <= 0) throw new IllegalArgumentException("timeout must be positive: " + d);
        return (int) Math.min(ms, Integer.MAX_VALUE);
    }

    private static void closeQuietly(Socket s) {
        if (s == null) return;
        try {
            s.close();
        } catch (IOException ignored) {
        }
    }

    /** Thrown when the server's reply doesn't follow the SMTP syntax. */
    public static final class SmtpProtocolException extends IOException {
        public SmtpProtocolException(String message) {
            super(message);
        }
    }

    /**
     * Closes the socket if a single write blocks longer than the read timeout. Java sockets have no write timeout,
     * and a server that stops reading during {@code DATA} would otherwise block the sender indefinitely.
     */
    private final class WatchdogOutputStream extends FilterOutputStream {
        private volatile boolean timedOut;

        WatchdogOutputStream(OutputStream out) {
            super(out);
        }

        @Override
        public void write(int b) throws IOException {
            write(new byte[]{(byte) b}, 0, 1);
        }

        @Override
        public void write(byte[] b, int off, int len) throws IOException {
            guard(() -> out.write(b, off, len));
        }

        @Override
        public void flush() throws IOException {
            guard(out::flush);
        }

        private void guard(IoAction action) throws IOException {
            Socket s = socket;
            ScheduledFuture<?> task = WATCHDOG.schedule(() -> {
                timedOut = true;
                closeQuietly(s);
            }, readTimeout.toMillis(), TimeUnit.MILLISECONDS);
            try {
                action.run();
            } catch (IOException e) {
                if (timedOut) {
                    java.net.SocketTimeoutException te =
                            new java.net.SocketTimeoutException("write to " + serverName + " timed out");
                    te.initCause(e);
                    throw te;
                }
                throw e;
            } finally {
                task.cancel(false);
            }
        }
    }

    private interface IoAction {
        void run() throws IOException;
    }

    /**
     * Doubles a {@code .} at the start of every line (RFC 5321 §4.5.2) and, on {@link #finish()}, writes the
     * {@code CRLF.CRLF} terminator (adding a CRLF first if the message didn't end with one). Lines are delimited by
     * LF, so a CRLF-normalised message is handled exactly.
     */
    static final class DotStuffingOutputStream extends FilterOutputStream {
        private boolean atLineStart = true;
        private int last = -1;
        private int prev = -1;

        DotStuffingOutputStream(OutputStream out) {
            super(out);
        }

        @Override
        public void write(int b) throws IOException {
            if (atLineStart && b == '.') out.write('.');
            out.write(b);
            atLineStart = b == '\n';
            prev = last;
            last = b & 0xff;
        }

        @Override
        public void write(byte[] b, int off, int len) throws IOException {
            int start = off;
            int end = off + len;
            for (int i = off; i < end; i++) {
                if (atLineStart && b[i] == '.') {
                    out.write(b, start, i - start);
                    out.write('.');
                    start = i;
                }
                atLineStart = b[i] == '\n';
            }
            out.write(b, start, end - start);
            if (len >= 2) {
                prev = b[end - 2] & 0xff;
                last = b[end - 1] & 0xff;
            } else if (len == 1) {
                prev = last;
                last = b[end - 1] & 0xff;
            }
        }

        /** Writes the end-of-data marker. Does not close or flush the underlying stream. */
        void finish() throws IOException {
            if (last == -1) {
                // Empty message: the terminator alone.
            } else if (last != '\n') {
                out.write('\r');
                out.write('\n');
            } else if (prev != '\r') {
                // Bare LF at the end: the terminator still needs a preceding CRLF.
                out.write('\r');
                out.write('\n');
            }
            out.write(".\r\n".getBytes(StandardCharsets.US_ASCII));
        }
    }
}
