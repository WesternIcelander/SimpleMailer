package io.siggi.simplemailer.inbound;

import io.siggi.simplemailer.config.Config;
import io.siggi.tools.io.LineReader;
import io.siggi.tools.io.ServerSocketHandler;
import io.siggi.tools.io.SizeExceededException;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.ByteArrayOutputStream;
import java.io.Closeable;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collection;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * The built-in SMTP bounce listener ({@code bounces.intake} includes {@code smtp}, PLAN.md §6a).
 *
 * <p>A minimal inbound SMTP server that accepts <b>only</b> bounces for messages we sent. It is not a relay and
 * stores no other mail: {@code RCPT TO} is accepted only for a {@code bounce+…@bounceDomain} address whose HMAC
 * tag verifies and whose job and recipient exist ({@link BounceProcessor#checkAddress}); everything else gets
 * {@code 550}. An accepted message is handed to {@link BounceProcessor#processMessage} once per accepted recipient.
 *
 * <p>Commands: {@code EHLO}/{@code HELO}, {@code STARTTLS} (only if a certificate is configured), {@code MAIL}
 * (with {@code SIZE} and {@code BODY} parameters), {@code RCPT}, {@code DATA}, {@code RSET}, {@code NOOP},
 * {@code QUIT}. Abuse limits: total and per-client-address connection caps, an idle timeout per command or data
 * line, a hard session timeout, a command line length limit, a message size limit ({@code SIZE}), a cap on
 * recipients per transaction and on transactions per connection, and a connection is dropped after too many
 * errors. One virtual thread per connection.
 */
public final class InboundSmtpServer implements Closeable {
    private static final Logger LOG = Logger.getLogger(InboundSmtpServer.class.getName());

    /** RFC 5321 §4.5.3.1.4: a command line is at most 512 octets; we allow some slack for long parameters. */
    static final int MAX_COMMAND_LINE = 1000;
    /** Recipients accepted in one transaction (RFC 5321 §4.5.3.1.8 minimum is 100). */
    static final int MAX_RECIPIENTS = 100;
    /** Mail transactions on one connection. */
    static final int MAX_TRANSACTIONS = 100;
    /** Error replies (bad syntax, bad sequence, rejected recipients) before the connection is dropped. */
    static final int MAX_ERRORS = 20;

    private static final Pattern MAIL_FROM = Pattern.compile("^MAIL FROM:\\s*<([^<>]*)>(.*)$", Pattern.CASE_INSENSITIVE);
    private static final Pattern RCPT_TO = Pattern.compile("^RCPT TO:\\s*<([^<>]*)>(.*)$", Pattern.CASE_INSENSITIVE);
    private static final int MAX_PATH = 256;

    private static final ScheduledExecutorService WATCHDOG = Executors.newSingleThreadScheduledExecutor(r -> {
        Thread t = new Thread(r, "inbound-smtp-watchdog");
        t.setDaemon(true);
        return t;
    });

    /**
     * Server settings.
     *
     * @param serverName               host name in the greeting and EHLO reply
     * @param maxMessageBytes          largest accepted message (advertised as {@code SIZE})
     * @param maxConnections           simultaneous connections in total
     * @param maxConnectionsPerAddress simultaneous connections from one client IP address
     * @param idleTimeout              wait for the next command or data line
     * @param sessionTimeout           hard limit on a whole connection
     * @param tlsContext               server TLS context for {@code STARTTLS}, or null to not offer it
     */
    public record Options(String serverName, long maxMessageBytes, int maxConnections, int maxConnectionsPerAddress,
                          Duration idleTimeout, Duration sessionTimeout, SSLContext tlsContext) {
        public Options {
            Objects.requireNonNull(serverName, "serverName");
            Objects.requireNonNull(idleTimeout, "idleTimeout");
            Objects.requireNonNull(sessionTimeout, "sessionTimeout");
            if (maxMessageBytes <= 0 || maxConnections <= 0 || maxConnectionsPerAddress <= 0) {
                throw new IllegalArgumentException("limits must be positive");
            }
        }

        /**
         * Options from {@code heloName} and {@code bounces.smtp*}; the TLS certificate and key are loaded from
         * {@code bounces.smtpTlsCert}/{@code bounces.smtpTlsKey} when set.
         */
        public static Options fromConfig(Config config) throws IOException {
            Config.Bounces b = config.bounces;
            SSLContext tls = null;
            if (b.smtpTlsCert != null && b.smtpTlsKey != null) {
                tls = loadTlsContext(Path.of(b.smtpTlsCert), Path.of(b.smtpTlsKey));
            }
            return new Options(config.heloName, b.smtpMaxMessageBytes, b.smtpMaxConnections,
                    b.smtpMaxConnectionsPerIp, b.smtpIdleTimeout, b.smtpSessionTimeout, tls);
        }
    }

    private final BounceProcessor processor;
    private final Options options;
    private final AtomicInteger connections = new AtomicInteger();
    private final Map<InetAddress, AtomicInteger> perAddress = new ConcurrentHashMap<>();
    private final Set<Socket> open = ConcurrentHashMap.newKeySet();
    private volatile ServerSocket serverSocket;
    private volatile boolean closed;

    public InboundSmtpServer(BounceProcessor processor, Options options) {
        this.processor = Objects.requireNonNull(processor, "processor");
        this.options = Objects.requireNonNull(options, "options");
    }

    /** Starts accepting connections on {@code socket} (already bound); each one runs on its own virtual thread. */
    public void start(ServerSocket socket) {
        if (serverSocket != null) throw new IllegalStateException("already started");
        this.serverSocket = socket;
        new ServerSocketHandler(socket, this::handle)
                .withThreadFactory(Thread.ofVirtual().name("inbound-smtp-", 0).factory())
                .withExceptionHandler(e -> {
                    LOG.log(Level.WARNING, "inbound SMTP accept failed", e);
                    return !closed;
                })
                .start();
    }

    public int port() {
        return serverSocket.getLocalPort();
    }

    /** Stops accepting and drops all open connections. */
    @Override
    public void close() throws IOException {
        closed = true;
        try {
            if (serverSocket != null) serverSocket.close();
        } finally {
            for (Socket s : open) closeQuietly(s);
        }
    }

    // ---- connection handling ----------------------------------------------------------------------------------

    /** Handles one accepted connection: enforces the connection limits, then runs the session. */
    void handle(Socket socket) {
        InetAddress address = socket.getInetAddress();
        AtomicInteger fromAddress = perAddress.computeIfAbsent(address, a -> new AtomicInteger());
        int total = connections.incrementAndGet();
        int mine = fromAddress.incrementAndGet();
        open.add(socket);
        ScheduledFuture<?> deadline = WATCHDOG.schedule(() -> closeQuietly(socket),
                options.sessionTimeout().toMillis(), TimeUnit.MILLISECONDS);
        try {
            if (closed) return;
            if (total > options.maxConnections() || mine > options.maxConnectionsPerAddress()) {
                socket.setSoTimeout(10_000);
                OutputStream out = socket.getOutputStream();
                out.write(("421 4.7.0 " + options.serverName() + " too many connections, try again later\r\n")
                        .getBytes(StandardCharsets.US_ASCII));
                out.flush();
                return;
            }
            new Session(socket).run();
        } catch (IOException | RuntimeException e) {
            if (!(e instanceof SocketTimeoutException) && !socket.isClosed()) {
                LOG.log(Level.FINE, "inbound SMTP session from " + address + " ended", e);
            }
        } finally {
            deadline.cancel(false);
            open.remove(socket);
            closeQuietly(socket);
            connections.decrementAndGet();
            if (fromAddress.decrementAndGet() <= 0) perAddress.remove(address, fromAddress);
        }
    }

    /** The SMTP conversation on one connection. */
    private final class Session {
        private Socket socket;
        private BufferedInputStream in;
        private OutputStream out;
        private LineReader lines;
        private final String client;

        private boolean tls;
        private String helo;
        private String mailFrom;
        private final List<String> recipients = new ArrayList<>();
        private int transactions;
        private int errors;

        Session(Socket socket) throws IOException {
            this.client = socket.getInetAddress().getHostAddress();
            attach(socket);
        }

        private void attach(Socket s) throws IOException {
            this.socket = s;
            s.setSoTimeout((int) Math.min(Math.max(options.idleTimeout().toMillis(), 1), Integer.MAX_VALUE));
            this.in = new BufferedInputStream(s.getInputStream());
            this.out = new BufferedOutputStream(s.getOutputStream());
            this.lines = new LineReader(in, false, MAX_COMMAND_LINE);
        }

        void run() throws IOException {
            reply("220 " + options.serverName() + " ESMTP SimpleMailer bounce intake");
            while (true) {
                String line;
                try {
                    line = lines.readLine();
                } catch (SizeExceededException e) {
                    reply("500 5.5.2 line too long");
                    return;
                }
                if (line == null) return;
                try {
                    if (!command(line)) return;
                } catch (SessionEnd e) {
                    return;
                }
            }
        }

        /** Runs one command; false ends the session. */
        private boolean command(String line) throws IOException {
            int sp = line.indexOf(' ');
            String verb = (sp < 0 ? line : line.substring(0, sp)).toUpperCase(Locale.ROOT);
            String rest = sp < 0 ? "" : line.substring(sp + 1);
            switch (verb) {
                case "EHLO", "HELO" -> hello(verb.equals("EHLO"), rest.trim());
                case "STARTTLS" -> {
                    return startTls(rest.trim());
                }
                case "MAIL" -> mail(line);
                case "RCPT" -> rcpt(line);
                case "DATA" -> {
                    return data(rest.trim());
                }
                case "RSET" -> {
                    resetTransaction();
                    reply("250 2.0.0 OK");
                }
                case "NOOP" -> reply("250 2.0.0 OK");
                case "QUIT" -> {
                    reply("221 2.0.0 " + options.serverName() + " closing connection");
                    return false;
                }
                case "VRFY", "EXPN" -> reply("502 5.5.1 command not implemented");
                default -> error("500 5.5.2 command not recognized");
            }
            return true;
        }

        private void hello(boolean extended, String domain) throws IOException {
            if (domain.isEmpty()) {
                error("501 5.5.4 " + (extended ? "EHLO" : "HELO") + " requires a domain or address literal");
                return;
            }
            resetTransaction();
            helo = domain;
            if (!extended) {
                reply("250 " + options.serverName());
                return;
            }
            List<String> ext = new ArrayList<>();
            ext.add(options.serverName() + " greets " + client);
            ext.add("SIZE " + options.maxMessageBytes());
            ext.add("8BITMIME");
            ext.add("ENHANCEDSTATUSCODES");
            if (options.tlsContext() != null && !tls) ext.add("STARTTLS");
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < ext.size(); i++) {
                sb.append("250").append(i == ext.size() - 1 ? ' ' : '-').append(ext.get(i));
                if (i < ext.size() - 1) sb.append("\r\n");
            }
            reply(sb.toString());
        }

        private boolean startTls(String args) throws IOException {
            if (options.tlsContext() == null) {
                error("502 5.5.1 STARTTLS not available");
                return true;
            }
            if (tls) {
                error("503 5.5.1 TLS already active");
                return true;
            }
            if (!args.isEmpty()) {
                error("501 5.5.4 STARTTLS takes no parameters");
                return true;
            }
            // Anything pipelined after STARTTLS was sent in plaintext and must not be treated as part of the TLS
            // session (CVE-2011-0411); drop such a client.
            if (in.available() > 0) {
                reply("554 5.5.1 data sent after STARTTLS before TLS negotiation");
                return false;
            }
            reply("220 2.0.0 ready to start TLS");
            SSLSocket ssl = (SSLSocket) options.tlsContext().getSocketFactory()
                    .createSocket(socket, client, socket.getPort(), true);
            ssl.setUseClientMode(false);
            open.add(ssl);
            try {
                ssl.startHandshake();
            } catch (IOException e) {
                LOG.log(Level.FINE, "inbound SMTP TLS handshake with " + client + " failed", e);
                open.remove(ssl);
                closeQuietly(ssl);
                return false;
            }
            Socket plain = socket;
            attach(ssl);
            open.remove(plain);
            tls = true;
            // RFC 3207 §4.2: discard all knowledge from before TLS; the client must EHLO again
            helo = null;
            resetTransaction();
            return true;
        }

        private void mail(String line) throws IOException {
            if (helo == null) {
                error("503 5.5.1 send EHLO/HELO first");
                return;
            }
            if (mailFrom != null) {
                error("503 5.5.1 nested MAIL command");
                return;
            }
            if (transactions >= MAX_TRANSACTIONS) {
                reply("421 4.7.0 too many transactions on one connection");
                throw new SessionEnd();
            }
            Matcher m = MAIL_FROM.matcher(line);
            if (!m.matches() || m.group(1).length() > MAX_PATH) {
                error("501 5.5.4 syntax: MAIL FROM:<address>");
                return;
            }
            for (String param : m.group(2).trim().split("\\s+")) {
                if (param.isEmpty()) continue;
                int eq = param.indexOf('=');
                String key = (eq < 0 ? param : param.substring(0, eq)).toUpperCase(Locale.ROOT);
                String value = eq < 0 ? null : param.substring(eq + 1);
                switch (key) {
                    case "SIZE" -> {
                        long size;
                        try {
                            size = Long.parseLong(Objects.requireNonNullElse(value, ""));
                        } catch (NumberFormatException e) {
                            error("501 5.5.4 bad SIZE parameter");
                            return;
                        }
                        if (size > options.maxMessageBytes()) {
                            error("552 5.3.4 message size exceeds fixed limit of " + options.maxMessageBytes());
                            return;
                        }
                    }
                    case "BODY" -> {
                        String v = value == null ? "" : value.toUpperCase(Locale.ROOT);
                        if (!v.equals("7BIT") && !v.equals("8BITMIME")) {
                            error("501 5.5.4 bad BODY parameter");
                            return;
                        }
                    }
                    default -> {
                        error("555 5.5.4 unsupported MAIL parameter " + key);
                        return;
                    }
                }
            }
            mailFrom = m.group(1).trim();
            reply("250 2.1.0 OK");
        }

        private void rcpt(String line) throws IOException {
            if (mailFrom == null) {
                error("503 5.5.1 need MAIL before RCPT");
                return;
            }
            Matcher m = RCPT_TO.matcher(line);
            if (!m.matches() || m.group(1).length() > MAX_PATH) {
                error("501 5.5.4 syntax: RCPT TO:<address>");
                return;
            }
            if (!m.group(2).isBlank()) {
                error("555 5.5.4 RCPT parameters not supported");
                return;
            }
            if (recipients.size() >= MAX_RECIPIENTS) {
                reply("452 4.5.3 too many recipients");
                return;
            }
            String address = m.group(1).trim();
            BounceProcessor.AddressCheck check;
            try {
                check = processor.checkAddress(address);
            } catch (IOException e) {
                LOG.log(Level.WARNING, "could not check bounce address " + address, e);
                reply("451 4.3.0 temporary failure, try again later");
                return;
            }
            if (!check.accepted()) {
                LOG.info("inbound SMTP from " + client + ": rejected RCPT " + address + " (" + check.outcome() + ")");
                error("550 5.1.1 no such recipient here (this server accepts only bounces)");
                return;
            }
            if (!recipients.contains(address)) recipients.add(address);
            reply("250 2.1.5 OK");
        }

        private boolean data(String args) throws IOException {
            if (!args.isEmpty()) {
                error("501 5.5.4 DATA takes no parameters");
                return true;
            }
            if (mailFrom == null) {
                error("503 5.5.1 need MAIL before DATA");
                return true;
            }
            if (recipients.isEmpty()) {
                error("554 5.5.1 no valid recipients");
                return true;
            }
            reply("354 end data with <CR><LF>.<CR><LF>");
            byte[] message = readData();
            transactions++;
            if (message == null) {
                resetTransaction();
                reply("552 5.3.4 message size exceeds fixed limit of " + options.maxMessageBytes());
                return true;
            }
            boolean temporaryFailure = false;
            for (String rcpt : recipients) {
                try {
                    BounceProcessor.Result r = processor.processMessage(message, rcpt, mailFrom,
                            BounceProcessor.Source.SMTP);
                    LOG.info("inbound SMTP from " + client + ": message for " + rcpt + " -> " + r.outcome());
                } catch (IOException | RuntimeException e) {
                    // the sender retries; bounces already applied are recognised as duplicates then
                    LOG.log(Level.WARNING, "could not process bounce for " + rcpt, e);
                    temporaryFailure = true;
                }
            }
            resetTransaction();
            reply(temporaryFailure ? "451 4.3.0 temporary failure processing message, try again later"
                    : "250 2.0.0 OK message accepted");
            return true;
        }

        /**
         * Reads the message up to the terminating {@code .} line, undoing dot-stuffing and normalising line endings
         * to CRLF. Returns null if it exceeded the size limit (the rest is read and discarded so the session stays
         * in sync). Throws on EOF before the end of data.
         */
        private byte[] readData() throws IOException {
            long max = options.maxMessageBytes();
            ByteArrayOutputStream buf = new ByteArrayOutputStream();
            ByteArrayOutputStream line = new ByteArrayOutputStream(256);
            boolean overflow = false;
            while (true) {
                line.reset();
                int b;
                boolean eol = false;
                while ((b = in.read()) != -1) {
                    if (b == '\n') {
                        eol = true;
                        break;
                    }
                    // past the limit only the first bytes of each line are kept, enough to spot the final "."
                    if (line.size() < 3 || (!overflow && buf.size() + line.size() < max + 2)) line.write(b);
                    else overflow = true;
                }
                if (!eol) throw new IOException("connection closed during DATA");
                byte[] bytes = line.toByteArray();
                int len = bytes.length;
                if (len > 0 && bytes[len - 1] == '\r') len--;
                if (len == 1 && bytes[0] == '.') break;
                if (overflow) continue;
                int start = len > 0 && bytes[0] == '.' ? 1 : 0;
                if ((long) buf.size() + (len - start) + 2 > max) {
                    overflow = true;
                    continue;
                }
                buf.write(bytes, start, len - start);
                buf.write('\r');
                buf.write('\n');
            }
            return overflow ? null : buf.toByteArray();
        }

        private void resetTransaction() {
            mailFrom = null;
            recipients.clear();
        }

        /** An error reply; the last one allowed is replaced by {@code 421} and the session ends. */
        private void error(String reply) throws IOException {
            if (++errors >= MAX_ERRORS) {
                reply("421 4.7.0 too many errors, closing connection");
                throw new SessionEnd();
            }
            reply(reply);
        }

        private void reply(String text) throws IOException {
            out.write(text.getBytes(StandardCharsets.UTF_8));
            out.write('\r');
            out.write('\n');
            out.flush();
        }
    }

    /** Ends the session after a final reply has been sent. */
    private static final class SessionEnd extends RuntimeException {
        SessionEnd() {
            super(null, null, false, false);
        }
    }

    // ---- TLS ----------------------------------------------------------------------------------------------------

    /**
     * Server TLS context from a PEM certificate chain (leaf first) and a PEM PKCS#8 private key
     * ({@code -----BEGIN PRIVATE KEY-----}; RSA, EC or EdDSA).
     */
    public static SSLContext loadTlsContext(Path certPem, Path keyPem) throws IOException {
        try {
            Collection<? extends Certificate> certs;
            try (InputStream in = Files.newInputStream(certPem)) {
                certs = CertificateFactory.getInstance("X.509").generateCertificates(in);
            }
            if (certs.isEmpty()) throw new IOException("no certificate in " + certPem);
            PrivateKey key = readPkcs8Key(keyPem);
            char[] password = new char[16];
            SecureRandom random = new SecureRandom();
            for (int i = 0; i < password.length; i++) password[i] = (char) ('a' + random.nextInt(26));
            KeyStore ks = KeyStore.getInstance("PKCS12");
            ks.load(null, null);
            ks.setKeyEntry("smtp", key, password, certs.toArray(new Certificate[0]));
            KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            kmf.init(ks, password);
            SSLContext ctx = SSLContext.getInstance("TLS");
            ctx.init(kmf.getKeyManagers(), null, null);
            return ctx;
        } catch (GeneralSecurityException e) {
            throw new IOException("could not load TLS certificate/key (" + certPem + ", " + keyPem + "): "
                    + e.getMessage(), e);
        }
    }

    private static PrivateKey readPkcs8Key(Path keyPem) throws IOException, GeneralSecurityException {
        String pem = Files.readString(keyPem, StandardCharsets.US_ASCII);
        String begin = "-----BEGIN PRIVATE KEY-----";
        String end = "-----END PRIVATE KEY-----";
        int b = pem.indexOf(begin);
        int e = pem.indexOf(end);
        if (b < 0 || e < b) {
            throw new IOException(keyPem + " must hold a PEM PKCS#8 private key (-----BEGIN PRIVATE KEY-----);"
                    + " convert with: openssl pkcs8 -topk8 -nocrypt");
        }
        byte[] der = Base64.getMimeDecoder().decode(pem.substring(b + begin.length(), e));
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(der);
        GeneralSecurityException last = null;
        for (String alg : List.of("RSA", "EC", "Ed25519", "Ed448", "RSASSA-PSS")) {
            try {
                return KeyFactory.getInstance(alg).generatePrivate(spec);
            } catch (GeneralSecurityException ex) {
                last = ex;
            }
        }
        throw new GeneralSecurityException("unsupported private key in " + keyPem, last);
    }

    private static void closeQuietly(Socket s) {
        try {
            s.close();
        } catch (IOException ignored) {
        }
    }
}
