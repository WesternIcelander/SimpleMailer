package io.siggi.simplemailer.mime;

import io.siggi.simplemailer.config.Config;
import io.siggi.simplemailer.store.JobStore;

import javax.net.ssl.SNIHostName;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import java.io.BufferedInputStream;
import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.IDN;
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.regex.Pattern;

/**
 * Downloads URL attachments (PLAN.md §3a) with an SSRF guard.
 *
 * <ul>
 *     <li>Only {@code https} URLs, plus {@code http} when {@code allowHttpAttachmentUrls} is set. No user info.</li>
 *     <li>If {@code attachmentUrlAllowlist} is not empty, the host must match one of its patterns: {@code host}
 *     matches exactly, {@code *.host} matches any subdomain of it.</li>
 *     <li>The host is resolved here and <em>every</em> address it resolves to must be public: loopback, private,
 *     link-local, CGNAT, multicast, reserved and similar ranges are refused (see {@link #isBlockedAddress}). The
 *     connection is then made to one of those checked addresses, so the address can't change between the check and
 *     the connect (no DNS rebinding). TLS still verifies the certificate against the URL's host name.</li>
 *     <li>Redirects (301, 302, 303, 307, 308) are followed up to {@link #MAX_REDIRECTS} times, and each target goes
 *     through the same scheme, allowlist and address checks.</li>
 *     <li>The body may not exceed the given byte limit (checked against {@code Content-Length} up front and while
 *     reading), and the whole fetch, redirects included, must finish within the fetch timeout.</li>
 * </ul>
 *
 * <p>The body is written atomically to the target file, so the file exists only once the download is complete.
 * HTTP/1.1 is spoken directly over a socket (with {@code Connection: close}) because the JDK clients resolve host
 * names themselves and can't be pinned to an address that has been checked.
 */
public final class AttachmentFetcher {
    /** Maximum number of redirects followed. */
    public static final int MAX_REDIRECTS = 3;
    private static final int MAX_HEADER_LINE = 8192;
    private static final int MAX_HEADER_BYTES = 65536;
    private static final Pattern MEDIA_TYPE = Pattern.compile(
            "^[A-Za-z0-9!#$&^_.+-]+/[A-Za-z0-9!#$&^_.+-]+(\\s*;.*)?$");

    /** Resolves a host name to addresses. */
    @FunctionalInterface
    public interface Resolver {
        InetAddress[] resolve(String host) throws UnknownHostException;
    }

    /** Opens a TCP connection to a (checked) address. */
    @FunctionalInterface
    public interface Connector {
        Socket connect(InetAddress address, int port, int timeoutMillis) throws IOException;
    }

    /** A fetch that was refused or failed; the message is suitable for the job's {@code errorMessage}. */
    public static final class FetchException extends IOException {
        public FetchException(String message) {
            super(message);
        }

        public FetchException(String message, Throwable cause) {
            super(message, cause);
        }
    }

    /** A completed download. {@code contentType} is the response {@code Content-Type}, or null. */
    public record Result(long size, String contentType, URI finalUrl) {
    }

    private final boolean allowHttp;
    private final List<String> allowlist;
    private final Duration connectTimeout;
    private final Duration fetchTimeout;
    private final Resolver resolver;
    private final Connector connector;
    private final SSLSocketFactory sslSocketFactory;

    public AttachmentFetcher(boolean allowHttp, List<String> allowlist, Duration connectTimeout,
                             Duration fetchTimeout, Resolver resolver, Connector connector,
                             SSLSocketFactory sslSocketFactory) {
        this.allowHttp = allowHttp;
        this.allowlist = new ArrayList<>();
        if (allowlist != null) {
            for (String p : allowlist) {
                if (p != null && !p.isBlank()) this.allowlist.add(p.trim().toLowerCase(Locale.ROOT));
            }
        }
        this.connectTimeout = Objects.requireNonNull(connectTimeout);
        this.fetchTimeout = Objects.requireNonNull(fetchTimeout);
        this.resolver = Objects.requireNonNull(resolver);
        this.connector = Objects.requireNonNull(connector);
        this.sslSocketFactory = Objects.requireNonNull(sslSocketFactory);
    }

    /** A fetcher using the configuration's URL rules and timeouts, system DNS and the default TLS trust store. */
    public static AttachmentFetcher fromConfig(Config config) {
        return new AttachmentFetcher(config.allowHttpAttachmentUrls, config.attachmentUrlAllowlist,
                config.connectTimeout, config.attachmentFetchTimeout, InetAddress::getAllByName,
                AttachmentFetcher::defaultConnect, (SSLSocketFactory) SSLSocketFactory.getDefault());
    }

    private static Socket defaultConnect(InetAddress address, int port, int timeoutMillis) throws IOException {
        Socket socket = new Socket();
        try {
            socket.connect(new InetSocketAddress(address, port), timeoutMillis);
            return socket;
        } catch (IOException e) {
            socket.close();
            throw e;
        }
    }

    /**
     * Downloads {@code url} into {@code target} (written atomically).
     *
     * @param maxBytes the largest body accepted
     * @throws FetchException if the URL is refused, the server answers with an error, the body is too large, or the
     *                        connection fails or times out
     */
    public Result fetch(String url, Path target, long maxBytes) throws FetchException {
        long deadline = System.nanoTime() + fetchTimeout.toNanos();
        URI uri = parse(url);
        try {
            for (int redirects = 0; ; redirects++) {
                Target t = check(uri);
                try (Socket socket = open(t, deadline)) {
                    OutputStream out = socket.getOutputStream();
                    out.write(requestFor(uri, t).getBytes(StandardCharsets.ISO_8859_1));
                    out.flush();
                    InputStream in = new DeadlineInputStream(new BufferedInputStream(socket.getInputStream()),
                            socket, deadline);
                    Response response = readResponse(in);
                    if (isRedirect(response.status)) {
                        String location = response.header("location");
                        if (location == null) {
                            throw new FetchException(describe(uri) + ": redirect without Location");
                        }
                        if (redirects >= MAX_REDIRECTS) {
                            throw new FetchException(describe(uri) + ": more than " + MAX_REDIRECTS + " redirects");
                        }
                        uri = resolveLocation(uri, location);
                        continue;
                    }
                    if (response.status != 200) {
                        throw new FetchException(describe(uri) + ": HTTP " + response.status
                                + (response.reason.isEmpty() ? "" : " " + response.reason));
                    }
                    InputStream body = bodyStream(response, in, maxBytes, uri);
                    CountingLimitStream counted = new CountingLimitStream(body, maxBytes, uri);
                    JobStore.writeAtomic(target, counted);
                    return new Result(counted.count, mediaType(response.header("content-type")), uri);
                }
            }
        } catch (FetchException e) {
            throw e;
        } catch (SocketTimeoutException e) {
            throw new FetchException(describe(uri) + ": timed out", e);
        } catch (IOException e) {
            throw new FetchException(describe(uri) + ": " + (e.getMessage() != null ? e.getMessage()
                    : e.getClass().getSimpleName()), e);
        }
    }

    // ---- URL and address checks -------------------------------------------------------------------------------

    private record Target(String host, int port, boolean https, InetAddress[] addresses) {
    }

    private URI parse(String url) throws FetchException {
        if (url == null) throw new FetchException("no URL");
        try {
            return new URI(url.trim());
        } catch (URISyntaxException e) {
            throw new FetchException("invalid URL: " + url);
        }
    }

    private URI resolveLocation(URI base, String location) throws FetchException {
        try {
            return base.resolve(new URI(location.trim()));
        } catch (URISyntaxException | IllegalArgumentException e) {
            throw new FetchException(describe(base) + ": invalid redirect location");
        }
    }

    /** Applies the scheme, allowlist and address rules to {@code uri}. */
    private Target check(URI uri) throws FetchException {
        String scheme = uri.getScheme() == null ? "" : uri.getScheme().toLowerCase(Locale.ROOT);
        boolean https = scheme.equals("https");
        if (!https && !(scheme.equals("http") && allowHttp)) {
            throw new FetchException(describe(uri) + ": only " + (allowHttp ? "http and https" : "https")
                    + " URLs are allowed");
        }
        if (uri.getRawUserInfo() != null) throw new FetchException(describe(uri) + ": user info is not allowed");
        String host = uri.getHost();
        if (host == null || host.isEmpty()) throw new FetchException(describe(uri) + ": URL has no host");
        if (host.startsWith("[") && host.endsWith("]")) host = host.substring(1, host.length() - 1);
        else {
            try {
                host = IDN.toASCII(host).toLowerCase(Locale.ROOT);
            } catch (IllegalArgumentException e) {
                throw new FetchException(describe(uri) + ": invalid host");
            }
        }
        while (host.endsWith(".")) host = host.substring(0, host.length() - 1);
        if (!isAllowedHost(host)) throw new FetchException(describe(uri) + ": host is not in the allowlist");
        int port = uri.getPort() < 0 ? (https ? 443 : 80) : uri.getPort();
        InetAddress[] addresses;
        try {
            addresses = resolver.resolve(host);
        } catch (UnknownHostException e) {
            throw new FetchException(describe(uri) + ": unknown host");
        }
        if (addresses == null || addresses.length == 0) {
            throw new FetchException(describe(uri) + ": unknown host");
        }
        for (InetAddress a : addresses) {
            if (isBlockedAddress(a)) {
                throw new FetchException(describe(uri) + ": refused, " + host + " resolves to a non-public address ("
                        + a.getHostAddress() + ")");
            }
        }
        return new Target(host, port, https, addresses);
    }

    /** True if the allowlist is empty or the host matches a pattern ({@code host} or {@code *.suffix}). */
    boolean isAllowedHost(String host) {
        if (allowlist.isEmpty()) return true;
        String h = host.toLowerCase(Locale.ROOT);
        for (String pattern : allowlist) {
            if (pattern.startsWith("*.")) {
                if (h.endsWith(pattern.substring(1)) && h.length() > pattern.length() - 1) return true;
            } else if (h.equals(pattern)) {
                return true;
            }
        }
        return false;
    }

    /**
     * True for addresses an attachment URL may not point at: unspecified, loopback, private (RFC 1918, IPv6 ULA),
     * link-local, CGNAT (100.64/10), multicast, IETF/benchmarking/reserved/broadcast ranges, and IPv6 forms that
     * embed such an IPv4 address (mapped, compatible, NAT64, 6to4).
     */
    public static boolean isBlockedAddress(InetAddress address) {
        if (address.isAnyLocalAddress() || address.isLoopbackAddress() || address.isLinkLocalAddress()
                || address.isSiteLocalAddress() || address.isMulticastAddress()) {
            return true;
        }
        byte[] b = address.getAddress();
        if (address instanceof Inet4Address) return isBlockedV4(b, 0);
        if (address instanceof Inet6Address) {
            int b0 = b[0] & 0xff, b1 = b[1] & 0xff;
            if ((b0 & 0xfe) == 0xfc) return true;                       // fc00::/7 unique local
            if (b0 == 0xfe && (b1 & 0xc0) == 0xc0) return true;          // fec0::/10 site local (deprecated)
            if (b0 == 0xff) return true;                                 // multicast
            boolean first10Zero = true;
            for (int i = 0; i < 10; i++) first10Zero &= b[i] == 0;
            if (first10Zero && (b[10] & 0xff) == 0xff && (b[11] & 0xff) == 0xff) return isBlockedV4(b, 12); // mapped
            boolean first12Zero = first10Zero && b[10] == 0 && b[11] == 0;
            if (first12Zero) return true;                                // ::/96 (incl. ::, ::1, IPv4-compatible)
            if (b0 == 0x00 && b1 == 0x64 && (b[2] & 0xff) == 0xff && (b[3] & 0xff) == 0x9b) {
                boolean wellKnown = true;                                // 64:ff9b::/96 NAT64
                for (int i = 4; i < 12; i++) wellKnown &= b[i] == 0;
                if (wellKnown) return isBlockedV4(b, 12);
                return true;                                             // 64:ff9b:1::/48 local-use NAT64
            }
            if (b0 == 0x20 && b1 == 0x02) return isBlockedV4(b, 2);      // 2002::/16 6to4
            if (b0 == 0x01 && b1 == 0x00) {                              // 100::/64 discard-only
                boolean discard = true;
                for (int i = 2; i < 8; i++) discard &= b[i] == 0;
                if (discard) return true;
            }
            if (b0 == 0x20 && b1 == 0x01 && b[2] == 0x0d && (b[3] & 0xff) == 0xb8) return true; // 2001:db8::/32
            return false;
        }
        return true;
    }

    private static boolean isBlockedV4(byte[] b, int off) {
        int a0 = b[off] & 0xff, a1 = b[off + 1] & 0xff, a2 = b[off + 2] & 0xff;
        if (a0 == 0 || a0 == 10 || a0 == 127) return true;               // this network, private, loopback
        if (a0 == 100 && (a1 & 0xc0) == 64) return true;                 // 100.64/10 CGNAT
        if (a0 == 169 && a1 == 254) return true;                         // link local
        if (a0 == 172 && (a1 & 0xf0) == 16) return true;                 // 172.16/12
        if (a0 == 192 && a1 == 168) return true;                         // 192.168/16
        if (a0 == 192 && a1 == 0 && a2 == 0) return true;                // 192.0.0/24 IETF protocol assignments
        if (a0 == 198 && (a1 & 0xfe) == 18) return true;                 // 198.18/15 benchmarking
        return a0 >= 224;                                                // multicast, reserved, broadcast
    }

    // ---- connection -------------------------------------------------------------------------------------------

    private Socket open(Target t, long deadline) throws IOException {
        IOException last = null;
        for (InetAddress address : t.addresses) {
            int timeout = (int) Math.max(1, Math.min(connectTimeout.toMillis(), remainingMillis(deadline)));
            Socket socket;
            try {
                socket = connector.connect(address, t.port, timeout);
            } catch (IOException e) {
                last = e;
                if (remainingMillis(deadline) <= 0) break;
                continue;
            }
            try {
                socket.setSoTimeout(timeout);
                if (!t.https) return socket;
                SSLSocket ssl = (SSLSocket) sslSocketFactory.createSocket(socket, t.host, t.port, true);
                SSLParameters params = ssl.getSSLParameters();
                params.setEndpointIdentificationAlgorithm("HTTPS");
                if (!isIpLiteral(t.host)) params.setServerNames(List.of(new SNIHostName(t.host)));
                ssl.setSSLParameters(params);
                ssl.setSoTimeout((int) Math.max(1, remainingMillis(deadline)));
                ssl.startHandshake();
                return ssl;
            } catch (IOException | RuntimeException e) {
                socket.close();
                throw e;
            }
        }
        if (last instanceof SocketTimeoutException) throw last;
        throw new IOException("could not connect" + (last != null && last.getMessage() != null
                ? ": " + last.getMessage() : ""), last);
    }

    private static boolean isIpLiteral(String host) {
        return host.indexOf(':') >= 0 || host.matches("[0-9.]+");
    }

    private static long remainingMillis(long deadline) {
        return (deadline - System.nanoTime()) / 1_000_000L;
    }

    private static String requestFor(URI uri, Target t) {
        String path = uri.getRawPath();
        if (path == null || path.isEmpty()) path = "/";
        if (uri.getRawQuery() != null) path += "?" + uri.getRawQuery();
        String host = t.host.indexOf(':') >= 0 ? "[" + t.host + "]" : t.host;
        boolean defaultPort = t.port == (t.https ? 443 : 80);
        return "GET " + path + " HTTP/1.1\r\n"
                + "Host: " + host + (defaultPort ? "" : ":" + t.port) + "\r\n"
                + "User-Agent: SimpleMailer\r\n"
                + "Accept: */*\r\n"
                + "Accept-Encoding: identity\r\n"
                + "Connection: close\r\n"
                + "\r\n";
    }

    // ---- HTTP/1.1 response parsing ----------------------------------------------------------------------------

    private record Response(int status, String reason, Map<String, String> headers) {
        String header(String name) {
            return headers.get(name);
        }
    }

    private static boolean isRedirect(int status) {
        return status == 301 || status == 302 || status == 303 || status == 307 || status == 308;
    }

    private static Response readResponse(InputStream in) throws IOException {
        int[] budget = {MAX_HEADER_BYTES};
        while (true) {
            String statusLine = readLine(in, budget);
            if (statusLine == null) throw new IOException("connection closed before a response");
            if (!statusLine.startsWith("HTTP/1.")) throw new IOException("not an HTTP/1.x response");
            String[] parts = statusLine.split(" ", 3);
            int status;
            try {
                status = Integer.parseInt(parts.length > 1 ? parts[1] : "");
            } catch (NumberFormatException e) {
                throw new IOException("bad HTTP status line");
            }
            Map<String, String> headers = new LinkedHashMap<>();
            String line;
            while ((line = readLine(in, budget)) != null && !line.isEmpty()) {
                int colon = line.indexOf(':');
                if (colon <= 0) throw new IOException("bad HTTP header line");
                String name = line.substring(0, colon).trim().toLowerCase(Locale.ROOT);
                String value = line.substring(colon + 1).trim();
                headers.merge(name, value, (a, b) -> a + ", " + b);
            }
            if (line == null) throw new IOException("connection closed in the response headers");
            if (status >= 100 && status < 200) continue; // interim responses
            return new Response(status, parts.length > 2 ? parts[2].trim() : "", headers);
        }
    }

    /** Reads a CRLF (or LF) terminated line as ISO-8859-1; null at EOF before any byte. */
    private static String readLine(InputStream in, int[] budget) throws IOException {
        ByteArrayOutputStream line = new ByteArrayOutputStream();
        int c;
        while ((c = in.read()) >= 0) {
            if (--budget[0] < 0) throw new IOException("HTTP response headers too large");
            if (c == '\n') break;
            if (line.size() >= MAX_HEADER_LINE) throw new IOException("HTTP header line too long");
            line.write(c);
        }
        if (c < 0 && line.size() == 0) return null;
        if (c < 0) throw new EOFException("connection closed in the response headers");
        String s = line.toString(StandardCharsets.ISO_8859_1);
        return s.endsWith("\r") ? s.substring(0, s.length() - 1) : s;
    }

    private static InputStream bodyStream(Response response, InputStream in, long maxBytes, URI uri)
            throws IOException {
        String te = response.header("transfer-encoding");
        if (te != null && !te.equalsIgnoreCase("identity")) {
            if (!te.toLowerCase(Locale.ROOT).trim().equals("chunked")) {
                throw new FetchException(describe(uri) + ": unsupported Transfer-Encoding " + te);
            }
            return new ChunkedInputStream(in);
        }
        String cl = response.header("content-length");
        if (cl != null) {
            long length;
            try {
                length = Long.parseLong(cl.trim());
            } catch (NumberFormatException e) {
                throw new FetchException(describe(uri) + ": invalid Content-Length");
            }
            if (length < 0) throw new FetchException(describe(uri) + ": invalid Content-Length");
            if (length > maxBytes) throw tooLarge(uri, maxBytes);
            return new FixedLengthInputStream(in, length);
        }
        return in; // read until the server closes the connection
    }

    private static FetchException tooLarge(URI uri, long maxBytes) {
        return new FetchException(describe(uri) + ": larger than " + maxBytes + " bytes");
    }

    /** The response media type if it looks valid (no control characters), else null. */
    static String mediaType(String contentType) {
        if (contentType == null) return null;
        String v = contentType.trim();
        if (v.isEmpty() || !MEDIA_TYPE.matcher(v).matches()) return null;
        for (int i = 0; i < v.length(); i++) {
            char c = v.charAt(i);
            if (c < 0x20 || c > 0x7e) return null;
        }
        return v;
    }

    /** The URL without query or user info, for error messages. */
    static String describe(URI uri) {
        if (uri.getScheme() == null || uri.getHost() == null) return "URL";
        return uri.getScheme() + "://" + uri.getHost() + (uri.getPort() >= 0 ? ":" + uri.getPort() : "")
                + (uri.getRawPath() == null ? "" : uri.getRawPath());
    }

    // ---- body streams -----------------------------------------------------------------------------------------

    /** Applies the overall deadline to every read by lowering the socket timeout to the time that is left. */
    private static final class DeadlineInputStream extends FilterInputStream {
        private final Socket socket;
        private final long deadline;

        DeadlineInputStream(InputStream in, Socket socket, long deadline) {
            super(in);
            this.socket = socket;
            this.deadline = deadline;
        }

        private void arm() throws IOException {
            long left = remainingMillis(deadline);
            if (left <= 0) throw new SocketTimeoutException("fetch timed out");
            socket.setSoTimeout((int) Math.min(Integer.MAX_VALUE, left));
        }

        @Override
        public int read() throws IOException {
            arm();
            return super.read();
        }

        @Override
        public int read(byte[] b, int off, int len) throws IOException {
            arm();
            return super.read(b, off, len);
        }
    }

    /** Counts the bytes read and fails once more than {@code max} have been read. */
    private static final class CountingLimitStream extends FilterInputStream {
        private final long max;
        private final URI uri;
        long count;

        CountingLimitStream(InputStream in, long max, URI uri) {
            super(in);
            this.max = max;
            this.uri = uri;
        }

        @Override
        public int read() throws IOException {
            int c = super.read();
            if (c >= 0 && ++count > max) throw tooLarge(uri, max);
            return c;
        }

        @Override
        public int read(byte[] b, int off, int len) throws IOException {
            int n = super.read(b, off, len);
            if (n > 0 && (count += n) > max) throw tooLarge(uri, max);
            return n;
        }
    }

    /** Exactly {@code length} bytes; EOF before that is an error. */
    private static final class FixedLengthInputStream extends FilterInputStream {
        private long remaining;

        FixedLengthInputStream(InputStream in, long length) {
            super(in);
            this.remaining = length;
        }

        @Override
        public int read() throws IOException {
            byte[] one = new byte[1];
            int n = read(one, 0, 1);
            return n < 0 ? -1 : one[0] & 0xff;
        }

        @Override
        public int read(byte[] b, int off, int len) throws IOException {
            if (remaining <= 0) return -1;
            int n = super.read(b, off, (int) Math.min(len, remaining));
            if (n < 0) throw new EOFException("connection closed before the end of the body");
            remaining -= n;
            return n;
        }
    }

    /** Decodes {@code Transfer-Encoding: chunked}; trailers are read and discarded. */
    private static final class ChunkedInputStream extends FilterInputStream {
        private final int[] budget = {MAX_HEADER_BYTES};
        private long chunkLeft;
        private boolean done;

        ChunkedInputStream(InputStream in) {
            super(in);
        }

        @Override
        public int read() throws IOException {
            byte[] one = new byte[1];
            int n = read(one, 0, 1);
            return n < 0 ? -1 : one[0] & 0xff;
        }

        @Override
        public int read(byte[] b, int off, int len) throws IOException {
            if (done) return -1;
            if (chunkLeft == 0) {
                budget[0] = MAX_HEADER_BYTES; // per chunk header (and the trailer section), not per body
                String line = readLine(in, budget);
                if (line == null) throw new EOFException("connection closed in a chunked body");
                int semi = line.indexOf(';');
                String size = (semi < 0 ? line : line.substring(0, semi)).trim();
                try {
                    chunkLeft = Long.parseLong(size, 16);
                } catch (NumberFormatException e) {
                    throw new IOException("bad chunk size");
                }
                if (chunkLeft < 0) throw new IOException("bad chunk size");
                if (chunkLeft == 0) {
                    String trailer;
                    while ((trailer = readLine(in, budget)) != null && !trailer.isEmpty()) {
                        // ignore trailers
                    }
                    done = true;
                    return -1;
                }
            }
            int n = in.read(b, off, (int) Math.min(len, chunkLeft));
            if (n < 0) throw new EOFException("connection closed in a chunked body");
            chunkLeft -= n;
            if (chunkLeft == 0) {
                budget[0] = MAX_HEADER_LINE;
                String crlf = readLine(in, budget);
                if (crlf == null || !crlf.isEmpty()) throw new IOException("bad chunk terminator");
            }
            return n;
        }
    }
}
