package io.siggi.simplemailer.smtp;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509ExtendedTrustManager;
import java.io.IOException;
import java.net.Socket;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertPathBuilderException;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Objects;

/**
 * STARTTLS handling for one outgoing SMTP connection (PLAN.md §5).
 *
 * <ul>
 *   <li><b>Opportunistic</b>: STARTTLS is always attempted when the server advertises it.</li>
 *   <li><b>{@code requireTls}</b>: if STARTTLS isn't advertised, is refused, or the handshake fails, this MX fails
 *       with {@link #TLS_REQUIRED_NOT_AVAILABLE}; the caller tries the next MX.</li>
 *   <li><b>{@code verifyCertificate}</b>: the server certificate is checked against the trust store and the MX host
 *       name (endpoint identification {@code HTTPS}); otherwise any certificate is accepted for this connection.
 *       A verification failure gives {@link #TLS_CERT_INVALID}.</li>
 * </ul>
 *
 * <p>When TLS is <em>not</em> required and the handshake fails (including a certificate verification failure with
 * {@code verifyCertificate}), the connection is unusable; the result says {@link Result#retryWithoutTls()}, and
 * the caller may reconnect to the same MX and send in plaintext without STARTTLS, as opportunistic TLS allows.
 *
 * <p>Usage: connect, {@code EHLO}, then {@link #negotiate(SmtpClient, String)}. On {@link Status#ENCRYPTED} the
 * client has already re-issued {@code EHLO} over TLS (RFC 3207 §4.2) and {@link Result#ehlo()} holds that reply.
 */
public final class TlsPolicy {
    /** {@code requireTls} was set but no TLS session could be established with this MX. */
    public static final String TLS_REQUIRED_NOT_AVAILABLE = "TLS_REQUIRED_NOT_AVAILABLE";
    /** {@code verifyCertificate} was set and the server certificate failed verification. */
    public static final String TLS_CERT_INVALID = "TLS_CERT_INVALID";
    /** Opportunistic TLS: the handshake failed (the caller may retry in plaintext). */
    public static final String TLS_HANDSHAKE_FAILED = "TLS_HANDSHAKE_FAILED";
    /** The server sent data between its {@code 220} reply to STARTTLS and the handshake (possible injection). */
    public static final String TLS_PROTOCOL_ERROR = "TLS_PROTOCOL_ERROR";

    private static volatile SSLContext trustAllContext;

    private final boolean requireTls;
    private final boolean verifyCertificate;
    private final SSLContext verifyingContext;

    /** A policy that verifies certificates against the JDK default trust store. */
    public TlsPolicy(boolean requireTls, boolean verifyCertificate) {
        this(requireTls, verifyCertificate, defaultContext());
    }

    /**
     * @param verifyingContext the context used when {@code verifyCertificate} is set (its trust managers decide which
     *                         certificates are trusted); tests pass one that trusts a self-signed certificate
     */
    public TlsPolicy(boolean requireTls, boolean verifyCertificate, SSLContext verifyingContext) {
        this.requireTls = requireTls;
        this.verifyCertificate = verifyCertificate;
        this.verifyingContext = Objects.requireNonNull(verifyingContext);
    }

    public boolean requireTls() {
        return requireTls;
    }

    public boolean verifyCertificate() {
        return verifyCertificate;
    }

    public enum Status {
        /** TLS is up and {@code EHLO} was re-issued; continue with {@code MAIL FROM}. */
        ENCRYPTED,
        /** No TLS, which the policy allows; continue on the same connection in plaintext. */
        PLAINTEXT,
        /** Don't send on this connection; see {@link Result#errorCode()} and {@link Result#retryWithoutTls()}. */
        FAILED
    }

    /**
     * The outcome of {@link #negotiate}.
     *
     * @param status          what happened
     * @param errorCode       one of the {@code TLS_*} constants when {@link Status#FAILED}, else {@code null}
     * @param detail          human-readable explanation (e.g. the handshake exception or the server's refusal), or
     *                        {@code null}
     * @param protocol        negotiated protocol (e.g. {@code TLSv1.3}) when encrypted, else {@code null}
     * @param cipherSuite     negotiated cipher suite when encrypted, else {@code null}
     * @param verified        true if encrypted and the certificate was verified
     * @param ehlo            the {@code EHLO} reply received over TLS when encrypted, else {@code null}
     * @param retryWithoutTls true if TLS isn't required and the caller may reconnect and send without STARTTLS
     */
    public record Result(Status status, String errorCode, String detail, String protocol, String cipherSuite,
                         boolean verified, SmtpResponse ehlo, boolean retryWithoutTls) {
        public boolean encrypted() {
            return status == Status.ENCRYPTED;
        }

        static Result plaintext(String detail) {
            return new Result(Status.PLAINTEXT, null, detail, null, null, false, null, false);
        }

        static Result failed(String errorCode, String detail, boolean retryWithoutTls) {
            return new Result(Status.FAILED, errorCode, detail, null, null, false, null, retryWithoutTls);
        }
    }

    /**
     * Applies the policy to a connection on which {@code EHLO} has just succeeded.
     *
     * <p>On {@link Status#FAILED} the client may already be closed (after a failed handshake) or still open in
     * plaintext (STARTTLS not offered or refused); either way the caller should {@link SmtpClient#quit()} it and not
     * send. Network errors other than the handshake itself (e.g. a timeout on the STARTTLS reply) are thrown.
     */
    public Result negotiate(SmtpClient client, String heloName) throws IOException {
        if (!client.isExtended() || !client.supports("STARTTLS")) {
            return notAvailable("STARTTLS not advertised by " + client.serverName());
        }
        SmtpResponse r = client.command("STARTTLS");
        if (r.code() != 220) {
            return notAvailable("STARTTLS refused: " + r);
        }
        if (client.hasBufferedInput()) {
            client.close();
            return Result.failed(requireTls ? TLS_REQUIRED_NOT_AVAILABLE : TLS_PROTOCOL_ERROR,
                    "server sent data after 220 to STARTTLS before the TLS handshake", !requireTls);
        }

        Socket plain = client.socket();
        SSLSocket ssl;
        try {
            SSLContext ctx = verifyCertificate ? verifyingContext : trustAll();
            ssl = (SSLSocket) ctx.getSocketFactory()
                    .createSocket(plain, client.serverName(), plain.getPort(), true);
            ssl.setUseClientMode(true);
            if (verifyCertificate) {
                SSLParameters params = ssl.getSSLParameters();
                params.setEndpointIdentificationAlgorithm("HTTPS");
                ssl.setSSLParameters(params);
            }
            client.attach(ssl);
            ssl.startHandshake();
        } catch (IOException e) {
            client.close();
            boolean certProblem = verifyCertificate && isCertificateFailure(e);
            String code = certProblem ? TLS_CERT_INVALID
                    : requireTls ? TLS_REQUIRED_NOT_AVAILABLE : TLS_HANDSHAKE_FAILED;
            client.note("TLS handshake failed: " + e);
            return Result.failed(code, "TLS handshake with " + client.serverName() + " failed: " + e.getMessage(),
                    !requireTls);
        }

        SSLSession session = ssl.getSession();
        client.note("TLS " + session.getProtocol() + " " + session.getCipherSuite()
                + (verifyCertificate ? " (certificate verified)" : " (certificate not verified)"));
        // RFC 3207 §4.2: forget everything learned before TLS and start over with EHLO.
        SmtpResponse ehlo = client.ehlo(heloName);
        return new Result(Status.ENCRYPTED, null, null, session.getProtocol(), session.getCipherSuite(),
                verifyCertificate, ehlo, false);
    }

    private Result notAvailable(String detail) {
        if (requireTls) return Result.failed(TLS_REQUIRED_NOT_AVAILABLE, detail, false);
        return Result.plaintext(detail);
    }

    /** True if {@code e} (or a cause) is a certificate/path validation or host name mismatch failure. */
    static boolean isCertificateFailure(Throwable e) {
        for (Throwable t = e; t != null; t = t.getCause()) {
            if (t instanceof CertificateException || t instanceof CertPathValidatorException
                    || t instanceof CertPathBuilderException || t instanceof SSLPeerUnverifiedException) {
                return true;
            }
            if (t.getCause() == t) break;
        }
        return false;
    }

    private static SSLContext defaultContext() {
        try {
            return SSLContext.getDefault();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("no default SSLContext", e);
        }
    }

    /** A context that accepts any server certificate (used when {@code verifyCertificate} is off). */
    static SSLContext trustAll() throws SSLException {
        SSLContext ctx = trustAllContext;
        if (ctx != null) return ctx;
        synchronized (TlsPolicy.class) {
            if (trustAllContext == null) {
                try {
                    SSLContext c = SSLContext.getInstance("TLS");
                    c.init(null, new TrustManager[]{new TrustAllManager()}, null);
                    trustAllContext = c;
                } catch (GeneralSecurityException e) {
                    throw new SSLException("cannot create trust-all SSLContext", e);
                }
            }
            return trustAllContext;
        }
    }

    /**
     * Accepts every server certificate. Extends {@link X509ExtendedTrustManager} so the JDK doesn't wrap it with its
     * own host name checks.
     */
    private static final class TrustAllManager extends X509ExtendedTrustManager {
        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType, Socket socket) {
        }

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType, Socket socket) {
        }

        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType, javax.net.ssl.SSLEngine engine) {
        }

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType, javax.net.ssl.SSLEngine engine) {
        }

        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType) {
        }

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType) {
        }

        @Override
        public X509Certificate[] getAcceptedIssuers() {
            return new X509Certificate[0];
        }
    }
}
