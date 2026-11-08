package io.siggi.simplemailer.api;

import io.siggi.http.HTTPRequest;
import io.siggi.http.HTTPResponder;
import io.siggi.simplemailer.config.Config;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Locale;

/**
 * Bearer API key authentication (PLAN.md §3, §6a).
 *
 * <p>There are two separate key sets: {@link Scope#SENDER} keys (config {@code apiKeys}) for the message endpoints,
 * and {@link Scope#BOUNCE} keys (config {@code bounces.apiKeys}) for {@code POST /v1/bounces}. A key is only valid
 * for its own scope, so a sender key can't report bounces and a bounce key can't send mail.
 *
 * <p>Keys are compared by SHA-256 digest with {@link MessageDigest#isEqual}, and every configured key is checked,
 * so the comparison time doesn't depend on which key (if any) matched or how long a matching prefix is.
 */
public final class Auth {
    public enum Scope {
        SENDER,
        BOUNCE
    }

    private static final String BEARER = "bearer";

    private final List<byte[]> senderKeys;
    private final List<byte[]> bounceKeys;

    public Auth(Collection<String> senderKeys, Collection<String> bounceKeys) {
        this.senderKeys = digestAll(senderKeys);
        this.bounceKeys = digestAll(bounceKeys);
    }

    public static Auth fromConfig(Config config) {
        return new Auth(config.apiKeys, config.bounces.apiKeys);
    }

    /** True if {@code key} is a configured key for {@code scope}. Null or blank keys are never valid. */
    public boolean isValid(String key, Scope scope) {
        if (key == null || key.isBlank()) return false;
        byte[] digest = sha256(key);
        boolean match = false;
        for (byte[] candidate : keys(scope)) {
            match |= MessageDigest.isEqual(candidate, digest);
        }
        return match;
    }

    /** True if the {@code Authorization} header value carries a valid bearer key for {@code scope}. */
    public boolean isAuthorized(String authorizationHeader, Scope scope) {
        return isValid(bearerToken(authorizationHeader), scope);
    }

    /**
     * Checks the request's {@code Authorization} header. If it isn't a valid key for {@code scope}, sends
     * {@code 401} with a {@code WWW-Authenticate} challenge and returns false; the caller must then stop.
     */
    public boolean authenticate(HTTPRequest request, Scope scope) throws IOException {
        if (isAuthorized(request.getHeader("Authorization"), scope)) return true;
        sendUnauthorized(request);
        return false;
    }

    /** Wraps {@code responder} so it only runs for requests carrying a valid key for {@code scope}. */
    public HTTPResponder protect(Scope scope, HTTPResponder responder) {
        return request -> {
            if (authenticate(request, scope)) responder.respond(request);
        };
    }

    /**
     * Extracts the token from an {@code Authorization: Bearer <token>} header value (scheme is case-insensitive per
     * RFC 7235). Returns null if the header is missing, uses another scheme, or has no token.
     */
    public static String bearerToken(String authorizationHeader) {
        if (authorizationHeader == null) return null;
        String value = authorizationHeader.trim();
        int space = indexOfWhitespace(value);
        if (space < 0) return null;
        if (!value.substring(0, space).toLowerCase(Locale.ROOT).equals(BEARER)) return null;
        String token = value.substring(space + 1).trim();
        if (token.isEmpty() || indexOfWhitespace(token) >= 0) return null;
        return token;
    }

    static void sendUnauthorized(HTTPRequest request) throws IOException {
        byte[] body = "{\"error\":\"unauthorized\",\"message\":\"missing or invalid API key\"}"
                .getBytes(StandardCharsets.UTF_8);
        request.response.setHeader("401 Unauthorized");
        request.response.setHeader("WWW-Authenticate", "Bearer realm=\"SimpleMailer\"");
        request.response.doNotCache();
        request.response.setContentType("application/json; charset=utf-8");
        request.response.contentLength(body.length);
        request.response.write(body);
    }

    private List<byte[]> keys(Scope scope) {
        return switch (scope) {
            case SENDER -> senderKeys;
            case BOUNCE -> bounceKeys;
        };
    }

    private static int indexOfWhitespace(String s) {
        for (int i = 0; i < s.length(); i++) {
            if (Character.isWhitespace(s.charAt(i))) return i;
        }
        return -1;
    }

    private static List<byte[]> digestAll(Collection<String> keys) {
        List<byte[]> out = new ArrayList<>();
        if (keys == null) return List.of();
        for (String key : keys) {
            if (key != null && !key.isBlank()) out.add(sha256(key));
        }
        return List.copyOf(out);
    }

    private static byte[] sha256(String s) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(s.getBytes(StandardCharsets.UTF_8));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }
}
