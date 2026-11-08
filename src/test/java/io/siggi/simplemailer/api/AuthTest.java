package io.siggi.simplemailer.api;

import io.siggi.simplemailer.Main;
import io.siggi.simplemailer.api.Auth.Scope;
import io.siggi.simplemailer.config.Config;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AuthTest {
    private final Auth auth = new Auth(List.of("send-1", "send-2"), List.of("bounce-1"));

    @Test
    void senderKeysOnlyValidForSenderScope() {
        assertTrue(auth.isValid("send-1", Scope.SENDER));
        assertTrue(auth.isValid("send-2", Scope.SENDER));
        assertFalse(auth.isValid("send-1", Scope.BOUNCE));
    }

    @Test
    void bounceKeysOnlyValidForBounceScope() {
        assertTrue(auth.isValid("bounce-1", Scope.BOUNCE));
        assertFalse(auth.isValid("bounce-1", Scope.SENDER));
    }

    @Test
    void unknownNullAndBlankKeysRejected() {
        assertFalse(auth.isValid("nope", Scope.SENDER));
        assertFalse(auth.isValid("send-", Scope.SENDER));
        assertFalse(auth.isValid("send-11", Scope.SENDER));
        assertFalse(auth.isValid(null, Scope.SENDER));
        assertFalse(auth.isValid("", Scope.SENDER));
        assertFalse(auth.isValid("  ", Scope.BOUNCE));
    }

    @Test
    void noKeysConfiguredRejectsEverything() {
        Auth empty = new Auth(List.of(), List.of());
        assertFalse(empty.isValid("anything", Scope.SENDER));
        assertFalse(empty.isValid("anything", Scope.BOUNCE));
        assertFalse(empty.isAuthorized("Bearer ", Scope.SENDER));
    }

    @Test
    void bearerTokenParsing() {
        assertEquals("abc", Auth.bearerToken("Bearer abc"));
        assertEquals("abc", Auth.bearerToken("bearer abc"));
        assertEquals("abc", Auth.bearerToken("BEARER   abc  "));
        assertNull(Auth.bearerToken(null));
        assertNull(Auth.bearerToken(""));
        assertNull(Auth.bearerToken("Bearer"));
        assertNull(Auth.bearerToken("Bearer "));
        assertNull(Auth.bearerToken("Basic abc"));
        assertNull(Auth.bearerToken("Bearer a b"));
        assertNull(Auth.bearerToken("abc"));
    }

    @Test
    void isAuthorizedChecksHeaderAndScope() {
        assertTrue(auth.isAuthorized("Bearer send-1", Scope.SENDER));
        assertFalse(auth.isAuthorized("Bearer send-1", Scope.BOUNCE));
        assertTrue(auth.isAuthorized("Bearer bounce-1", Scope.BOUNCE));
        assertFalse(auth.isAuthorized("Basic send-1", Scope.SENDER));
        assertFalse(auth.isAuthorized("send-1", Scope.SENDER));
    }

    @Test
    void fromConfigUsesSeparateKeySets() throws Exception {
        Config config = Config.fromJson("{\"apiKeys\":[\"s\"],\"bounces\":{\"apiKeys\":[\"b\"]}}");
        Auth a = Auth.fromConfig(config);
        assertTrue(a.isValid("s", Scope.SENDER));
        assertFalse(a.isValid("s", Scope.BOUNCE));
        assertTrue(a.isValid("b", Scope.BOUNCE));
        assertFalse(a.isValid("b", Scope.SENDER));
    }

    @Test
    void protectedRespondersOverHttp(@TempDir Path dataDir) throws Exception {
        Config config = Config.fromJson("{\"dataDir\": \"" + dataDir.toString().replace("\\", "\\\\")
                + "\", \"apiKeys\":[\"sender-key\"], \"bounces\":{\"apiKeys\":[\"bounce-key\"]}}");
        ServerSocket socket = new ServerSocket(0, 50, InetAddress.getLoopbackAddress());
        try (Main main = Main.start(config, socket)) {
            main.httpServer().responderRegistry.register("/test/send",
                    main.auth().protect(Scope.SENDER, AuthTest::ok));
            main.httpServer().responderRegistry.register("/test/bounce",
                    main.auth().protect(Scope.BOUNCE, AuthTest::ok));
            HttpClient client = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).build();

            assertEquals(200, get(client, main, "/test/send", "Bearer sender-key").statusCode());
            assertEquals(200, get(client, main, "/test/bounce", "Bearer bounce-key").statusCode());

            HttpResponse<String> crossed = get(client, main, "/test/bounce", "Bearer sender-key");
            assertEquals(401, crossed.statusCode());
            assertTrue(crossed.headers().firstValue("WWW-Authenticate").orElse("").startsWith("Bearer"));
            assertTrue(crossed.body().contains("unauthorized"));

            assertEquals(401, get(client, main, "/test/send", "Bearer bounce-key").statusCode());
            assertEquals(401, get(client, main, "/test/send", "Bearer wrong").statusCode());
            assertEquals(401, get(client, main, "/test/send", null).statusCode());
            assertEquals(401, get(client, main, "/test/send", "Basic c2VuZGVyLWtleQ==").statusCode());
            // /health stays unauthenticated
            assertEquals(200, get(client, main, "/health", null).statusCode());
        }
    }

    private static void ok(io.siggi.http.HTTPRequest request) throws Exception {
        byte[] body = "{\"ok\":true}".getBytes(StandardCharsets.UTF_8);
        request.response.setHeader("200 OK");
        request.response.setContentType("application/json");
        request.response.contentLength(body.length);
        request.response.write(body);
    }

    private static HttpResponse<String> get(HttpClient client, Main main, String path, String authorization)
            throws Exception {
        HttpRequest.Builder b = HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + main.port() + path))
                .timeout(Duration.ofSeconds(5)).GET();
        if (authorization != null) b.header("Authorization", authorization);
        return client.send(b.build(), HttpResponse.BodyHandlers.ofString());
    }
}
