package io.siggi.simplemailer;

import io.siggi.simplemailer.config.Config;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Path;
import java.time.Duration;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class MainTest {
    @TempDir
    Path dataDir;

    private Main main;
    private final HttpClient client = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).build();

    @BeforeEach
    void start() throws Exception {
        Config config = Config.fromJson("{\"dataDir\": \"" + dataDir.toString().replace("\\", "\\\\") + "\"}");
        ServerSocket socket = new ServerSocket(0, 50, InetAddress.getLoopbackAddress());
        main = Main.start(config, socket);
    }

    @AfterEach
    void stop() throws Exception {
        main.close();
    }

    private HttpResponse<String> send(String method, String path) throws Exception {
        HttpRequest request = HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + main.port() + path))
                .timeout(Duration.ofSeconds(5))
                .method(method, HttpRequest.BodyPublishers.noBody())
                .build();
        return client.send(request, HttpResponse.BodyHandlers.ofString());
    }

    @Test
    void healthReturnsOkWithoutAuth() throws Exception {
        HttpResponse<String> response = send("GET", "/health");
        assertEquals(200, response.statusCode());
        assertTrue(response.headers().firstValue("Content-Type").orElse("").startsWith("application/json"));
        assertEquals("{\"status\":\"ok\"}", response.body());
    }

    @Test
    void healthRejectsOtherMethods() throws Exception {
        HttpResponse<String> response = send("POST", "/health");
        assertEquals(405, response.statusCode());
    }

    @Test
    void unknownPathIs404() throws Exception {
        assertEquals(404, send("GET", "/nope").statusCode());
        assertEquals(404, send("GET", "/health/extra").statusCode());
    }
}
