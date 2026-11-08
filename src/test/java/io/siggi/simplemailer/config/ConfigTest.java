package io.siggi.simplemailer.config;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class ConfigTest {
    @TempDir
    Path dir;

    @Test
    void defaultsWhenFileMissing() throws Exception {
        Config c = Config.load(dir.resolve("nope.json"), Map.of());
        assertEquals(8080, c.listenPort);
        assertEquals("data", c.dataDir);
        assertEquals(Duration.ofHours(48), c.maxRetryDuration);
        assertNull(c.jobRetention);
        assertTrue(c.bounces.intake.isEmpty());
        assertFalse(c.retrySchedule.isEmpty());
    }

    @Test
    void loadsFile() throws Exception {
        Path f = dir.resolve("config.json");
        Files.writeString(f, """
                {
                  "listenPort": 9000,
                  "publicBaseUrl": "https://mail.example.com/",
                  "apiKeys": ["k1", "k2"],
                  "heloName": "mx.example.com",
                  "connectTimeout": "10s",
                  "readTimeout": 120,
                  "retrySchedule": ["1m", "PT5M", "1h"],
                  "jobRetention": "30d",
                  "bounces": {"domain": "b.example.com", "secret": "s", "intake": ["SMTP", "api"],
                              "smtpPort": 2525, "apiKeys": ["bk"]},
                  "dkim": {"Example.com": {"selector": "sel", "keyFile": "dkim.pem"}}
                }
                """);
        Config c = Config.load(f, Map.of());
        assertEquals(9000, c.listenPort);
        assertEquals("https://mail.example.com", c.publicBaseUrl);
        assertEquals(List.of("k1", "k2"), c.apiKeys);
        assertEquals(Duration.ofSeconds(10), c.connectTimeout);
        assertEquals(Duration.ofSeconds(120), c.readTimeout);
        assertEquals(List.of(Duration.ofMinutes(1), Duration.ofMinutes(5), Duration.ofHours(1)), c.retrySchedule);
        assertEquals(Duration.ofDays(30), c.jobRetention);
        assertTrue(c.bounces.smtpIntake());
        assertTrue(c.bounces.apiIntake());
        assertEquals(2525, c.bounces.smtpPort);
        assertEquals("sel", c.dkim.get("example.com").selector);
    }

    @Test
    void envOverridesFile() throws Exception {
        Path f = dir.resolve("config.json");
        Files.writeString(f, """
                {"listenPort": 9000, "apiKeys": ["fromfile"], "bounces": {"domain": "file.example"}}
                """);
        Config c = Config.load(Map.of(
                "SIMPLEMAILER_CONFIG", f.toString(),
                "SIMPLEMAILER_LISTEN_PORT", "7000",
                "SIMPLEMAILER_API_KEYS", "a, b",
                "SIMPLEMAILER_ALLOW_HTTP_ATTACHMENT_URLS", "true",
                "SIMPLEMAILER_MAX_RETRY_DURATION", "12h",
                "SIMPLEMAILER_BOUNCES_SECRET", "envsecret",
                "SIMPLEMAILER_BOUNCES_SMTP_PORT", "2526",
                "SIMPLEMAILER_DKIM", "{\"x.com\":{\"selector\":\"s\",\"keyFile\":\"k.pem\"}}"));
        assertEquals(7000, c.listenPort);
        assertEquals(List.of("a", "b"), c.apiKeys);
        assertTrue(c.allowHttpAttachmentUrls);
        assertEquals(Duration.ofHours(12), c.maxRetryDuration);
        assertEquals("file.example", c.bounces.domain);
        assertEquals("envsecret", c.bounces.secret);
        assertEquals(2526, c.bounces.smtpPort);
        assertEquals("k.pem", c.dkim.get("x.com").keyFile);
    }

    @Test
    void envOnlyNoFile() throws Exception {
        Config c = Config.load(dir.resolve("missing.json"), Map.of("SIMPLEMAILER_HELO_NAME", "h.example"));
        assertEquals("h.example", c.heloName);
    }

    @Test
    void rejectsInvalid() {
        assertThrows(Config.ConfigException.class, () -> Config.fromJson("{\"listenPort\": 0}"));
        assertThrows(Config.ConfigException.class, () -> Config.fromJson("{\"bounces\": {\"intake\": [\"pop3\"]}}"));
        assertThrows(Config.ConfigException.class,
                () -> Config.fromJson("{\"bounces\": {\"intake\": [\"smtp\"]}}")); // missing domain/secret
        assertThrows(Config.ConfigException.class, () -> Config.fromJson(
                "{\"bounces\": {\"intake\": [\"api\"], \"domain\": \"d\", \"secret\": \"s\"}}")); // no bounce keys
        assertThrows(Config.ConfigException.class, () -> Config.fromJson(
                "{\"apiKeys\": [\"k\"], \"bounces\": {\"apiKeys\": [\"k\"]}}")); // shared key
        assertThrows(Config.ConfigException.class, () -> Config.fromJson("{\"connectTimeout\": \"soon\"}"));
        assertThrows(Config.ConfigException.class,
                () -> Config.load(dir.resolve("x.json"), Map.of("SIMPLEMAILER_LISTEN_PORT", "abc")));
    }

    @Test
    void rejectsMalformedFile() throws Exception {
        Path f = dir.resolve("bad.json");
        Files.writeString(f, "{not json");
        assertThrows(Config.ConfigException.class, () -> Config.load(f, Map.of()));
    }

    @Test
    void durationParsing() {
        assertEquals(Duration.ofMillis(500), Config.parseDuration("500ms"));
        assertEquals(Duration.ofSeconds(45), Config.parseDuration("45"));
        assertEquals(Duration.ofDays(2), Config.parseDuration("2d"));
        assertEquals(Duration.ofMinutes(90), Config.parseDuration("PT90M"));
        assertEquals("2d", Config.formatDuration(Duration.ofDays(2)));
        assertEquals("90m", Config.formatDuration(Duration.ofMinutes(90)));
    }

    @Test
    void jsonRoundTrip() throws Exception {
        Config c = Config.fromJson("{\"jobRetention\": \"7d\"}");
        Config again = Config.fromJson(c.toJson());
        assertEquals(Duration.ofDays(7), again.jobRetention);
        assertEquals(c.retrySchedule, again.retrySchedule);
    }

    @Test
    void upperSnake() {
        assertEquals("LISTEN_PORT", Config.toUpperSnake("listenPort"));
        assertEquals("SMTP_TLS_CERT", Config.toUpperSnake("smtpTlsCert"));
    }
}
