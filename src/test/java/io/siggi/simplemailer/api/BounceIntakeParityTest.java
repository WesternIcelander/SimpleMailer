package io.siggi.simplemailer.api;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.sun.net.httpserver.HttpServer;
import io.siggi.simplemailer.Main;
import io.siggi.simplemailer.config.Config;
import io.siggi.simplemailer.inbound.VerpAddress;
import io.siggi.simplemailer.model.Job;
import io.siggi.simplemailer.model.JobStatus;
import io.siggi.simplemailer.model.RecipientResult;
import io.siggi.simplemailer.model.SendRequest;
import io.siggi.simplemailer.smtp.SmtpClient;
import io.siggi.simplemailer.smtp.SmtpResponse;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * PLAN.md §10 (bounces): the same bounce has the same effect whether it arrives at the inbound SMTP listener, as a
 * raw message at {@code POST /v1/bounces}, or as a pre-parsed JSON report; a resend through either intake is a
 * duplicate that fires no second callback; and a bad VERP tag is refused by both ({@code 550} / {@code 422}).
 * Runs the real {@link Main} wiring with both intakes enabled and a local HTTP server receiving the callbacks.
 */
class BounceIntakeParityTest {
    private static final String BOUNCE_KEY = "bounce-key";
    private static final String DOMAIN = "bounces.example.com";
    private static final Duration TIMEOUT = Duration.ofSeconds(10);

    @TempDir
    Path dataDir;

    private final LinkedBlockingQueue<String> callbacks = new LinkedBlockingQueue<>();
    private final HttpClient client = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).build();
    private HttpServer callbackServer;
    private Main main;
    private VerpAddress verp;

    @BeforeEach
    void setUp() throws Exception {
        callbackServer = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
        callbackServer.createContext("/hook", exchange -> {
            callbacks.add(new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8));
            exchange.sendResponseHeaders(204, -1);
            exchange.close();
        });
        callbackServer.start();

        Config config = new Config();
        config.dataDir = dataDir.toString();
        config.apiKeys = new ArrayList<>(List.of("sender-key"));
        config.publicBaseUrl = "https://mail.example.com/";
        config.heloName = "mx.bounces.test";
        config.callbackRetrySchedule = new ArrayList<>(List.of(Duration.ofMillis(50)));
        config.bounces.domain = DOMAIN;
        config.bounces.secret = "s3cret";
        config.bounces.intake = new ArrayList<>(List.of("smtp", "api"));
        config.bounces.apiKeys = new ArrayList<>(List.of(BOUNCE_KEY));
        main = Main.start(config, new ServerSocket(0, 50, InetAddress.getLoopbackAddress()),
                new ServerSocket(0, 50, InetAddress.getLoopbackAddress()));
        main.setDeliveryQueue(j -> {
        });
        verp = VerpAddress.fromConfig(config);
    }

    @AfterEach
    void tearDown() throws Exception {
        if (main != null) main.close();
        if (callbackServer != null) callbackServer.stop(0);
    }

    // ---- helpers ----------------------------------------------------------------------------------------------

    /** A job to two recipients, both delivered, with its delivery callback already sent. */
    private Job deliveredJob() throws Exception {
        SendRequest req = new SendRequest();
        req.id = UUID.randomUUID().toString();
        req.from = "sender@example.test";
        req.to = List.of("a@x.test", "b@x.test");
        req.subject = "hi";
        req.text = "hello";
        req.callbackUrl = "http://127.0.0.1:" + callbackServer.getAddress().getPort() + "/hook";
        Job job = Job.create(req, "hash", Instant.now(), JobStatus.QUEUED);
        main.store().create(job.id, "hash", () -> job);
        return main.store().update(job.id, j -> {
            Instant now = Instant.now();
            for (RecipientResult r : j.recipients) r.markDelivered(now, "mx.test", 250, "OK", true);
            j.recomputeStatus(now);
            j.callback.terminalNotified = true;
        }).orElseThrow();
    }

    /** A Postfix-style RFC 3464 DSN for {@code a@x.test}, CRLF line endings. */
    private static String dsn(String messageId, String address) {
        return """
                Return-Path: <>
                From: MAILER-DAEMON@mx.example.org (Mail Delivery System)
                To: %s
                Subject: Undelivered Mail Returned to Sender
                Message-ID: %s
                Auto-Submitted: auto-replied
                MIME-Version: 1.0
                Content-Type: multipart/report; report-type=delivery-status; boundary="BND"

                --BND
                Content-Type: text/plain; charset=us-ascii

                Your message could not be delivered.
                .a line starting with a dot

                --BND
                Content-Type: message/delivery-status

                Reporting-MTA: dns; mx.example.org

                Final-Recipient: rfc822; a@x.test
                Action: failed
                Status: 5.1.1
                Diagnostic-Code: smtp; 550 5.1.1 user unknown

                --BND
                Content-Type: text/rfc822-headers

                From: sender@example.test
                To: a@x.test
                Subject: hi

                --BND--
                """.formatted(address, messageId).replace("\n", "\r\n");
    }

    private static String jsonReport(String address) {
        return "{\"address\":\"" + address + "\",\"action\":\"failed\",\"status\":\"5.1.1\","
                + "\"diagnostic\":\"550 5.1.1 user unknown\",\"finalRecipient\":\"a@x.test\"}";
    }

    /** Sends {@code message} to {@code address} through the inbound SMTP listener; returns the DATA reply. */
    private SmtpResponse sendSmtp(String address, String message) throws IOException {
        try (SmtpClient c = SmtpClient.connect(new InetSocketAddress(InetAddress.getLoopbackAddress(),
                main.inboundSmtpServer().port()), "localhost", TIMEOUT, TIMEOUT)) {
            assertEquals(220, c.greeting().code());
            assertEquals(250, c.ehlo("mx.example.org").code());
            assertEquals(250, c.mail("").code());
            SmtpResponse rcpt = c.rcpt(address);
            if (rcpt.code() != 250) {
                c.quit();
                return rcpt;
            }
            SmtpResponse data = c.data(new ByteArrayInputStream(message.getBytes(StandardCharsets.UTF_8)));
            c.quit();
            return data;
        }
    }

    private HttpResponse<String> postApi(String query, String body, String contentType) throws Exception {
        HttpRequest req = HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + main.port() + "/v1/bounces" + query))
                .timeout(Duration.ofSeconds(5))
                .header("Content-Type", contentType)
                .header("Authorization", "Bearer " + BOUNCE_KEY)
                .POST(HttpRequest.BodyPublishers.ofString(body)).build();
        return client.send(req, HttpResponse.BodyHandlers.ofString());
    }

    private static String q(String address) {
        return "?address=" + URLEncoder.encode(address, StandardCharsets.UTF_8);
    }

    private JsonObject nextCallback() throws InterruptedException {
        String body = callbacks.poll(10, TimeUnit.SECONDS);
        assertNotNull(body, "expected a callback");
        return JsonParser.parseString(body).getAsJsonObject();
    }

    /**
     * What a bounce did to a job, without what legitimately differs between intakes (ids, timestamps, the intake
     * name, the parse kind, dedupe keys and stored file names).
     */
    private static String effect(Job job) {
        StringBuilder sb = new StringBuilder("job=").append(job.status);
        for (RecipientResult r : job.recipients) {
            sb.append(" | rcpt ").append(r.index).append(' ').append(r.address).append(' ').append(r.status)
                    .append(" dsn=").append(r.dsnStatus).append(" diag=").append(r.dsnDiagnostic)
                    .append(" bouncedAt=").append(r.bouncedAt != null)
                    .append(" deliveredAt=").append(r.deliveredAt != null);
        }
        sb.append(" | bounces=").append(job.bounces.size());
        for (Job.BounceRecord b : job.bounces) {
            sb.append(" [").append(b.recipientIndex).append(' ').append(b.recipient).append(" action=")
                    .append(b.action).append(" status=").append(b.status).append(" diag=").append(b.diagnostic)
                    .append(" ignored=").append(b.ignored).append(" final=").append(b.finalRecipient).append(']');
        }
        return sb.toString();
    }

    /** The same, from a callback event's {@code job} object. */
    private static String effect(JsonObject event) {
        JsonObject job = event.getAsJsonObject("job");
        StringBuilder sb = new StringBuilder(event.get("event").getAsString())
                .append(" job=").append(job.get("status").getAsString());
        for (JsonElement e : job.getAsJsonArray("recipients")) {
            JsonObject r = e.getAsJsonObject();
            sb.append(" | ").append(str(r, "address")).append(' ').append(str(r, "status"))
                    .append(" dsn=").append(str(r, "dsnStatus")).append(" diag=").append(str(r, "dsnDiagnostic"))
                    .append(" bouncedAt=").append(r.has("bouncedAt"));
        }
        JsonArray bounces = job.getAsJsonArray("bounces");
        sb.append(" | bounces=").append(bounces == null ? 0 : bounces.size());
        return sb.toString();
    }

    private static String str(JsonObject o, String key) {
        JsonElement e = o.get(key);
        return e == null || e.isJsonNull() ? null : e.getAsString();
    }

    // ---- tests ------------------------------------------------------------------------------------------------

    @Test
    void sameBounceHasSameEffectThroughEveryIntakeAndResendsAreDuplicates() throws Exception {
        Job viaSmtp = deliveredJob();
        Job viaRaw = deliveredJob();
        Job viaJson = deliveredJob();
        String smtpAddress = verp.encode(viaSmtp.id, 0);
        String rawAddress = verp.encode(viaRaw.id, 0);
        String jsonAddress = verp.encode(viaJson.id, 0);
        String smtpDsn = dsn("<smtp-dsn@mx.example.org>", smtpAddress);
        String rawDsn = dsn("<raw-dsn@mx.example.org>", rawAddress);

        // 1. inbound SMTP
        SmtpResponse data = sendSmtp(smtpAddress, smtpDsn);
        assertEquals(250, data.code(), data.toString());
        JsonObject smtpEvent = nextCallback();
        assertEquals(viaSmtp.id, smtpEvent.getAsJsonObject("job").get("id").getAsString());

        // 2. POST /v1/bounces, raw message
        HttpResponse<String> raw = postApi(q(rawAddress), rawDsn, "message/rfc822");
        assertEquals(202, raw.statusCode(), raw.body());
        assertEquals("applied", JsonParser.parseString(raw.body()).getAsJsonObject().get("outcome").getAsString());
        JsonObject rawEvent = nextCallback();
        assertEquals(viaRaw.id, rawEvent.getAsJsonObject("job").get("id").getAsString());

        // 3. POST /v1/bounces, pre-parsed JSON
        HttpResponse<String> json = postApi("", jsonReport(jsonAddress), "application/json");
        assertEquals(202, json.statusCode(), json.body());
        JsonObject jsonEvent = nextCallback();
        assertEquals(viaJson.id, jsonEvent.getAsJsonObject("job").get("id").getAsString());

        Job smtpAfter = main.store().get(viaSmtp.id).orElseThrow();
        Job rawAfter = main.store().get(viaRaw.id).orElseThrow();
        Job jsonAfter = main.store().get(viaJson.id).orElseThrow();

        // the expected effect, spelled out once
        assertEquals(JobStatus.PARTIALLY_FAILED, smtpAfter.status);
        assertEquals(RecipientResult.Status.BOUNCED, smtpAfter.recipient(0).status);
        assertEquals("5.1.1", smtpAfter.recipient(0).dsnStatus);
        assertEquals("550 5.1.1 user unknown", smtpAfter.recipient(0).dsnDiagnostic);
        assertEquals(RecipientResult.Status.DELIVERED, smtpAfter.recipient(1).status);
        assertEquals(1, smtpAfter.bounces.size());
        assertEquals("failed", smtpAfter.bounces.get(0).action);
        assertFalse(smtpAfter.bounces.get(0).ignored);
        assertEquals("bounced", smtpEvent.get("event").getAsString());
        assertEquals("partially_failed", smtpEvent.getAsJsonObject("job").get("status").getAsString());

        // ... and it is identical for all three intakes
        assertEquals(effect(smtpAfter), effect(rawAfter));
        assertEquals(effect(smtpAfter), effect(jsonAfter));
        assertEquals(effect(smtpEvent), effect(rawEvent));
        assertEquals(effect(smtpEvent), effect(jsonEvent));

        assertEquals("smtp", smtpAfter.bounces.get(0).source);
        assertEquals("api", rawAfter.bounces.get(0).source);
        assertEquals("api", jsonAfter.bounces.get(0).source);
        // both raw intakes store the message as received (SMTP dot-stuffing undone)
        assertArrayEquals(smtpDsn.getBytes(StandardCharsets.UTF_8),
                Files.readAllBytes(dataDir.resolve(smtpAfter.bounces.get(0).file)));
        assertArrayEquals(rawDsn.getBytes(StandardCharsets.UTF_8),
                Files.readAllBytes(dataDir.resolve(rawAfter.bounces.get(0).file)));

        // resends, each through the other intake where possible: duplicates, nothing changes, no callback
        HttpResponse<String> smtpViaApi = postApi(q(smtpAddress), smtpDsn, "message/rfc822");
        assertEquals(200, smtpViaApi.statusCode(), smtpViaApi.body());
        assertEquals("duplicate",
                JsonParser.parseString(smtpViaApi.body()).getAsJsonObject().get("outcome").getAsString());
        SmtpResponse rawViaSmtp = sendSmtp(rawAddress, rawDsn);
        assertEquals(250, rawViaSmtp.code(), rawViaSmtp.toString());
        SmtpResponse smtpAgain = sendSmtp(smtpAddress, smtpDsn);
        assertEquals(250, smtpAgain.code(), smtpAgain.toString());
        HttpResponse<String> jsonAgain = postApi("", jsonReport(jsonAddress), "application/json");
        assertEquals(200, jsonAgain.statusCode(), jsonAgain.body());

        assertNull(callbacks.poll(500, TimeUnit.MILLISECONDS), "a duplicate bounce must not fire a callback");
        assertEquals(effect(smtpAfter), effect(main.store().get(viaSmtp.id).orElseThrow()));
        assertEquals(effect(rawAfter), effect(main.store().get(viaRaw.id).orElseThrow()));
        assertEquals(effect(jsonAfter), effect(main.store().get(viaJson.id).orElseThrow()));
        try (var files = Files.list(dataDir.resolve("bounces"))) {
            assertEquals(2, files.count(), "only the two raw bounces are stored");
        }
    }

    @Test
    void badTagIsRefusedByEveryIntake() throws Exception {
        Job job = deliveredJob();
        String good = verp.encode(job.id, 0);
        String forged = good.replaceFirst("\\.[0-9a-f]{16}@", ".0000000000000000@");
        assertFalse(forged.equals(good));
        String raw = dsn("<forged@mx.example.org>", forged);

        assertEquals(550, sendSmtp(forged, raw).code());
        HttpResponse<String> api = postApi(q(forged), raw, "message/rfc822");
        assertEquals(422, api.statusCode(), api.body());
        assertEquals("bad_tag", JsonParser.parseString(api.body()).getAsJsonObject().get("error").getAsString());
        HttpResponse<String> json = postApi("", jsonReport(forged), "application/json");
        assertEquals(422, json.statusCode(), json.body());

        // a non-bounce address is refused the same way
        assertEquals(550, sendSmtp("postmaster@" + DOMAIN, raw).code());
        assertEquals(422, postApi(q("postmaster@" + DOMAIN), raw, "message/rfc822").statusCode());

        Job after = main.store().get(job.id).orElseThrow();
        assertEquals(JobStatus.DELIVERED, after.status);
        assertTrue(after.bounces.isEmpty());
        assertNull(callbacks.poll(300, TimeUnit.MILLISECONDS));
    }
}
