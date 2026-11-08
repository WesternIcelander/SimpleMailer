package io.siggi.simplemailer.api;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import io.siggi.simplemailer.Main;
import io.siggi.simplemailer.config.Config;
import io.siggi.simplemailer.inbound.VerpAddress;
import io.siggi.simplemailer.model.Job;
import io.siggi.simplemailer.model.JobStatus;
import io.siggi.simplemailer.model.RecipientResult;
import io.siggi.simplemailer.model.SendRequest;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.net.InetAddress;
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
import java.util.List;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class BounceApiTest {
    private static final String SENDER_KEY = "sender-key";
    private static final String BOUNCE_KEY = "bounce-key";
    private static final String DOMAIN = "bounces.example.com";

    @TempDir
    Path dataDir;

    private Main main;
    private VerpAddress verp;
    private final HttpClient client = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).build();

    private void start(String intake) throws Exception {
        Config config = Config.fromJson("{\"dataDir\": \"" + dataDir.toString().replace("\\", "\\\\") + "\","
                + "\"apiKeys\": [\"" + SENDER_KEY + "\"], \"publicBaseUrl\": \"https://mail.example.com/\","
                + "\"bounces\": {\"domain\": \"" + DOMAIN + "\", \"secret\": \"s3cret\", \"intake\": [" + intake + "],"
                + "\"apiKeys\": [\"" + BOUNCE_KEY + "\"], \"smtpMaxMessageBytes\": 8192}}");
        ServerSocket socket = new ServerSocket(0, 50, InetAddress.getLoopbackAddress());
        main = Main.start(config, socket, null);
        main.setDeliveryQueue(j -> {
        });
        verp = VerpAddress.fromConfig(config);
    }

    @AfterEach
    void stop() throws Exception {
        if (main != null) main.close();
    }

    private Job deliveredJob(String... rcpts) throws Exception {
        SendRequest req = new SendRequest();
        req.id = UUID.randomUUID().toString();
        req.from = "sender@example.test";
        req.to = List.of(rcpts);
        req.subject = "hi";
        req.text = "hello";
        Job job = Job.create(req, "hash", Instant.now(), JobStatus.QUEUED);
        main.store().create(job.id, "hash", () -> job);
        return main.store().update(job.id, j -> {
            Instant now = Instant.now();
            for (RecipientResult r : j.recipients) r.markDelivered(now, "mx.test", 250, "OK", true);
            j.recomputeStatus(now);
        }).orElseThrow();
    }

    private static String crlf(String s) {
        return s.replace("\r\n", "\n").replace("\n", "\r\n");
    }

    private static String dsn(String messageId, String to, String rcpt) {
        return crlf("""
                Return-Path: <>
                From: MAILER-DAEMON@mx.example.org
                To: %s
                Subject: Undelivered Mail Returned to Sender
                Message-ID: %s
                MIME-Version: 1.0
                Content-Type: multipart/report; report-type=delivery-status; boundary="BND"

                --BND
                Content-Type: text/plain

                Your message could not be delivered.

                --BND
                Content-Type: message/delivery-status

                Reporting-MTA: dns; mx.example.org

                Final-Recipient: rfc822; %s
                Action: failed
                Status: 5.1.1
                Diagnostic-Code: smtp; 550 5.1.1 user unknown

                --BND--
                """.formatted(to, messageId, rcpt));
    }

    private HttpResponse<String> post(String query, String body, String contentType, String key, String... headers)
            throws Exception {
        HttpRequest.Builder b = HttpRequest.newBuilder(
                        URI.create("http://127.0.0.1:" + main.port() + "/v1/bounces" + query))
                .timeout(Duration.ofSeconds(5))
                .POST(HttpRequest.BodyPublishers.ofString(body));
        if (contentType != null) b.header("Content-Type", contentType);
        if (key != null) b.header("Authorization", "Bearer " + key);
        for (int i = 0; i < headers.length; i += 2) b.header(headers[i], headers[i + 1]);
        return client.send(b.build(), HttpResponse.BodyHandlers.ofString());
    }

    private static String q(String address) {
        return "?address=" + URLEncoder.encode(address, StandardCharsets.UTF_8);
    }

    private static JsonObject json(HttpResponse<String> r) {
        return JsonParser.parseString(r.body()).getAsJsonObject();
    }

    @Test
    void rawFormAppliesBounceAndResendIsDuplicate() throws Exception {
        start("\"api\"");
        Job job = deliveredJob("a@x.test", "b@x.test");
        String address = verp.encode(job.id, 0);
        String raw = dsn("<b1@mx.example.org>", address, "a@x.test");

        HttpResponse<String> r = post(q(address), raw, "message/rfc822", BOUNCE_KEY);
        assertEquals(202, r.statusCode(), r.body());
        JsonObject body = json(r);
        assertEquals("applied", body.get("outcome").getAsString());
        assertEquals(job.id, body.get("id").getAsString());
        assertEquals(0, body.get("recipientIndex").getAsInt());

        Job after = main.store().get(job.id).orElseThrow();
        assertEquals(RecipientResult.Status.BOUNCED, after.recipient(0).status);
        assertEquals(RecipientResult.Status.DELIVERED, after.recipient(1).status);
        assertEquals(JobStatus.PARTIALLY_FAILED, after.status);
        assertEquals(1, after.bounces.size());
        assertEquals("api", after.bounces.get(0).source);
        assertEquals("5.1.1", after.recipient(0).dsnStatus);
        assertArrayEquals(raw.getBytes(StandardCharsets.UTF_8),
                Files.readAllBytes(dataDir.resolve(after.bounces.get(0).file)));

        HttpResponse<String> again = post("", raw, "message/rfc822", BOUNCE_KEY, "X-Envelope-To", address);
        assertEquals(200, again.statusCode(), again.body());
        assertEquals("duplicate", json(again).get("outcome").getAsString());
        assertEquals(1, main.store().get(job.id).orElseThrow().bounces.size());
    }

    @Test
    void jsonFormAppliesBounce() throws Exception {
        start("\"api\"");
        Job job = deliveredJob("a@x.test");
        String address = verp.encode(job.id, 0);
        String report = "{\"address\":\"" + address + "\",\"action\":\"failed\",\"status\":\"5.1.1\","
                + "\"diagnostic\":\"550 5.1.1 user unknown\",\"finalRecipient\":\"a@x.test\"}";

        HttpResponse<String> r = post("", report, "application/json", BOUNCE_KEY);
        assertEquals(202, r.statusCode(), r.body());
        Job after = main.store().get(job.id).orElseThrow();
        assertEquals(JobStatus.BOUNCED, after.status);
        assertEquals("5.1.1", after.recipient(0).dsnStatus);
        assertEquals("550 5.1.1 user unknown", after.recipient(0).dsnDiagnostic);
        assertEquals("api", after.bounces.get(0).source);

        HttpResponse<String> again = post("", report, "application/json", BOUNCE_KEY);
        assertEquals(200, again.statusCode(), again.body());
    }

    @Test
    void delayedReportIsRecordedWithoutChangingStatus() throws Exception {
        start("\"api\"");
        Job job = deliveredJob("a@x.test");
        String address = verp.encode(job.id, 0);
        HttpResponse<String> r = post("", "{\"address\":\"" + address + "\",\"action\":\"delayed\",\"status\":\"4.2.2\"}",
                "application/json", BOUNCE_KEY);
        assertEquals(202, r.statusCode(), r.body());
        assertEquals("noted", json(r).get("outcome").getAsString());
        assertEquals(JobStatus.DELIVERED, main.store().get(job.id).orElseThrow().status);
    }

    @Test
    void multipartFormAppliesBounce() throws Exception {
        start("\"api\"");
        Job job = deliveredJob("a@x.test");
        String address = verp.encode(job.id, 0);
        String raw = dsn("<b2@mx.example.org>", address, "a@x.test");
        String boundary = "XYZBOUNDARY";
        String body = "--" + boundary + "\r\n"
                + "Content-Disposition: form-data; name=\"address\"\r\n\r\n" + address + "\r\n"
                + "--" + boundary + "\r\n"
                + "Content-Disposition: form-data; name=\"message\"; filename=\"bounce.eml\"\r\n"
                + "Content-Type: message/rfc822\r\n\r\n" + raw + "\r\n"
                + "--" + boundary + "--\r\n";
        HttpResponse<String> r = post("", body, "multipart/form-data; boundary=" + boundary, BOUNCE_KEY);
        assertEquals(202, r.statusCode(), r.body());
        assertEquals(JobStatus.BOUNCED, main.store().get(job.id).orElseThrow().status);
    }

    @Test
    void badTagNotBounceAddressAndUnknownJob() throws Exception {
        start("\"api\"");
        Job job = deliveredJob("a@x.test");
        String address = verp.encode(job.id, 0);
        String forged = address.substring(0, address.indexOf('@') - 1)
                + (address.charAt(address.indexOf('@') - 1) == '0' ? '1' : '0') + address.substring(address.indexOf('@'));
        String raw = dsn("<b3@mx.example.org>", forged, "a@x.test");

        HttpResponse<String> bad = post(q(forged), raw, "message/rfc822", BOUNCE_KEY);
        assertEquals(422, bad.statusCode(), bad.body());
        assertEquals("bad_tag", json(bad).get("error").getAsString());

        HttpResponse<String> badJson = post("", "{\"address\":\"" + forged + "\",\"status\":\"5.1.1\"}",
                "application/json", BOUNCE_KEY);
        assertEquals(422, badJson.statusCode(), badJson.body());

        HttpResponse<String> notBounce = post(q("someone@" + DOMAIN), raw, "message/rfc822", BOUNCE_KEY);
        assertEquals(422, notBounce.statusCode(), notBounce.body());
        assertEquals("not_bounce_address", json(notBounce).get("error").getAsString());

        String unknown = verp.encode(UUID.randomUUID().toString(), 0);
        HttpResponse<String> missing = post(q(unknown), raw, "message/rfc822", BOUNCE_KEY);
        assertEquals(404, missing.statusCode(), missing.body());

        Job after = main.store().get(job.id).orElseThrow();
        assertEquals(JobStatus.DELIVERED, after.status);
        assertTrue(after.bounces.isEmpty());
    }

    @Test
    void autoReplyIsIgnoredWith422() throws Exception {
        start("\"api\"");
        Job job = deliveredJob("a@x.test");
        String address = verp.encode(job.id, 0);
        String raw = crlf("""
                From: someone@x.test
                To: %s
                Subject: Out of office
                Message-ID: <ooo@x.test>
                Auto-Submitted: auto-replied

                I am away.
                """.formatted(address));
        HttpResponse<String> r = post(q(address), raw, "message/rfc822", BOUNCE_KEY);
        assertEquals(422, r.statusCode(), r.body());
        assertEquals("not_a_bounce", json(r).get("error").getAsString());
        Job after = main.store().get(job.id).orElseThrow();
        assertEquals(JobStatus.DELIVERED, after.status);
        assertEquals(1, after.bounces.size());
        assertTrue(after.bounces.get(0).ignored);
    }

    @Test
    void authAndRequestValidation() throws Exception {
        start("\"api\"");
        Job job = deliveredJob("a@x.test");
        String address = verp.encode(job.id, 0);
        String raw = dsn("<b4@mx.example.org>", address, "a@x.test");

        assertEquals(401, post(q(address), raw, "message/rfc822", SENDER_KEY).statusCode());
        assertEquals(401, post(q(address), raw, "message/rfc822", null).statusCode());
        // a bounce key can't send mail
        HttpRequest send = HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + main.port() + "/v1/messages"))
                .header("Authorization", "Bearer " + BOUNCE_KEY).header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString("{}")).build();
        assertEquals(401, client.send(send, HttpResponse.BodyHandlers.ofString()).statusCode());

        assertEquals(400, post("", raw, "message/rfc822", BOUNCE_KEY).statusCode());
        assertEquals(400, post("", "{\"status\":\"5.1.1\"}", "application/json", BOUNCE_KEY).statusCode());
        assertEquals(400, post("", "not json", "application/json", BOUNCE_KEY).statusCode());
        assertEquals(415, post(q(address), raw, "text/plain", BOUNCE_KEY).statusCode());
        assertEquals(413, post(q(address), "x".repeat(9000), "message/rfc822", BOUNCE_KEY).statusCode());

        HttpRequest get = HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + main.port() + "/v1/bounces"))
                .header("Authorization", "Bearer " + BOUNCE_KEY).GET().build();
        assertEquals(405, client.send(get, HttpResponse.BodyHandlers.ofString()).statusCode());

        assertEquals(JobStatus.DELIVERED, main.store().get(job.id).orElseThrow().status);
    }

    @Test
    void disabledIntakeIsNotExposed() throws Exception {
        start("");
        Job job = deliveredJob("a@x.test");
        String address = verp.encode(job.id, 0);
        HttpResponse<String> r = post(q(address), dsn("<b5@mx.example.org>", address, "a@x.test"),
                "message/rfc822", BOUNCE_KEY);
        assertEquals(404, r.statusCode(), r.body());
        assertFalse(main.store().get(job.id).orElseThrow().status == JobStatus.BOUNCED);
    }
}
