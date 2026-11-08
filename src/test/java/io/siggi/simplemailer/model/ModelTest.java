package io.siggi.simplemailer.model;

import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;
import java.util.Map;

import static io.siggi.simplemailer.model.RecipientResult.Status.BOUNCED;
import static io.siggi.simplemailer.model.RecipientResult.Status.DEFERRED;
import static io.siggi.simplemailer.model.RecipientResult.Status.DELIVERED;
import static io.siggi.simplemailer.model.RecipientResult.Status.FAILED;
import static io.siggi.simplemailer.model.RecipientResult.Status.PENDING;
import static io.siggi.simplemailer.model.RecipientResult.Status.SENDING;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ModelTest {
    private static final String ID = "3f2b8c1e-4d5a-4b6c-8d7e-9f0a1b2c3d4e";

    private static SendRequest structured() {
        SendRequest r = new SendRequest();
        r.id = ID;
        r.from = "sender@example.com";
        r.to = List.of("a@x.com");
        r.cc = List.of("b@y.org", "A@X.com");
        r.bcc = List.of("c@x.com");
        r.subject = "Hi";
        r.text = "Hello";
        return r;
    }

    @Test
    void validStructuredRequest() {
        assertEquals(List.of(), structured().validate());
    }

    @Test
    void envelopeIsDedupedUnion() {
        assertEquals(List.of("a@x.com", "b@y.org", "c@x.com"), structured().envelopeRecipients());
    }

    @Test
    void validRawRequest() {
        SendRequest r = new SendRequest();
        r.id = ID;
        r.from = "sender@example.com";
        r.raw = "Subject: x\r\n\r\nbody";
        r.recipients = List.of("a@x.com");
        assertEquals(List.of(), r.validate());
        assertEquals(List.of("a@x.com"), r.envelopeRecipients());
    }

    @Test
    void rejectsBothRawAndStructured() {
        SendRequest r = structured();
        r.raw = "x";
        assertTrue(r.validate().stream().anyMatch(e -> e.contains("either raw")));
    }

    @Test
    void rejectsNeitherRawNorStructured() {
        SendRequest r = structured();
        r.subject = null;
        r.text = null;
        assertTrue(r.validate().stream().anyMatch(e -> e.contains("required")));
    }

    @Test
    void rejectsBadIdAndAddresses() {
        SendRequest r = structured();
        r.id = "not-a-uuid";
        r.to = List.of("nope", "a b@x.com");
        r.from = "x@";
        List<String> errors = r.validate();
        assertTrue(errors.contains("id must be a UUID"), errors.toString());
        assertTrue(errors.contains("to: invalid address 'nope'"), errors.toString());
        assertTrue(errors.contains("to: invalid address 'a b@x.com'"), errors.toString());
        assertTrue(errors.contains("from is not a valid address"), errors.toString());
    }

    @Test
    void rejectsNoRecipients() {
        SendRequest r = structured();
        r.to = null;
        r.cc = null;
        r.bcc = List.of();
        assertTrue(r.validate().contains("at least one of to/cc/bcc is required"));
    }

    @Test
    void rejectsReservedAndMultilineHeaders() {
        SendRequest r = structured();
        r.headers = Map.of("Bcc", "x@y.com", "X-Ok", "a\r\nInjected: yes");
        List<String> errors = r.validate();
        assertTrue(errors.stream().anyMatch(e -> e.contains("Bcc can't be set")), errors.toString());
        assertTrue(errors.stream().anyMatch(e -> e.contains("single line")), errors.toString());
    }

    @Test
    void attachmentNeedsExactlyOneSource() {
        SendRequest r = structured();
        SendRequest.Attachment a = new SendRequest.Attachment();
        a.filename = "f.pdf";
        a.url = "https://x/f.pdf";
        a.content = "AAAA";
        r.attachments = List.of(a);
        assertTrue(r.validate().stream().anyMatch(e -> e.contains("exactly one of part, content or url")));
        a.content = null;
        assertEquals(List.of(), r.validate());
    }

    @Test
    void addressSyntax() {
        assertTrue(SendRequest.isValidAddress("first.last+tag@sub.example.co.uk"));
        assertTrue(SendRequest.isValidAddress("x@[192.0.2.1]"));
        assertFalse(SendRequest.isValidAddress("x@localhost"));
        assertFalse(SendRequest.isValidAddress("<x@y.com>"));
        assertFalse(SendRequest.isValidAddress("x..y@y.com"));
        assertFalse(SendRequest.isValidAddress(null));
    }

    @Test
    void aggregateStatus() {
        assertNull(JobStatus.aggregate(List.of(DELIVERED, PENDING)));
        assertNull(JobStatus.aggregate(List.of(DEFERRED, SENDING)));
        assertEquals(JobStatus.DEFERRED, JobStatus.aggregate(List.of(DELIVERED, DEFERRED)));
        assertEquals(JobStatus.DELIVERED, JobStatus.aggregate(List.of(DELIVERED, DELIVERED)));
        assertEquals(JobStatus.FAILED, JobStatus.aggregate(List.of(FAILED, FAILED)));
        assertEquals(JobStatus.BOUNCED, JobStatus.aggregate(List.of(BOUNCED, FAILED)));
        assertEquals(JobStatus.PARTIALLY_FAILED, JobStatus.aggregate(List.of(DELIVERED, FAILED)));
        assertEquals(JobStatus.PARTIALLY_FAILED, JobStatus.aggregate(List.of(DELIVERED, BOUNCED)));
    }

    @Test
    void jobLifecycleAndJsonRoundTrip() {
        Instant t0 = Instant.parse("2026-01-01T00:00:00Z");
        SendRequest req = structured();
        req.callbackUrl = "https://caller/hook";
        Job job = Job.create(req, "abc123", t0, JobStatus.QUEUED);
        assertEquals(3, job.recipients.size());
        assertEquals(2, job.recipient(2).index);
        assertEquals("x.com", job.recipient(2).domain());
        assertEquals("https://caller/hook", job.callback.url);

        job.recipient(0).beginAttempt(t0);
        assertEquals(JobStatus.QUEUED, job.recomputeStatus(t0));
        job.recipient(0).markDelivered(t0, "mx.x.com", 250, "OK", true);
        job.recipient(1).markFailed(t0, "mx.y.org", 550, "no such user", null);
        job.recipient(2).markDeferred(t0.plusSeconds(60), "mx.x.com", 451, "try later", null);
        assertEquals(JobStatus.DEFERRED, job.recomputeStatus(t0));
        assertEquals(1, job.unfinishedRecipients().size());
        job.recipient(2).markDelivered(t0, "mx.x.com", 250, "OK", true);
        assertEquals(JobStatus.PARTIALLY_FAILED, job.recomputeStatus(t0));

        String json = ModelJson.GSON.toJson(job);
        assertTrue(json.contains("\"status\":\"partially_failed\""), json);
        assertTrue(json.contains("\"createdAt\":\"2026-01-01T00:00:00Z\""), json);
        Job back = ModelJson.GSON.fromJson(json, Job.class);
        assertEquals(JobStatus.PARTIALLY_FAILED, back.status);
        assertEquals(t0, back.createdAt);
        assertEquals(FAILED, back.recipient(1).status);
        assertEquals(550, back.recipient(1).smtpCode);
        assertEquals(List.of("a@x.com"), back.request.to);
    }

    @Test
    void failJobFailsUnfinishedRecipients() {
        Job job = Job.create(structured(), "h", Instant.EPOCH, JobStatus.PREPARING);
        job.failJob(Instant.EPOCH, "ATTACHMENT_FETCH_FAILED", "404");
        assertEquals(JobStatus.FAILED, job.status);
        assertTrue(job.recipients.stream().allMatch(r -> r.status == FAILED
                && "ATTACHMENT_FETCH_FAILED".equals(r.error)));
    }
}
