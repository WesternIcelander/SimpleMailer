package io.siggi.simplemailer.mime;

import io.siggi.simplemailer.config.Config;
import io.siggi.simplemailer.model.Job;
import io.siggi.simplemailer.model.JobStatus;
import io.siggi.simplemailer.model.RecipientResult;
import io.siggi.simplemailer.model.SendRequest;
import io.siggi.simplemailer.store.JobStore;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class JobPreparerTest {
    @TempDir
    Path dataDir;

    private TestHttpServer server;
    private JobStore store;
    private Config config;
    private final List<Job> queued = new CopyOnWriteArrayList<>();
    private final List<Job> failed = new CopyOnWriteArrayList<>();

    @BeforeEach
    void start() throws Exception {
        server = new TestHttpServer();
        store = new JobStore(dataDir);
        config = Config.fromJson("{\"heloName\": \"mx.example.com\", \"maxAttachmentBytes\": 1000,"
                + " \"maxMessageBytes\": 1500, \"allowHttpAttachmentUrls\": true}");
    }

    @AfterEach
    void stop() throws Exception {
        server.close();
    }

    private JobPreparer preparer() {
        return new JobPreparer(config, store, server.fetcher(), Runnable::run, queued::add, failed::add);
    }

    private static SendRequest.Attachment url(String url, String filename) {
        SendRequest.Attachment a = new SendRequest.Attachment();
        a.url = url;
        a.filename = filename;
        return a;
    }

    /** Creates a preparing job; {@code stored} maps attachment index to content already in payloads/{uuid}/. */
    private String createJob(List<SendRequest.Attachment> attachments, Map<Integer, byte[]> stored) throws Exception {
        SendRequest send = new SendRequest();
        send.id = UUID.randomUUID().toString();
        send.from = "sender@example.com";
        send.to = List.of("a@x.com", "b@y.org");
        send.subject = "Invoice";
        send.text = "see attached";
        send.attachments = new ArrayList<>(attachments);
        assertTrue(send.validate().isEmpty(), send.validate().toString());
        store.create(send.id, JobStore.payloadHash(send), () -> {
            for (Map.Entry<Integer, byte[]> e : stored.entrySet()) {
                JobStore.writeAtomic(MessagePayload.attachmentFile(store, send.id, e.getKey()), e.getValue());
            }
            return Job.create(send, "x", Instant.now(), JobStatus.PREPARING);
        });
        return send.id;
    }

    private Job job(String id) throws Exception {
        return store.get(id).orElseThrow();
    }

    @Test
    void fetchesBuildsAndQueues() throws Exception {
        server.ok("/invoice", "application/pdf", "%PDF-fake".getBytes(StandardCharsets.UTF_8));
        SendRequest.Attachment typed = url(server.url("/invoice"), "typed.pdf");
        typed.contentType = "application/x-custom";
        server.ok("/typed", "application/pdf", "typed".getBytes(StandardCharsets.UTF_8));
        typed.url = server.url("/typed");
        SendRequest.Attachment inlineBytes = new SendRequest.Attachment();
        inlineBytes.content = "AQID";
        inlineBytes.filename = "b.bin";
        String id = createJob(List.of(url(server.url("/invoice"), "invoice.pdf"), inlineBytes, typed),
                Map.of(1, new byte[]{1, 2, 3}));

        Job result = preparer().prepare(id).orElseThrow();

        assertEquals(JobStatus.QUEUED, result.status);
        assertEquals(JobStatus.QUEUED, job(id).status);
        assertEquals(1, queued.size());
        assertEquals(id, queued.get(0).id);
        assertTrue(failed.isEmpty());
        assertEquals("%PDF-fake", Files.readString(MessagePayload.attachmentFile(store, id, 0)));
        // content type taken from the response unless the caller gave one
        assertEquals("application/pdf", job(id).request.attachments.get(0).contentType);
        assertEquals("application/x-custom", job(id).request.attachments.get(2).contentType);
        String eml = Files.readString(store.payloadFile(id), StandardCharsets.ISO_8859_1);
        assertTrue(eml.contains("Content-Type: application/pdf; name=invoice.pdf")
                || eml.contains("Content-Type: application/pdf;"), eml);
        assertTrue(eml.contains("application/x-custom"), eml);
        assertTrue(eml.contains("filename=invoice.pdf"), eml);
    }

    @Test
    void redirectToLoopbackFailsTheJob() throws Exception {
        server.redirect("/r", "http://127.0.0.1:" + server.port() + "/secret");
        server.ok("/secret", "text/plain", "internal".getBytes(StandardCharsets.UTF_8));
        String id = createJob(List.of(url(server.url("/r"), "a.txt")), Map.of());

        preparer().prepare(id);

        Job job = job(id);
        assertEquals(JobStatus.FAILED, job.status);
        assertEquals(JobPreparer.ATTACHMENT_FETCH_FAILED, job.error);
        assertTrue(job.errorMessage.startsWith("attachments[0]: "), job.errorMessage);
        for (RecipientResult r : job.recipients) {
            assertEquals(RecipientResult.Status.FAILED, r.status);
            assertEquals(JobPreparer.ATTACHMENT_FETCH_FAILED, r.error);
        }
        assertFalse(Files.exists(store.payloadFile(id)), "nothing is sent");
        assertFalse(server.requests.contains("/secret"));
        assertEquals(1, failed.size());
        assertTrue(queued.isEmpty());
    }

    @Test
    void oversizeFileFailsTheJob() throws Exception {
        server.ok("/big", "application/octet-stream", new byte[1001]);
        String id = createJob(List.of(url(server.url("/big"), "big.bin")), Map.of());
        preparer().prepare(id);
        Job job = job(id);
        assertEquals(JobStatus.FAILED, job.status);
        assertTrue(job.errorMessage.contains("larger than 1000"), job.errorMessage);
        assertFalse(Files.exists(MessagePayload.attachmentFile(store, id, 0)));
    }

    @Test
    void totalSizeCapCountsStoredAttachments() throws Exception {
        server.ok("/a", "application/octet-stream", new byte[600]);
        SendRequest.Attachment stored = new SendRequest.Attachment();
        stored.content = "AA==";
        stored.filename = "stored.bin";
        // 1000 stored + 600 fetched > maxMessageBytes 1500, although each is within maxAttachmentBytes
        String id = createJob(List.of(stored, url(server.url("/a"), "a.bin")), Map.of(0, new byte[1000]));
        preparer().prepare(id);
        Job job = job(id);
        assertEquals(JobStatus.FAILED, job.status);
        assertTrue(job.errorMessage.contains("total"), job.errorMessage);
    }

    @Test
    void alreadyFetchedFilesAreNotFetchedAgain() throws Exception {
        server.ok("/b", "text/plain", "second".getBytes(StandardCharsets.UTF_8));
        // attachment 0 was fetched before a restart; only attachment 1 is downloaded now
        String id = createJob(List.of(url(server.url("/a"), "a.txt"), url(server.url("/b"), "b.txt")),
                Map.of(0, "first".getBytes(StandardCharsets.UTF_8)));
        preparer().prepare(id);
        assertEquals(JobStatus.QUEUED, job(id).status);
        assertEquals(List.of("/b"), server.requests);
        assertEquals("first", Files.readString(MessagePayload.attachmentFile(store, id, 0)));
    }

    @Test
    void onlyPreparingJobsArePrepared() throws Exception {
        String id = createJob(List.of(url(server.url("/a"), "a.txt")), Map.of());
        store.update(id, j -> j.status = JobStatus.QUEUED);
        preparer().prepare(id);
        assertEquals(0, server.hits.get());
        assertTrue(queued.isEmpty());
    }

    @Test
    void resumeAllPreparesLeftoverJobsInTheBackground() throws Exception {
        server.ok("/a", "text/plain", "x".getBytes(StandardCharsets.UTF_8));
        String id = createJob(List.of(url(server.url("/a"), "a.txt")), Map.of());
        CountDownLatch done = new CountDownLatch(1);
        JobPreparer p = new JobPreparer(config, store, server.fetcher(),
                r -> Thread.ofVirtual().start(r), j -> {
                    queued.add(j);
                    done.countDown();
                }, failed::add);
        p.resumeAll();
        assertTrue(done.await(10, TimeUnit.SECONDS));
        assertEquals(JobStatus.QUEUED, job(id).status);
    }
}
