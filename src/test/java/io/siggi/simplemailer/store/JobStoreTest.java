package io.siggi.simplemailer.store;

import io.siggi.simplemailer.model.Job;
import io.siggi.simplemailer.model.JobStatus;
import io.siggi.simplemailer.model.SendRequest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.*;

class JobStoreTest {
    @TempDir
    Path dataDir;

    private static SendRequest request(String id, String subject) {
        SendRequest r = new SendRequest();
        r.id = id;
        r.from = "a@example.com";
        r.to = List.of("b@example.org");
        r.subject = subject;
        r.text = "hello";
        return r;
    }

    @Test
    void createThenDuplicateThenConflict() throws Exception {
        JobStore store = new JobStore(dataDir);
        String id = UUID.randomUUID().toString();
        String hash = JobStore.payloadHash(request(id, "s"));

        JobStore.CreateResult first = store.create(id, hash, Job::new);
        assertEquals(JobStore.CreateOutcome.CREATED, first.outcome());
        assertEquals(id, first.job().id);
        assertEquals(hash, first.job().payloadHash);
        assertNotNull(first.job().createdAt);
        assertTrue(Files.exists(dataDir.resolve("jobs").resolve(id + ".json")));

        JobStore.CreateResult again = store.create(id, hash, () -> fail("factory must not run"));
        assertEquals(JobStore.CreateOutcome.DUPLICATE, again.outcome());
        assertEquals(hash, again.job().payloadHash);

        String other = JobStore.payloadHash(request(id, "different"));
        JobStore.CreateResult conflict = store.create(id, other, () -> fail("factory must not run"));
        assertEquals(JobStore.CreateOutcome.CONFLICT, conflict.outcome());
        assertEquals(hash, conflict.job().payloadHash);
    }

    @Test
    void idsAreCaseInsensitive() throws Exception {
        JobStore store = new JobStore(dataDir);
        String id = UUID.randomUUID().toString();
        store.create(id, "h", Job::new);
        assertEquals(JobStore.CreateOutcome.DUPLICATE,
                store.create(id.toUpperCase(), "h", Job::new).outcome());
        assertTrue(store.get(id.toUpperCase()).isPresent());
    }

    @Test
    void rejectsNonUuidIds() throws Exception {
        JobStore store = new JobStore(dataDir);
        assertThrows(IllegalArgumentException.class, () -> store.create("../../etc/passwd", "h", Job::new));
        assertTrue(store.get("../x").isEmpty());
        assertThrows(IllegalArgumentException.class, () -> store.payloadFile("../x"));
    }

    @Test
    void concurrentCreatesProduceExactlyOneJob() throws Exception {
        JobStore store = new JobStore(dataDir);
        String id = UUID.randomUUID().toString();
        int threads = 32;
        AtomicInteger factoryCalls = new AtomicInteger();
        CountDownLatch start = new CountDownLatch(1);
        List<Future<JobStore.CreateResult>> results = new ArrayList<>();
        try (ExecutorService pool = Executors.newVirtualThreadPerTaskExecutor()) {
            for (int i = 0; i < threads; i++) {
                results.add(pool.submit(() -> {
                    start.await();
                    return store.create(id, "hash", () -> {
                        factoryCalls.incrementAndGet();
                        return new Job();
                    });
                }));
            }
            start.countDown();
            int created = 0, duplicate = 0;
            for (Future<JobStore.CreateResult> f : results) {
                switch (f.get().outcome()) {
                    case CREATED -> created++;
                    case DUPLICATE -> duplicate++;
                    case CONFLICT -> fail("unexpected conflict");
                }
            }
            assertEquals(1, created);
            assertEquals(threads - 1, duplicate);
            assertEquals(1, factoryCalls.get());
        }
    }

    @Test
    void updateAndPersistAcrossInstances() throws Exception {
        JobStore store = new JobStore(dataDir);
        String id = UUID.randomUUID().toString();
        store.create(id, "h", Job::new);
        assertTrue(store.update(id, j -> j.status = JobStatus.SENDING).isPresent());
        assertTrue(store.update(UUID.randomUUID().toString(), j -> fail("must not run")).isEmpty());

        JobStore reopened = new JobStore(dataDir);
        Job job = reopened.get(id).orElseThrow();
        assertEquals(JobStatus.SENDING, job.status);
        assertEquals(List.of(id), reopened.listIds());
    }

    @Test
    void atomicWritesLeaveNoTempFilesAndReplace() throws Exception {
        JobStore store = new JobStore(dataDir);
        String id = UUID.randomUUID().toString();
        store.writePayload(id, "first".getBytes(StandardCharsets.UTF_8));
        store.writePayload(id, new ByteArrayInputStream("second".getBytes(StandardCharsets.UTF_8)));
        assertEquals("second", Files.readString(store.payloadFile(id)));
        try (var files = Files.list(dataDir.resolve("payloads"))) {
            assertEquals(List.of(store.payloadFile(id)), files.toList());
        }
    }

    @Test
    void staleTempFilesAreRemovedOnOpen() throws Exception {
        Path jobs = Files.createDirectories(dataDir.resolve("jobs"));
        Path stale = jobs.resolve(".abc.json.123.tmp");
        Files.writeString(stale, "partial");
        new JobStore(dataDir);
        assertFalse(Files.exists(stale));
    }

    @Test
    void failedWriteKeepsOldContent() throws Exception {
        Path target = dataDir.resolve("f.txt");
        JobStore.writeAtomic(target, "old".getBytes(StandardCharsets.UTF_8));
        var failing = new java.io.InputStream() {
            int n;

            @Override
            public int read() throws IOException {
                if (n++ > 3) throw new IOException("boom");
                return 'x';
            }
        };
        assertThrows(IOException.class, () -> JobStore.writeAtomic(target, failing));
        assertEquals("old", Files.readString(target));
        try (var files = Files.list(dataDir)) {
            assertEquals(List.of(target), files.toList());
        }
    }

    @Test
    void payloadHashIsCanonical() {
        String id = UUID.randomUUID().toString();
        SendRequest a = request(id, "s");
        SendRequest b = request(id, "s");
        assertEquals(JobStore.payloadHash(a), JobStore.payloadHash(b));
        assertEquals(64, JobStore.payloadHash(a).length());

        b.requireTls = true;
        assertNotEquals(JobStore.payloadHash(a), JobStore.payloadHash(b));

        // Uploaded file hashes count, independent of map order.
        String h1 = JobStore.payloadHash(a, Map.of("logo", "aa", "doc", "bb"));
        String h2 = JobStore.payloadHash(a, new java.util.LinkedHashMap<>(Map.of("doc", "bb", "logo", "aa")));
        assertEquals(h1, h2);
        assertNotEquals(h1, JobStore.payloadHash(a, Map.of("logo", "aa", "doc", "cc")));
        assertNotEquals(h1, JobStore.payloadHash(a));
    }

    @Test
    void canonicalJsonSortsKeysAndDropsNulls() {
        var el = com.google.gson.JsonParser.parseString("{\"b\":1,\"a\":{\"z\":null,\"y\":[{\"d\":2,\"c\":3}]}}");
        assertEquals("{\"a\":{\"y\":[{\"c\":3,\"d\":2}]},\"b\":1}", JobStore.canonicalJson(el));
    }

    @Test
    void sha256OfFile() throws Exception {
        Path f = dataDir.resolve("x");
        Files.writeString(f, "abc");
        assertEquals("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", JobStore.sha256Hex(f));
        assertEquals(JobStore.sha256Hex("abc".getBytes(StandardCharsets.UTF_8)), JobStore.sha256Hex(f));
    }
}
