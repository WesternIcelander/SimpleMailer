package io.siggi.simplemailer.store;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParseException;
import io.siggi.simplemailer.model.Job;
import io.siggi.simplemailer.model.ModelJson;
import io.siggi.simplemailer.model.SendRequest;
import io.siggi.tools.Digests;
import io.siggi.tools.Hex;

import java.io.IOException;
import java.io.InputStream;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.TreeMap;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.locks.ReentrantLock;

/**
 * File-backed job store (PLAN.md §4).
 *
 * <p>Layout under the data directory: {@code jobs/{uuid}.json} (job state including the payload hash),
 * {@code payloads/{uuid}.eml} (the built or raw message) and {@code payloads/{uuid}/} (fetched attachments). Every
 * write goes to a temporary file in the target directory first and is then moved into place with
 * {@link StandardCopyOption#ATOMIC_MOVE}, so a reader or a crash never sees a half-written file.
 *
 * <p>Every operation on one job runs under that job's lock. Locks live in a single {@link ConcurrentHashMap} and are
 * reference counted, so they are removed again when nobody holds or waits for them. {@link #create} checks for the
 * job file and creates it under the lock, so two concurrent POSTs with the same id can't both create a job.
 *
 * <p>Job ids must be UUIDs ({@link SendRequest#isValidUuid}); they are lower-cased, so ids that differ only in case
 * name the same job. This also keeps ids from escaping the data directory.
 */
public final class JobStore {
    private static final String JOB_SUFFIX = ".json";
    private static final String PAYLOAD_SUFFIX = ".eml";
    private static final String TMP_SUFFIX = ".tmp";

    private final Path jobsDir;
    private final Path payloadsDir;
    private final ConcurrentHashMap<String, LockEntry> locks = new ConcurrentHashMap<>();

    /** Opens (and creates if needed) the store under {@code dataDir}. */
    public JobStore(Path dataDir) throws IOException {
        this.jobsDir = dataDir.resolve("jobs");
        this.payloadsDir = dataDir.resolve("payloads");
        Files.createDirectories(jobsDir);
        Files.createDirectories(payloadsDir);
        deleteStaleTempFiles(jobsDir);
        deleteStaleTempFiles(payloadsDir);
    }

    // ---- creation / idempotency -------------------------------------------------------------------------------

    /** Outcome of {@link #create}. */
    public enum CreateOutcome {
        /** No job existed; the new job was written. */
        CREATED,
        /** A job with this id and the same payload hash already exists (idempotent replay). */
        DUPLICATE,
        /** A job with this id exists with a different payload hash. */
        CONFLICT
    }

    /** Result of {@link #create}: the outcome and the job now stored under that id (the new or the existing one). */
    public record CreateResult(CreateOutcome outcome, Job job) {
    }

    /**
     * Creates a job unless one with {@code id} already exists, atomically with respect to other calls for the same id.
     *
     * <p>If the job file exists, its payload hash is compared with {@code payloadHash}: equal gives
     * {@link CreateOutcome#DUPLICATE}, different gives {@link CreateOutcome#CONFLICT}, and {@code factory} isn't
     * called. Otherwise {@code factory} builds the job (it runs under the lock and may write the payload file via
     * {@link #writePayload}); the store sets its id, payload hash and timestamps if missing, and saves it.
     */
    public CreateResult create(String id, String payloadHash, IOSupplier<Job> factory) throws IOException {
        String key = normaliseId(id);
        if (payloadHash == null || payloadHash.isEmpty()) throw new IllegalArgumentException("payloadHash is required");
        return withLock(key, () -> {
            Optional<Job> existing = readJob(key);
            if (existing.isPresent()) {
                Job job = existing.get();
                CreateOutcome outcome = payloadHash.equals(job.payloadHash)
                        ? CreateOutcome.DUPLICATE : CreateOutcome.CONFLICT;
                return new CreateResult(outcome, job);
            }
            Job job = factory.get();
            if (job == null) throw new IllegalStateException("job factory returned null");
            job.id = key;
            job.payloadHash = payloadHash;
            Instant now = Instant.now();
            if (job.createdAt == null) job.createdAt = now;
            if (job.updatedAt == null) job.updatedAt = job.createdAt;
            writeJob(job);
            return new CreateResult(CreateOutcome.CREATED, job);
        });
    }

    // ---- reads and updates ------------------------------------------------------------------------------------

    /** Loads a job, or empty if there is none with this id (also for ids that aren't UUIDs). */
    public Optional<Job> get(String id) throws IOException {
        if (!SendRequest.isValidUuid(id)) return Optional.empty();
        String key = normaliseId(id);
        return withLock(key, () -> readJob(key));
    }

    /** Writes {@code job} (which must have a valid id), setting {@code updatedAt}. */
    public void save(Job job) throws IOException {
        String key = normaliseId(job.id);
        job.id = key;
        withLock(key, () -> {
            job.updatedAt = Instant.now();
            writeJob(job);
            return null;
        });
    }

    /**
     * Read-modify-write under the job's lock: loads the job, applies {@code change} and saves it (setting
     * {@code updatedAt}). Returns empty, without calling {@code change}, if the job doesn't exist.
     */
    public Optional<Job> update(String id, IOConsumer<Job> change) throws IOException {
        String key = normaliseId(id);
        return withLock(key, () -> {
            Optional<Job> loaded = readJob(key);
            if (loaded.isEmpty()) return Optional.empty();
            Job job = loaded.get();
            change.accept(job);
            job.id = key;
            job.updatedAt = Instant.now();
            writeJob(job);
            return Optional.of(job);
        });
    }

    /** Ids of all stored jobs (for the startup rescan, PLAN.md §4). */
    public List<String> listIds() throws IOException {
        List<String> ids = new ArrayList<>();
        try (DirectoryStream<Path> dir = Files.newDirectoryStream(jobsDir, "*" + JOB_SUFFIX)) {
            for (Path p : dir) {
                String name = p.getFileName().toString();
                String id = name.substring(0, name.length() - JOB_SUFFIX.length());
                if (SendRequest.isValidUuid(id)) ids.add(id);
            }
        }
        ids.sort(null);
        return ids;
    }

    /**
     * Runs {@code action} while holding the lock for {@code id}. Store methods called from inside it for the same id
     * re-enter the lock (it is reentrant).
     */
    public <T> T withLock(String id, IOSupplier<T> action) throws IOException {
        String key = normaliseId(id);
        LockEntry entry = locks.compute(key, (k, e) -> {
            if (e == null) e = new LockEntry();
            e.refs++;
            return e;
        });
        entry.lock.lock();
        try {
            return action.get();
        } finally {
            entry.lock.unlock();
            locks.compute(key, (k, e) -> --e.refs == 0 ? null : e);
        }
    }

    // ---- payload files ----------------------------------------------------------------------------------------

    /** {@code payloads/{uuid}.eml}: the built or raw message for a job. */
    public Path payloadFile(String id) {
        return payloadsDir.resolve(normaliseId(id) + PAYLOAD_SUFFIX);
    }

    /**
     * {@code payloads/{uuid}.dkim}: the job's {@code DKIM-Signature} header field, computed once and sent in front
     * of the payload on every attempt (absent when the message isn't signed).
     */
    public Path signatureFile(String id) {
        return payloadsDir.resolve(normaliseId(id) + ".dkim");
    }

    /** {@code payloads/{uuid}/}: directory for a job's fetched or uploaded attachments (not created here). */
    public Path payloadDir(String id) {
        return payloadsDir.resolve(normaliseId(id));
    }

    /** Atomically writes the payload file for a job. */
    public void writePayload(String id, byte[] message) throws IOException {
        writeAtomic(payloadFile(id), message);
    }

    /** Atomically writes the payload file for a job from a stream. */
    public void writePayload(String id, InputStream message) throws IOException {
        writeAtomic(payloadFile(id), message);
    }

    // ---- atomic file writes -----------------------------------------------------------------------------------

    /**
     * Writes {@code data} to {@code target} atomically: a temp file in the same directory is written and synced, then
     * moved over the target with {@link StandardCopyOption#ATOMIC_MOVE}.
     */
    public static void writeAtomic(Path target, byte[] data) throws IOException {
        writeAtomic(target, out -> {
            java.nio.ByteBuffer buf = java.nio.ByteBuffer.wrap(data);
            while (buf.hasRemaining()) out.write(buf);
        });
    }

    /** Like {@link #writeAtomic(Path, byte[])}, copying from a stream. */
    public static void writeAtomic(Path target, InputStream in) throws IOException {
        writeAtomic(target, out -> {
            // Not closed here: closing would close the channel before it is synced.
            in.transferTo(java.nio.channels.Channels.newOutputStream(out));
        });
    }

    private interface ChannelWriter {
        void write(FileChannel channel) throws IOException;
    }

    private static void writeAtomic(Path target, ChannelWriter writer) throws IOException {
        Path dir = target.toAbsolutePath().getParent();
        Files.createDirectories(dir);
        Path tmp = Files.createTempFile(dir, "." + target.getFileName() + ".", TMP_SUFFIX);
        boolean moved = false;
        try {
            try (FileChannel ch = FileChannel.open(tmp, StandardOpenOption.WRITE, StandardOpenOption.TRUNCATE_EXISTING)) {
                writer.write(ch);
                ch.force(true);
            }
            try {
                Files.move(tmp, target, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
            } catch (AtomicMoveNotSupportedException e) {
                Files.move(tmp, target, StandardCopyOption.REPLACE_EXISTING);
            }
            moved = true;
        } finally {
            if (!moved) Files.deleteIfExists(tmp);
        }
    }

    private static void deleteStaleTempFiles(Path dir) throws IOException {
        try (DirectoryStream<Path> stream = Files.newDirectoryStream(dir, ".*" + TMP_SUFFIX)) {
            for (Path p : stream) Files.deleteIfExists(p);
        }
    }

    // ---- payload hash -----------------------------------------------------------------------------------------

    /**
     * Payload hash for idempotency (PLAN.md §3a, §4): SHA-256 (hex) of the canonicalised request JSON together with
     * the SHA-256 of each uploaded file, keyed by multipart part name.
     *
     * <p>Canonical form: object keys sorted, nulls dropped, no whitespace. The request is serialised through the
     * model, so fields the server doesn't know are ignored and an absent boolean equals {@code false}. Inline base64
     * attachments are part of the JSON; URL attachments count only by their URL string.
     */
    public static String payloadHash(SendRequest request, Map<String, String> uploadedFileHashes) {
        JsonObject root = new JsonObject();
        root.add("request", ModelJson.GSON.toJsonTree(request));
        JsonObject files = new JsonObject();
        if (uploadedFileHashes != null) {
            new TreeMap<>(uploadedFileHashes).forEach(files::addProperty);
        }
        root.add("files", files);
        return sha256Hex(canonicalJson(root).getBytes(StandardCharsets.UTF_8));
    }

    /** {@link #payloadHash(SendRequest, Map)} without uploaded files. */
    public static String payloadHash(SendRequest request) {
        return payloadHash(request, Map.of());
    }

    /** Serialises JSON with object keys sorted recursively and null members removed. */
    public static String canonicalJson(JsonElement element) {
        return ModelJson.GSON.toJson(canonicalise(element));
    }

    private static JsonElement canonicalise(JsonElement element) {
        if (element == null || element.isJsonNull()) return com.google.gson.JsonNull.INSTANCE;
        if (element.isJsonObject()) {
            TreeMap<String, JsonElement> sorted = new TreeMap<>();
            for (Map.Entry<String, JsonElement> e : element.getAsJsonObject().entrySet()) {
                if (e.getValue() == null || e.getValue().isJsonNull()) continue;
                sorted.put(e.getKey(), canonicalise(e.getValue()));
            }
            JsonObject out = new JsonObject();
            sorted.forEach(out::add);
            return out;
        }
        if (element.isJsonArray()) {
            JsonArray out = new JsonArray();
            for (JsonElement e : element.getAsJsonArray()) out.add(canonicalise(e));
            return out;
        }
        return element;
    }

    public static String sha256Hex(byte[] data) {
        return Hex.toHex(Digests.sha256().digest(data));
    }

    /** SHA-256 (hex) of a file's contents, for uploaded attachments. */
    public static String sha256Hex(Path file) throws IOException {
        MessageDigest md = Digests.sha256();
        try (InputStream in = Files.newInputStream(file)) {
            byte[] buf = new byte[65536];
            int n;
            while ((n = in.read(buf)) > 0) md.update(buf, 0, n);
        }
        return Hex.toHex(md.digest());
    }

    // ---- internals --------------------------------------------------------------------------------------------

    private Path jobFile(String key) {
        return jobsDir.resolve(key + JOB_SUFFIX);
    }

    private Optional<Job> readJob(String key) throws IOException {
        String json;
        try {
            json = Files.readString(jobFile(key), StandardCharsets.UTF_8);
        } catch (NoSuchFileException e) {
            return Optional.empty();
        }
        try {
            Job job = ModelJson.GSON.fromJson(json, Job.class);
            if (job == null) throw new IOException("empty job file for " + key);
            return Optional.of(job);
        } catch (JsonParseException e) {
            throw new IOException("corrupt job file for " + key, e);
        }
    }

    private void writeJob(Job job) throws IOException {
        writeAtomic(jobFile(job.id), ModelJson.GSON.toJson(job).getBytes(StandardCharsets.UTF_8));
    }

    private static String normaliseId(String id) {
        if (!SendRequest.isValidUuid(id)) throw new IllegalArgumentException("job id must be a UUID: " + id);
        return id.toLowerCase(Locale.ROOT);
    }

    private static final class LockEntry {
        final ReentrantLock lock = new ReentrantLock();
        int refs; // guarded by the ConcurrentHashMap bin lock (only touched inside compute)
    }

    @FunctionalInterface
    public interface IOSupplier<T> {
        T get() throws IOException;
    }

    @FunctionalInterface
    public interface IOConsumer<T> {
        void accept(T value) throws IOException;
    }
}
