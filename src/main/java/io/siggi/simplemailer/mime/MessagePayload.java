package io.siggi.simplemailer.mime;

import io.siggi.simplemailer.model.ModelJson;
import io.siggi.simplemailer.model.SendRequest;
import io.siggi.simplemailer.store.JobStore;

import java.io.IOException;
import java.io.InputStream;
import java.net.URLConnection;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

/**
 * Stores a structured job's attachment content and builds its message file (PLAN.md §3a, §4).
 *
 * <p>Each attachment's bytes live at {@code payloads/{uuid}/{index}}, whatever its source: uploaded file parts are
 * copied there, inline base64 is decoded there, and URL attachments are written there by the fetcher. Once every
 * attachment is present, {@link #buildMessage} streams the MIME message into {@code payloads/{uuid}.eml}, so retries
 * and restarts always send the same bytes.
 */
public final class MessagePayload {
    private MessagePayload() {
    }

    /** {@code payloads/{uuid}/{index}}: where attachment {@code index} of a job is stored. */
    public static Path attachmentFile(JobStore store, String id, int index) {
        return store.payloadDir(id).resolve(Integer.toString(index));
    }

    /**
     * Writes the content of every uploaded or base64 attachment to its {@link #attachmentFile}. URL attachments are
     * skipped; they are fetched later.
     *
     * @param uploads uploaded file parts by part name
     * @param decoded decoded base64 content by attachment index
     */
    public static void storeAttachments(JobStore store, SendRequest send, Map<String, Path> uploads,
                                        Map<Integer, byte[]> decoded) throws IOException {
        if (send.attachments == null || send.attachments.isEmpty()) return;
        Files.createDirectories(store.payloadDir(send.id));
        for (int i = 0; i < send.attachments.size(); i++) {
            SendRequest.Attachment a = send.attachments.get(i);
            Path target = attachmentFile(store, send.id, i);
            if (a.part != null) {
                Path upload = uploads.get(a.part);
                if (upload == null) throw new IllegalArgumentException("no uploaded part named " + a.part);
                try (InputStream in = Files.newInputStream(upload)) {
                    JobStore.writeAtomic(target, in);
                }
            } else if (a.content != null) {
                byte[] data = decoded.get(i);
                if (data == null) throw new IllegalArgumentException("attachment " + i + " was not decoded");
                JobStore.writeAtomic(target, data);
            }
        }
    }

    /** Builds the MIME message from the request and the stored attachment files and writes the payload file. */
    public static void buildMessage(JobStore store, SendRequest send, String heloName) throws IOException {
        MessageBuilder builder = MessageBuilder.fromRequest(send, heloName);
        if (send.attachments != null) {
            for (int i = 0; i < send.attachments.size(); i++) {
                SendRequest.Attachment a = send.attachments.get(i);
                String cid = a.inline ? a.effectiveCid() : null;
                builder.attachment(MessageBuilder.Attachment.of(a.filename, contentTypeOf(a), a.inline, cid,
                        attachmentFile(store, send.id, i)));
            }
        }
        MessageBuilder.Message message = builder.build();
        try (InputStream in = message.openStream()) {
            store.writePayload(send.id, in);
        }
    }

    /** The attachment's content type, or a guess from its filename, or {@code application/octet-stream}. */
    public static String contentTypeOf(SendRequest.Attachment a) {
        if (a.contentType != null && !a.contentType.isBlank()) return a.contentType;
        String guess = a.filename == null ? null : URLConnection.guessContentTypeFromName(a.filename);
        return guess != null ? guess : "application/octet-stream";
    }

    /**
     * The request as it is kept in the job file: a copy with base64 {@code content} removed, since that content is
     * already stored in the attachment files and would otherwise be rewritten with every job update.
     */
    public static SendRequest forJobFile(SendRequest send) {
        if (send.attachments == null || send.attachments.stream().noneMatch(a -> a != null && a.content != null)) {
            return send;
        }
        SendRequest copy = ModelJson.GSON.fromJson(ModelJson.GSON.toJsonTree(send), SendRequest.class);
        for (SendRequest.Attachment a : copy.attachments) {
            if (a != null) a.content = null;
        }
        return copy;
    }

    /** Deletes a job's attachment directory (cleanup after a failed create). */
    public static void deleteAttachments(JobStore store, String id) {
        Path dir = store.payloadDir(id);
        if (!Files.isDirectory(dir)) return;
        try (Stream<Path> walk = Files.walk(dir)) {
            List<Path> paths = walk.sorted(Comparator.reverseOrder()).toList();
            for (Path p : paths) Files.deleteIfExists(p);
        } catch (IOException ignored) {
            // best effort
        }
    }
}
