package io.siggi.simplemailer.api;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParseException;
import com.google.gson.JsonParser;
import io.siggi.http.HTTPRequest;
import io.siggi.http.HTTPResponder;
import io.siggi.http.UploadedFile;
import io.siggi.simplemailer.config.Config;
import io.siggi.simplemailer.mime.MessagePayload;
import io.siggi.simplemailer.mime.RawMessage;
import io.siggi.simplemailer.model.Job;
import io.siggi.simplemailer.model.JobStatus;
import io.siggi.simplemailer.model.ModelJson;
import io.siggi.simplemailer.model.SendRequest;
import io.siggi.simplemailer.store.JobStore;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.function.Consumer;

/**
 * {@code POST /v1/messages} (PLAN.md §3): validates the request, persists the job and returns immediately. It never
 * touches SMTP; new jobs are handed to {@code enqueue}.
 *
 * <ul>
 *     <li>{@code 202} new job, with {@code Location} and {@code {"id","status","statusUrl"}}</li>
 *     <li>{@code 200} same id and identical payload: the current job status, nothing is enqueued again</li>
 *     <li>{@code 409} same id, different payload</li>
 *     <li>{@code 400} validation errors, {@code 413} body larger than {@code maxMessageBytes},
 *     {@code 415} unsupported content type</li>
 * </ul>
 *
 * <p>Two encodings: {@code application/json} (the JSON alone; attachments are base64 {@code content} or {@code url})
 * and {@code multipart/form-data} (the JSON in a {@code message} field, plus one file part per {@code part}
 * attachment). Uploaded and base64 attachments are stored under {@code payloads/{uuid}/} during the POST, and for
 * structured messages without URL attachments the MIME message is built right away.
 */
public final class MessagesResponder implements HTTPResponder {
    public static final String PATH = "/v1/messages";
    /** The {@code multipart/form-data} field holding the request JSON. */
    public static final String MESSAGE_FIELD = "message";

    private final Config config;
    private final JobStore store;
    private final Consumer<Job> enqueue;

    public MessagesResponder(Config config, JobStore store, Consumer<Job> enqueue) {
        this.config = config;
        this.store = store;
        this.enqueue = enqueue;
    }

    /** {@code publicBaseUrl/v1/messages/{id}}; the request Host isn't trusted behind a proxy. */
    public static String statusUrl(Config config, String id) {
        return config.publicBaseUrl + PATH + "/" + id;
    }

    @Override
    public void respond(HTTPRequest request) throws Exception {
        if (!request.method().equals("POST")) {
            Json.sendMethodNotAllowed(request, "POST");
            return;
        }
        try {
            handlePost(request);
        } catch (IOException e) {
            if (request.response.alreadyWrote()) throw e;
            Json.sendError(request, "500 Internal Server Error", "internal_error", "could not store the message");
        }
    }

    private void handlePost(HTTPRequest request) throws IOException {
        String contentType = request.getHeader("Content-Type");
        String media = contentType == null ? "" : mediaType(contentType);
        boolean multipart = media.equals("multipart/form-data");
        if (!multipart && !media.equals("application/json")) {
            Json.sendError(request, "415 Unsupported Media Type", "unsupported_media_type",
                    "Content-Type must be application/json or multipart/form-data");
            return;
        }

        // multipart/form-data was already parsed by SiggiHTTP (bounded by the upload limit, set to maxMessageBytes)
        Map<String, Path> uploads = new HashMap<>();
        Map<String, UploadedFile> uploadInfo = new HashMap<>();
        byte[] body;
        if (multipart) {
            String field = request.post().get(MESSAGE_FIELD);
            UploadedFile messageFile = request.uploadedFiles().get(MESSAGE_FIELD);
            if (field != null) {
                body = field.getBytes(StandardCharsets.UTF_8);
            } else if (messageFile != null) {
                if (messageFile.file.length() > config.maxMessageBytes) {
                    sendTooLarge(request);
                    return;
                }
                body = Files.readAllBytes(messageFile.file.toPath());
            } else {
                Json.sendValidationErrors(request,
                        List.of("multipart/form-data requests need a '" + MESSAGE_FIELD + "' field with the JSON"));
                return;
            }
            for (Map.Entry<String, UploadedFile> e : request.uploadedFiles().entrySet()) {
                if (e.getKey().equals(MESSAGE_FIELD)) continue;
                uploads.put(e.getKey(), e.getValue().file.toPath());
                uploadInfo.put(e.getKey(), e.getValue());
            }
        } else {
            long declared = contentLength(request);
            if (declared > config.maxMessageBytes) {
                sendTooLarge(request);
                return;
            }
            body = readBody(request.getInputStream(), config.maxMessageBytes);
            if (body == null) {
                sendTooLarge(request);
                return;
            }
        }
        if (body.length == 0) {
            Json.sendValidationErrors(request, List.of("request body is required"));
            return;
        }

        SendRequest send;
        try {
            JsonElement json = JsonParser.parseString(new String(body, StandardCharsets.UTF_8));
            if (!json.isJsonObject()) {
                Json.sendValidationErrors(request, List.of("request body must be a JSON object"));
                return;
            }
            send = ModelJson.GSON.fromJson(json, SendRequest.class);
        } catch (JsonParseException | IllegalStateException | NumberFormatException e) {
            Json.sendValidationErrors(request, List.of("invalid JSON: " + rootMessage(e)));
            return;
        }

        if (multipart) applyUploadDefaults(send, uploadInfo);
        List<String> errors = new ArrayList<>(send.validate());
        Map<Integer, byte[]> decoded = new HashMap<>();
        errors.addAll(validateAttachments(send, multipart, uploads, decoded));
        if (!errors.isEmpty()) {
            Json.sendValidationErrors(request, errors);
            return;
        }
        String tooLarge = oversizeAttachment(send, uploads, decoded);
        if (tooLarge != null) {
            Json.sendError(request, "413 Payload Too Large", "too_large", tooLarge);
            return;
        }

        send.id = send.id.toLowerCase(Locale.ROOT);
        Map<String, String> fileHashes = new TreeMap<>();
        for (String part : referencedParts(send)) {
            fileHashes.put(part, JobStore.sha256Hex(uploads.get(part)));
        }
        String hash = JobStore.payloadHash(send, fileHashes);
        boolean fetchLater = hasUrlAttachments(send);
        JobStatus initial = fetchLater ? JobStatus.PREPARING : JobStatus.QUEUED;
        JobStore.CreateResult result = store.create(send.id, hash, () -> {
            if (send.isRaw()) {
                // raw messages are stored as-is, apart from CRLF normalisation (PLAN.md §3a)
                store.writePayload(send.id, RawMessage.normalise(send.raw));
            } else {
                // uploaded and base64 attachments go to payloads/{uuid}/; URL attachments are fetched later and
                // the message is built then (PLAN.md §3a)
                try {
                    MessagePayload.storeAttachments(store, send, uploads, decoded);
                    if (!fetchLater) MessagePayload.buildMessage(store, send, config.heloName);
                } catch (IOException | RuntimeException e) {
                    MessagePayload.deleteAttachments(store, send.id);
                    throw e;
                }
            }
            return Job.create(MessagePayload.forJobFile(send), hash, Instant.now(), initial);
        });
        Job job = result.job();
        String statusUrl = statusUrl(config, job.id);

        switch (result.outcome()) {
            case CREATED -> {
                enqueue.accept(job);
                JsonObject out = new JsonObject();
                out.addProperty("id", job.id);
                out.addProperty("status", job.status.wireName());
                out.addProperty("statusUrl", statusUrl);
                request.response.setHeader("Location", statusUrl);
                Json.send(request, "202 Accepted", out);
            }
            case DUPLICATE -> {
                request.response.setHeader("Location", statusUrl);
                Json.send(request, "200 OK", Json.jobStatus(job, statusUrl));
            }
            case CONFLICT -> {
                JsonObject out = Json.error("conflict",
                        "a message with this id already exists with a different payload");
                out.addProperty("id", job.id);
                out.addProperty("statusUrl", statusUrl);
                Json.send(request, "409 Conflict", out);
            }
        }
    }

    /**
     * For {@code part} attachments, the uploaded file's name and content type stand in for a missing
     * {@code filename} / {@code contentType}. Applied before hashing, so they count towards the payload.
     */
    private static void applyUploadDefaults(SendRequest send, Map<String, UploadedFile> uploads) {
        if (send.isRaw() || send.attachments == null) return;
        for (SendRequest.Attachment a : send.attachments) {
            if (a == null || a.part == null) continue;
            UploadedFile f = uploads.get(a.part);
            if (f == null) continue;
            if ((a.filename == null || a.filename.isBlank()) && f.filename != null && !f.filename.isBlank()) {
                a.filename = f.filename;
            }
            if ((a.contentType == null || a.contentType.isBlank()) && f.contentType != null
                    && !f.contentType.isBlank()) {
                a.contentType = f.contentType.trim();
            }
        }
    }

    /**
     * Attachment source rules: {@code part} needs a {@code multipart/form-data} request and an uploaded file of that
     * name, and every uploaded file must be used; {@code content} must be base64 (decoded into {@code decoded} by
     * attachment index); {@code url} must be https (or http when {@code allowHttpAttachmentUrls}).
     */
    private List<String> validateAttachments(SendRequest send, boolean multipart, Map<String, Path> uploads,
                                             Map<Integer, byte[]> decoded) {
        List<String> errors = new ArrayList<>();
        if (send.isRaw()) {
            if (!uploads.isEmpty()) errors.add("file parts are not used with raw");
            return errors;
        }
        Set<String> used = new HashSet<>();
        for (int i = 0; send.attachments != null && i < send.attachments.size(); i++) {
            SendRequest.Attachment a = send.attachments.get(i);
            if (a == null) continue;
            String where = "attachments[" + i + "]";
            if (a.part != null) {
                if (!multipart) {
                    errors.add(where + ": part attachments require a multipart/form-data request");
                } else if (!uploads.containsKey(a.part)) {
                    errors.add(where + ": no file part named '" + a.part + "'");
                } else {
                    used.add(a.part);
                }
            }
            if (a.content != null) {
                try {
                    // The MIME decoder silently skips non-alphabet characters, so strip whitespace (line breaks)
                    // ourselves and use the strict decoder.
                    decoded.put(i, Base64.getDecoder().decode(a.content.replaceAll("\\s+", "")));
                } catch (IllegalArgumentException e) {
                    errors.add(where + ": content is not valid base64");
                }
            }
            if (a.url != null) {
                String lower = a.url.trim().toLowerCase(Locale.ROOT);
                boolean ok = lower.startsWith("https://")
                        || (config.allowHttpAttachmentUrls && lower.startsWith("http://"));
                if (!ok) {
                    errors.add(where + ": url must be " + (config.allowHttpAttachmentUrls ? "an http or https" : "an https")
                            + " URL");
                }
            }
        }
        for (String name : new TreeSet<>(uploads.keySet())) {
            if (!used.contains(name)) errors.add("file part '" + name + "' is not used by any attachment");
        }
        return errors;
    }

    /** An error message if an uploaded or base64 attachment is larger than {@code maxAttachmentBytes}, else null. */
    private String oversizeAttachment(SendRequest send, Map<String, Path> uploads, Map<Integer, byte[]> decoded)
            throws IOException {
        if (send.isRaw() || send.attachments == null) return null;
        for (int i = 0; i < send.attachments.size(); i++) {
            SendRequest.Attachment a = send.attachments.get(i);
            if (a == null) continue;
            long size = a.part != null ? Files.size(uploads.get(a.part))
                    : a.content != null ? decoded.get(i).length : 0;
            if (size > config.maxAttachmentBytes) {
                return "attachments[" + i + "] exceeds " + config.maxAttachmentBytes + " bytes";
            }
        }
        return null;
    }

    private static Set<String> referencedParts(SendRequest send) {
        Set<String> parts = new TreeSet<>();
        if (send.isRaw() || send.attachments == null) return parts;
        for (SendRequest.Attachment a : send.attachments) {
            if (a != null && a.part != null) parts.add(a.part);
        }
        return parts;
    }

    private static boolean hasUrlAttachments(SendRequest send) {
        if (send.isRaw() || send.attachments == null) return false;
        return send.attachments.stream().anyMatch(a -> a != null && a.url != null);
    }

    private void sendTooLarge(HTTPRequest request) throws IOException {
        request.response.keepAlive(false);
        Json.sendError(request, "413 Payload Too Large", "too_large",
                "request body exceeds " + config.maxMessageBytes + " bytes");
    }

    private static String mediaType(String contentType) {
        int semi = contentType.indexOf(';');
        return (semi < 0 ? contentType : contentType.substring(0, semi)).trim().toLowerCase(Locale.ROOT);
    }

    private static long contentLength(HTTPRequest request) {
        String value = request.getHeader("Content-Length");
        if (value == null) return -1;
        try {
            return Long.parseLong(value.trim());
        } catch (NumberFormatException e) {
            return -1;
        }
    }

    /** Reads the whole body, or returns null if it is longer than {@code max} bytes. A missing body reads as empty. */
    static byte[] readBody(InputStream in, long max) throws IOException {
        if (in == null) return new byte[0];
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] buf = new byte[16384];
        long total = 0;
        int n;
        while ((n = in.read(buf)) > 0) {
            total += n;
            if (total > max) return null;
            out.write(buf, 0, n);
        }
        return out.toByteArray();
    }

    private static String rootMessage(Throwable e) {
        Throwable t = e;
        while (t.getCause() != null && t.getCause() != t) t = t.getCause();
        return t.getMessage() != null ? t.getMessage() : t.getClass().getSimpleName();
    }
}
