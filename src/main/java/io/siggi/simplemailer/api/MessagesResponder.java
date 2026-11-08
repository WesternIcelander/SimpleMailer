package io.siggi.simplemailer.api;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParseException;
import com.google.gson.JsonParser;
import io.siggi.http.HTTPRequest;
import io.siggi.http.HTTPResponder;
import io.siggi.simplemailer.config.Config;
import io.siggi.simplemailer.model.Job;
import io.siggi.simplemailer.model.JobStatus;
import io.siggi.simplemailer.model.ModelJson;
import io.siggi.simplemailer.model.SendRequest;
import io.siggi.simplemailer.store.JobStore;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Locale;
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
 * <p>Only {@code application/json} is accepted here; {@code multipart/form-data} intake arrives with attachment
 * support (PLAN.md §11 step 2).
 */
public final class MessagesResponder implements HTTPResponder {
    public static final String PATH = "/v1/messages";

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
        if (contentType == null || !mediaType(contentType).equals("application/json")) {
            Json.sendError(request, "415 Unsupported Media Type", "unsupported_media_type",
                    "Content-Type must be application/json");
            return;
        }

        long declared = contentLength(request);
        if (declared > config.maxMessageBytes) {
            sendTooLarge(request);
            return;
        }
        byte[] body = readBody(request.getInputStream(), config.maxMessageBytes);
        if (body == null) {
            sendTooLarge(request);
            return;
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

        List<String> errors = new ArrayList<>(send.validate());
        errors.addAll(validateJsonAttachments(send));
        if (!errors.isEmpty()) {
            Json.sendValidationErrors(request, errors);
            return;
        }

        send.id = send.id.toLowerCase(Locale.ROOT);
        String hash = JobStore.payloadHash(send);
        JobStatus initial = hasUrlAttachments(send) ? JobStatus.PREPARING : JobStatus.QUEUED;
        JobStore.CreateResult result = store.create(send.id, hash,
                () -> Job.create(send, hash, Instant.now(), initial));
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
     * Attachment rules that only apply to JSON requests: no {@code part} sources (those need
     * {@code multipart/form-data}), {@code content} must be base64, and {@code url} must be https (or http when
     * {@code allowHttpAttachmentUrls}).
     */
    private List<String> validateJsonAttachments(SendRequest send) {
        List<String> errors = new ArrayList<>();
        if (send.isRaw() || send.attachments == null) return errors;
        for (int i = 0; i < send.attachments.size(); i++) {
            SendRequest.Attachment a = send.attachments.get(i);
            if (a == null) continue;
            String where = "attachments[" + i + "]";
            if (a.part != null) {
                errors.add(where + ": part attachments require a multipart/form-data request");
            }
            if (a.content != null) {
                try {
                    // The MIME decoder silently skips non-alphabet characters, so strip whitespace (line breaks)
                    // ourselves and use the strict decoder.
                    Base64.getDecoder().decode(a.content.replaceAll("\\s+", ""));
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
        return errors;
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
