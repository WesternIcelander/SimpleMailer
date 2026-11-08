package io.siggi.simplemailer.api;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParseException;
import com.google.gson.JsonParser;
import io.siggi.http.HTTPRequest;
import io.siggi.http.HTTPResponder;
import io.siggi.http.UploadedFile;
import io.siggi.simplemailer.inbound.BounceProcessor;
import io.siggi.simplemailer.inbound.BounceProcessor.Outcome;
import io.siggi.simplemailer.inbound.BounceProcessor.Result;
import io.siggi.simplemailer.inbound.BounceProcessor.Source;
import io.siggi.simplemailer.model.ModelJson;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.List;
import java.util.Locale;
import java.util.Objects;

/**
 * {@code POST /v1/bounces} (PLAN.md §6a, the {@code api} bounce intake): an external mail receiver reports a bounce
 * it received for the bounce domain. Registered only when {@code bounces.intake} includes {@code api}, behind the
 * bounce key scope ({@code bounces.apiKeys}). Everything goes through the shared {@link BounceProcessor}, so a bounce
 * has the same effect as one received by the SMTP intake, and the address is always checked against the VERP HMAC.
 *
 * <p>Request forms:
 * <ul>
 *     <li><b>Raw</b>: {@code Content-Type: message/rfc822} with the received message as the body. The envelope
 *     recipient (the VERP bounce address) comes from {@code ?address=} or the {@code X-Envelope-To} header; the
 *     optional envelope sender ({@code MAIL FROM}, empty or {@code <>} for the null path) from {@code ?sender=} or
 *     {@code X-Envelope-From}.</li>
 *     <li><b>Raw, multipart</b>: {@code multipart/form-data} with the message in a {@code message} part (file or
 *     field), and the address and sender in {@code address} / {@code sender} fields (or the query / headers as
 *     above).</li>
 *     <li><b>Pre-parsed JSON</b>: {@code application/json}
 *     {@code {"address", "action", "status", "diagnostic", "finalRecipient"}}; only {@code address} is required.</li>
 * </ul>
 *
 * <p>Responses: {@code 202} applied (or recorded as a note, e.g. {@code Action: delayed}); {@code 200} duplicate;
 * {@code 404} unknown or expired job; {@code 422} not a bounce address, bad VERP tag, or not a bounce (an
 * auto-reply, recorded as ignored); {@code 400} malformed request; {@code 413} message larger than
 * {@code bounces.smtpMaxMessageBytes} (the same limit as the SMTP intake); {@code 415} unsupported content type;
 * {@code 401} (from {@link Auth}) without a valid bounce key. Response bodies are
 * {@code {"outcome", "id", "recipientIndex", "eventId", "message"}}, plus {@code "error"} on 4xx.
 */
public final class BounceResponder implements HTTPResponder {
    public static final String PATH = "/v1/bounces";
    /** The {@code multipart/form-data} part holding the raw message. */
    public static final String MESSAGE_FIELD = "message";
    public static final String ADDRESS_FIELD = "address";
    public static final String SENDER_FIELD = "sender";
    public static final String ENVELOPE_TO_HEADER = "X-Envelope-To";
    public static final String ENVELOPE_FROM_HEADER = "X-Envelope-From";
    /** Largest JSON (pre-parsed) report accepted. */
    static final int MAX_JSON_BYTES = 64 * 1024;

    private final BounceProcessor processor;
    private final long maxMessageBytes;

    /**
     * @param processor       the shared bounce processor
     * @param maxMessageBytes largest raw bounce message accepted
     */
    public BounceResponder(BounceProcessor processor, long maxMessageBytes) {
        this.processor = Objects.requireNonNull(processor, "processor");
        if (maxMessageBytes <= 0) throw new IllegalArgumentException("maxMessageBytes must be positive");
        this.maxMessageBytes = maxMessageBytes;
    }

    /** The JSON (pre-parsed) form. */
    private static final class JsonReport {
        String address;
        String action;
        String status;
        String diagnostic;
        String finalRecipient;
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
            Json.sendError(request, "500 Internal Server Error", "internal_error", "could not process the bounce");
        }
    }

    private void handlePost(HTTPRequest request) throws IOException {
        String contentType = request.getHeader("Content-Type");
        String media = contentType == null ? "" : mediaType(contentType);
        Result result;
        switch (media) {
            case "application/json" -> {
                byte[] body = readLimited(request, MAX_JSON_BYTES);
                if (body == null) return;
                JsonReport report;
                try {
                    JsonElement json = JsonParser.parseString(new String(body, StandardCharsets.UTF_8));
                    if (!json.isJsonObject()) {
                        Json.sendValidationErrors(request, List.of("request body must be a JSON object"));
                        return;
                    }
                    report = ModelJson.GSON.fromJson(json, JsonReport.class);
                } catch (JsonParseException | IllegalStateException | NumberFormatException e) {
                    Json.sendValidationErrors(request, List.of("invalid JSON"));
                    return;
                }
                if (isBlank(report.address)) {
                    Json.sendValidationErrors(request, List.of("address is required"));
                    return;
                }
                result = processor.processReport(report.address.trim(),
                        new BounceProcessor.Report(report.action, report.status, report.diagnostic,
                                report.finalRecipient),
                        Source.API);
            }
            case "message/rfc822" -> {
                String address = firstNonBlank(request.get().get(ADDRESS_FIELD), request.getHeader(ENVELOPE_TO_HEADER));
                if (address == null) {
                    sendMissingAddress(request);
                    return;
                }
                byte[] raw = readLimited(request, maxMessageBytes);
                if (raw == null) return;
                if (raw.length == 0) {
                    Json.sendValidationErrors(request, List.of("request body (the bounce message) is required"));
                    return;
                }
                String sender = firstNonNull(request.get().get(SENDER_FIELD), request.getHeader(ENVELOPE_FROM_HEADER));
                result = processor.processMessage(raw, address.trim(), sender, Source.API);
            }
            case "multipart/form-data" -> {
                String address = firstNonBlank(request.post().get(ADDRESS_FIELD), request.get().get(ADDRESS_FIELD),
                        request.getHeader(ENVELOPE_TO_HEADER));
                if (address == null) {
                    sendMissingAddress(request);
                    return;
                }
                byte[] raw;
                String field = request.post().get(MESSAGE_FIELD);
                UploadedFile file = request.uploadedFiles().get(MESSAGE_FIELD);
                if (file != null) {
                    if (file.file.length() > maxMessageBytes) {
                        sendTooLarge(request);
                        return;
                    }
                    raw = Files.readAllBytes(file.file.toPath());
                } else if (field != null) {
                    raw = field.getBytes(StandardCharsets.UTF_8);
                    if (raw.length > maxMessageBytes) {
                        sendTooLarge(request);
                        return;
                    }
                } else {
                    raw = new byte[0];
                }
                if (raw.length == 0) {
                    Json.sendValidationErrors(request,
                            List.of("multipart/form-data requests need a '" + MESSAGE_FIELD + "' part with the message"));
                    return;
                }
                String sender = firstNonNull(request.post().get(SENDER_FIELD), request.get().get(SENDER_FIELD),
                        request.getHeader(ENVELOPE_FROM_HEADER));
                result = processor.processMessage(raw, address.trim(), sender, Source.API);
            }
            default -> {
                Json.sendError(request, "415 Unsupported Media Type", "unsupported_media_type",
                        "Content-Type must be message/rfc822, multipart/form-data or application/json");
                return;
            }
        }
        sendResult(request, result);
    }

    private static void sendResult(HTTPRequest request, Result result) throws IOException {
        String status;
        String error = null;
        switch (result.outcome()) {
            case APPLIED, NOTED -> status = "202 Accepted";
            case DUPLICATE -> status = "200 OK";
            case UNKNOWN_JOB -> {
                status = "404 Not Found";
                error = "not_found";
            }
            case NOT_BOUNCE_ADDRESS -> {
                status = "422 Unprocessable Entity";
                error = "not_bounce_address";
            }
            case BAD_TAG -> {
                status = "422 Unprocessable Entity";
                error = "bad_tag";
            }
            case IGNORED -> {
                status = "422 Unprocessable Entity";
                error = "not_a_bounce";
            }
            default -> throw new IllegalStateException("unexpected outcome " + result.outcome());
        }
        JsonObject body = new JsonObject();
        if (error != null) body.addProperty("error", error);
        body.addProperty("outcome", outcomeName(result.outcome()));
        if (result.jobId() != null) body.addProperty("id", result.jobId());
        if (result.recipientIndex() != null) body.addProperty("recipientIndex", result.recipientIndex());
        if (result.eventId() != null) body.addProperty("eventId", result.eventId());
        if (result.detail() != null) body.addProperty("message", result.detail());
        Json.send(request, status, body);
    }

    static String outcomeName(Outcome outcome) {
        return outcome.name().toLowerCase(Locale.ROOT);
    }

    private static void sendMissingAddress(HTTPRequest request) throws IOException {
        Json.sendValidationErrors(request, List.of("the envelope recipient is required: '" + ADDRESS_FIELD
                + "' parameter or " + ENVELOPE_TO_HEADER + " header"));
    }

    /** Reads the body, or sends {@code 413} and returns null if it is longer than {@code max}. */
    private byte[] readLimited(HTTPRequest request, long max) throws IOException {
        String declared = request.getHeader("Content-Length");
        if (declared != null) {
            try {
                if (Long.parseLong(declared.trim()) > max) {
                    sendTooLarge(request);
                    return null;
                }
            } catch (NumberFormatException ignored) {
                // read and count instead
            }
        }
        byte[] body = MessagesResponder.readBody(request.getInputStream(), max);
        if (body == null) sendTooLarge(request);
        return body;
    }

    private void sendTooLarge(HTTPRequest request) throws IOException {
        request.response.keepAlive(false);
        Json.sendError(request, "413 Payload Too Large", "too_large",
                "request body exceeds the bounce size limit");
    }

    private static String mediaType(String contentType) {
        int semi = contentType.indexOf(';');
        return (semi < 0 ? contentType : contentType.substring(0, semi)).trim().toLowerCase(Locale.ROOT);
    }

    private static boolean isBlank(String s) {
        return s == null || s.isBlank();
    }

    private static String firstNonBlank(String... values) {
        for (String v : values) {
            if (!isBlank(v)) return v;
        }
        return null;
    }

    private static String firstNonNull(String... values) {
        for (String v : values) {
            if (v != null) return v.trim();
        }
        return null;
    }
}
