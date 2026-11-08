package io.siggi.simplemailer.api;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import io.siggi.http.HTTPRequest;
import io.siggi.simplemailer.model.Job;
import io.siggi.simplemailer.model.ModelJson;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.List;

/**
 * JSON response helpers for the API (PLAN.md §3).
 */
public final class Json {
    private Json() {
    }

    /** Sends {@code body} as JSON with the given status line (e.g. {@code "200 OK"}); responses are never cached. */
    public static void send(HTTPRequest request, String status, JsonElement body) throws IOException {
        byte[] bytes = ModelJson.GSON.toJson(body).getBytes(StandardCharsets.UTF_8);
        request.response.setHeader(status);
        request.response.doNotCache();
        request.response.setContentType("application/json; charset=utf-8");
        request.response.contentLength(bytes.length);
        request.response.write(bytes);
    }

    /** Sends {@code {"error": code, "message": message}}. */
    public static void sendError(HTTPRequest request, String status, String code, String message) throws IOException {
        send(request, status, error(code, message));
    }

    /** Sends {@code 400} with {@code {"error":"validation_failed","message":..., "errors":[...]}}. */
    public static void sendValidationErrors(HTTPRequest request, List<String> errors) throws IOException {
        JsonObject body = error("validation_failed", "the request is invalid");
        JsonArray list = new JsonArray();
        errors.forEach(list::add);
        body.add("errors", list);
        send(request, "400 Bad Request", body);
    }

    /** Sends {@code 405} with an {@code Allow} header. */
    public static void sendMethodNotAllowed(HTTPRequest request, String allow) throws IOException {
        request.response.setHeader("Allow", allow);
        sendError(request, "405 Method Not Allowed", "method_not_allowed", "use " + allow);
    }

    public static JsonObject error(String code, String message) {
        JsonObject body = new JsonObject();
        body.addProperty("error", code);
        if (message != null) body.addProperty("message", message);
        return body;
    }

    /**
     * Status JSON for {@code GET /v1/messages/{id}}: the job as persisted, without the request itself and the payload
     * hash (internal), plus {@code statusUrl}.
     */
    public static JsonObject jobStatus(Job job, String statusUrl) {
        JsonObject json = ModelJson.GSON.toJsonTree(job).getAsJsonObject();
        json.remove("request");
        json.remove("payloadHash");
        JsonObject out = new JsonObject();
        out.add("id", json.remove("id"));
        out.add("status", json.remove("status"));
        out.addProperty("statusUrl", statusUrl);
        json.entrySet().forEach(e -> out.add(e.getKey(), e.getValue()));
        return out;
    }
}
