package io.siggi.simplemailer.api;

import io.siggi.http.HTTPRequest;
import io.siggi.http.HTTPResponder;
import io.siggi.simplemailer.config.Config;
import io.siggi.simplemailer.model.Job;
import io.siggi.simplemailer.model.SendRequest;
import io.siggi.simplemailer.store.JobStore;

import java.io.IOException;
import java.util.Optional;

/**
 * {@code GET /v1/messages/{id}} (PLAN.md §3): the job's status JSON, or {@code 404} if there is no such job.
 * Registered for the {@code /v1/messages/} prefix.
 */
public final class StatusResponder implements HTTPResponder {
    public static final String PREFIX = MessagesResponder.PATH + "/";

    private final Config config;
    private final JobStore store;

    public StatusResponder(Config config, JobStore store) {
        this.config = config;
        this.store = store;
    }

    @Override
    public void respond(HTTPRequest request) throws Exception {
        String path = request.path();
        String id = path.startsWith(PREFIX) ? path.substring(PREFIX.length()) : "";
        if (!SendRequest.isValidUuid(id)) {
            Json.sendError(request, "404 Not Found", "not_found", "no such message");
            return;
        }
        if (!request.method().equals("GET")) {
            Json.sendMethodNotAllowed(request, "GET");
            return;
        }
        Optional<Job> job;
        try {
            job = store.get(id);
        } catch (IOException e) {
            Json.sendError(request, "500 Internal Server Error", "internal_error", "could not read the message status");
            return;
        }
        if (job.isEmpty()) {
            Json.sendError(request, "404 Not Found", "not_found", "no such message");
            return;
        }
        Job j = job.get();
        Json.send(request, "200 OK", Json.jobStatus(j, MessagesResponder.statusUrl(config, j.id)));
    }
}
