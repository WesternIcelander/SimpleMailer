package io.siggi.simplemailer.model;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonParseException;
import com.google.gson.TypeAdapter;
import com.google.gson.stream.JsonReader;
import com.google.gson.stream.JsonWriter;

import java.io.IOException;
import java.time.Instant;
import java.time.format.DateTimeParseException;

/**
 * Gson setup for the model classes: {@link Instant} as ISO-8601 strings, nulls omitted.
 */
public final class ModelJson {
    private ModelJson() {
    }

    /** A builder with the model type adapters registered, for callers that need extra settings. */
    public static GsonBuilder builder() {
        return new GsonBuilder()
                .registerTypeAdapter(Instant.class, new InstantAdapter().nullSafe())
                .disableHtmlEscaping();
    }

    public static final Gson GSON = builder().create();

    private static final class InstantAdapter extends TypeAdapter<Instant> {
        @Override
        public void write(JsonWriter out, Instant value) throws IOException {
            out.value(value.toString());
        }

        @Override
        public Instant read(JsonReader in) throws IOException {
            String s = in.nextString();
            try {
                return Instant.parse(s);
            } catch (DateTimeParseException e) {
                throw new JsonParseException("invalid timestamp: " + s, e);
            }
        }
    }
}
