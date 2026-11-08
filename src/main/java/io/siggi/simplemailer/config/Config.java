package io.siggi.simplemailer.config;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParseException;
import com.google.gson.JsonParser;
import com.google.gson.JsonPrimitive;
import com.google.gson.TypeAdapter;
import com.google.gson.annotations.SerializedName;
import com.google.gson.stream.JsonReader;
import com.google.gson.stream.JsonToken;
import com.google.gson.stream.JsonWriter;

import java.io.IOException;
import java.io.Reader;
import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * Server configuration (PLAN.md §7), loaded from a JSON file and overridden by environment variables.
 *
 * <p>Environment variables are named {@code SIMPLEMAILER_} plus the field name in upper snake case; nested
 * {@code bounces} fields use {@code SIMPLEMAILER_BOUNCES_}, e.g. {@code SIMPLEMAILER_LISTEN_PORT},
 * {@code SIMPLEMAILER_BOUNCES_SMTP_PORT}. List values are comma separated, map values (e.g. {@code dkim}) are
 * JSON, durations accept {@code 30s}/{@code 5m}/{@code 2h}/{@code 1d}, ISO-8601 ({@code PT1M}) or plain seconds.
 * {@code SIMPLEMAILER_CONFIG} names the config file (default {@code config.json}; a missing file is allowed).
 */
public final class Config {
    public static final String ENV_PREFIX = "SIMPLEMAILER_";
    public static final String CONFIG_FILE_ENV = ENV_PREFIX + "CONFIG";
    public static final String DEFAULT_CONFIG_FILE = "config.json";

    public int listenPort = 8080;
    public String bindAddress = "0.0.0.0";
    public String publicBaseUrl = "http://localhost:8080";
    public List<String> apiKeys = new ArrayList<>();
    public String heloName = "localhost";

    public List<String> attachmentUrlAllowlist = new ArrayList<>();
    public long maxAttachmentBytes = 25L * 1024 * 1024;
    public boolean allowHttpAttachmentUrls = false;
    /** Overall time limit for fetching one URL attachment, redirects included. */
    public Duration attachmentFetchTimeout = Duration.ofSeconds(60);

    public Bounces bounces = new Bounces();

    public String dataDir = "data";
    public long maxMessageBytes = 35L * 1024 * 1024;
    public int maxConcurrentDeliveries = 50;
    public Duration connectTimeout = Duration.ofSeconds(30);
    public Duration readTimeout = Duration.ofMinutes(5);
    public List<Duration> retrySchedule = new ArrayList<>(List.of(
            Duration.ofMinutes(1), Duration.ofMinutes(5), Duration.ofMinutes(15),
            Duration.ofHours(1), Duration.ofHours(2), Duration.ofHours(4)));
    public Duration maxRetryDuration = Duration.ofHours(48);
    /** {@code null} means records are kept forever. */
    public Duration jobRetention = null;
    public String callbackSecret = null;
    /** Backoff between callback attempts; the last entry repeats (PLAN.md §6). */
    public List<Duration> callbackRetrySchedule = new ArrayList<>(List.of(
            Duration.ofSeconds(10), Duration.ofMinutes(1), Duration.ofMinutes(5), Duration.ofMinutes(15),
            Duration.ofHours(1), Duration.ofHours(2)));
    /** A callback event that still fails this long after it was created is given up. */
    public Duration callbackMaxRetryDuration = Duration.ofHours(24);
    /** Connect and response timeout for one callback POST. */
    public Duration callbackTimeout = Duration.ofSeconds(30);
    /**
     * SSRF guard for callback URLs: when true, a callback whose host resolves to a loopback, private, link-local or
     * other non-public address is refused (the event is given up, nothing is sent).
     */
    public boolean blockPrivateCallbackTargets = false;
    public Map<String, DkimKey> dkim = new LinkedHashMap<>();
    public List<String> trustedProxies = new ArrayList<>();

    public static final class Bounces {
        public String domain = null;
        public String secret = null;
        /** Any of {@code smtp}, {@code api}; empty disables bounce intake. */
        public List<String> intake = new ArrayList<>();
        public int smtpPort = 25;
        public String smtpTlsCert = null;
        public String smtpTlsKey = null;
        public List<String> apiKeys = new ArrayList<>();

        public boolean smtpIntake() {
            return intake.contains(INTAKE_SMTP);
        }

        public boolean apiIntake() {
            return intake.contains(INTAKE_API);
        }

        public static final String INTAKE_SMTP = "smtp";
        public static final String INTAKE_API = "api";
    }

    public static final class DkimKey {
        public String selector;
        public String keyFile;

        public DkimKey() {
        }

        public DkimKey(String selector, String keyFile) {
            this.selector = selector;
            this.keyFile = keyFile;
        }
    }

    private static final Gson GSON = new GsonBuilder()
            .registerTypeAdapter(Duration.class, new DurationAdapter().nullSafe())
            .setPrettyPrinting()
            .create();

    /** Loads using {@code SIMPLEMAILER_CONFIG} (or {@code config.json}) and the process environment. */
    public static Config load() throws IOException {
        return load(System.getenv());
    }

    public static Config load(Map<String, String> env) throws IOException {
        String file = env.getOrDefault(CONFIG_FILE_ENV, DEFAULT_CONFIG_FILE);
        return load(Path.of(file), env);
    }

    /** Loads {@code file} (skipped if it doesn't exist), applies {@code env} overrides, and validates. */
    public static Config load(Path file, Map<String, String> env) throws IOException {
        JsonObject json = new JsonObject();
        if (file != null && Files.exists(file)) {
            try (Reader reader = Files.newBufferedReader(file, StandardCharsets.UTF_8)) {
                JsonElement parsed = JsonParser.parseReader(reader);
                if (!parsed.isJsonObject()) {
                    throw new ConfigException(file + ": top level must be a JSON object");
                }
                json = parsed.getAsJsonObject();
            } catch (JsonParseException e) {
                throw new ConfigException(file + ": invalid JSON: " + e.getMessage(), e);
            }
        }
        applyEnv(json, Config.class, ENV_PREFIX, env);
        Config config;
        try {
            config = GSON.fromJson(json, Config.class);
        } catch (JsonParseException | IllegalArgumentException e) {
            throw new ConfigException("Invalid configuration: " + e.getMessage(), e);
        }
        config.normalise();
        config.validate();
        return config;
    }

    public static Config fromJson(String json) throws ConfigException {
        try {
            Config config = GSON.fromJson(json, Config.class);
            config.normalise();
            config.validate();
            return config;
        } catch (JsonParseException | IllegalArgumentException e) {
            throw new ConfigException("Invalid configuration: " + e.getMessage(), e);
        }
    }

    public String toJson() {
        return GSON.toJson(this);
    }

    /** Replace JSON nulls for collections/sections with defaults so the rest of the code never sees null. */
    private void normalise() {
        if (apiKeys == null) apiKeys = new ArrayList<>();
        if (attachmentUrlAllowlist == null) attachmentUrlAllowlist = new ArrayList<>();
        if (bounces == null) bounces = new Bounces();
        if (bounces.intake == null) bounces.intake = new ArrayList<>();
        if (bounces.apiKeys == null) bounces.apiKeys = new ArrayList<>();
        if (retrySchedule == null) retrySchedule = new ArrayList<>();
        if (callbackRetrySchedule == null) callbackRetrySchedule = new ArrayList<>();
        if (dkim == null) dkim = new LinkedHashMap<>();
        if (trustedProxies == null) trustedProxies = new ArrayList<>();
        bounces.intake.replaceAll(s -> s.trim().toLowerCase(Locale.ROOT));
        if (publicBaseUrl != null) {
            while (publicBaseUrl.endsWith("/")) publicBaseUrl = publicBaseUrl.substring(0, publicBaseUrl.length() - 1);
        }
        Map<String, DkimKey> lower = new LinkedHashMap<>();
        dkim.forEach((domain, key) -> lower.put(domain.toLowerCase(Locale.ROOT), key));
        dkim = lower;
    }

    private void validate() throws ConfigException {
        List<String> errors = new ArrayList<>();
        if (listenPort < 1 || listenPort > 65535) errors.add("listenPort must be 1-65535");
        if (isBlank(bindAddress)) errors.add("bindAddress is required");
        if (isBlank(publicBaseUrl)) errors.add("publicBaseUrl is required");
        if (isBlank(heloName)) errors.add("heloName is required");
        if (isBlank(dataDir)) errors.add("dataDir is required");
        if (maxMessageBytes <= 0) errors.add("maxMessageBytes must be positive");
        if (maxAttachmentBytes <= 0) errors.add("maxAttachmentBytes must be positive");
        if (maxConcurrentDeliveries <= 0) errors.add("maxConcurrentDeliveries must be positive");
        requirePositive(errors, "connectTimeout", connectTimeout);
        requirePositive(errors, "readTimeout", readTimeout);
        requirePositive(errors, "attachmentFetchTimeout", attachmentFetchTimeout);
        requirePositive(errors, "maxRetryDuration", maxRetryDuration);
        requirePositive(errors, "callbackMaxRetryDuration", callbackMaxRetryDuration);
        requirePositive(errors, "callbackTimeout", callbackTimeout);
        if (jobRetention != null && (jobRetention.isZero() || jobRetention.isNegative())) {
            errors.add("jobRetention must be positive (or omitted to keep forever)");
        }
        for (Duration d : retrySchedule) {
            if (d == null || d.isZero() || d.isNegative()) errors.add("retrySchedule entries must be positive");
        }
        for (Duration d : callbackRetrySchedule) {
            if (d == null || d.isZero() || d.isNegative()) errors.add("callbackRetrySchedule entries must be positive");
        }
        if (apiKeys.stream().anyMatch(Config::isBlank)) errors.add("apiKeys must not contain blank keys");
        for (String intake : bounces.intake) {
            if (!intake.equals(Bounces.INTAKE_SMTP) && !intake.equals(Bounces.INTAKE_API)) {
                errors.add("bounces.intake: unknown value '" + intake + "' (expected smtp or api)");
            }
        }
        if (bounces.smtpPort < 1 || bounces.smtpPort > 65535) errors.add("bounces.smtpPort must be 1-65535");
        if ((bounces.smtpTlsCert == null) != (bounces.smtpTlsKey == null)) {
            errors.add("bounces.smtpTlsCert and bounces.smtpTlsKey must be set together");
        }
        if (bounces.apiKeys.stream().anyMatch(Config::isBlank)) errors.add("bounces.apiKeys must not contain blank keys");
        if (!bounces.intake.isEmpty()) {
            if (isBlank(bounces.domain)) errors.add("bounces.domain is required when bounce intake is enabled");
            if (isBlank(bounces.secret)) errors.add("bounces.secret is required when bounce intake is enabled");
        }
        if (bounces.apiIntake() && bounces.apiKeys.isEmpty()) {
            errors.add("bounces.apiKeys is required when the api bounce intake is enabled");
        }
        for (String key : bounces.apiKeys) {
            if (apiKeys.contains(key)) errors.add("bounces.apiKeys must not reuse a sender API key");
        }
        dkim.forEach((domain, key) -> {
            if (key == null || isBlank(key.selector) || isBlank(key.keyFile)) {
                errors.add("dkim." + domain + " needs selector and keyFile");
            }
        });
        if (!errors.isEmpty()) {
            throw new ConfigException("Invalid configuration: " + String.join("; ", errors));
        }
    }

    private static void requirePositive(List<String> errors, String name, Duration d) {
        if (d == null || d.isZero() || d.isNegative()) errors.add(name + " must be positive");
    }

    private static boolean isBlank(String s) {
        return s == null || s.isBlank();
    }

    // ---- environment overrides ----

    private static void applyEnv(JsonObject json, Class<?> type, String prefix, Map<String, String> env)
            throws ConfigException {
        for (Field field : type.getFields()) {
            if (Modifier.isStatic(field.getModifiers())) continue;
            SerializedName sn = field.getAnnotation(SerializedName.class);
            String jsonName = sn != null ? sn.value() : field.getName();
            String envName = prefix + toUpperSnake(field.getName());
            Class<?> ft = field.getType();
            if (ft == Bounces.class) {
                JsonElement existing = json.get(jsonName);
                JsonObject child = existing != null && existing.isJsonObject() ? existing.getAsJsonObject() : new JsonObject();
                applyEnv(child, Bounces.class, envName + "_", env);
                if (!child.isEmpty() || existing != null) json.add(jsonName, child);
                continue;
            }
            String value = env.get(envName);
            if (value == null) continue;
            json.add(jsonName, envValueToJson(envName, ft, value));
        }
    }

    private static JsonElement envValueToJson(String envName, Class<?> type, String value) throws ConfigException {
        String v = value.trim();
        if (List.class.isAssignableFrom(type)) {
            JsonArray array = new JsonArray();
            for (String part : v.split(",")) {
                String p = part.trim();
                if (!p.isEmpty()) array.add(p);
            }
            return array;
        }
        if (Map.class.isAssignableFrom(type)) {
            try {
                JsonElement e = JsonParser.parseString(v);
                if (!e.isJsonObject()) throw new ConfigException(envName + " must be a JSON object");
                return e;
            } catch (JsonParseException e) {
                throw new ConfigException(envName + ": invalid JSON: " + e.getMessage(), e);
            }
        }
        if (type == int.class || type == long.class) {
            try {
                return new JsonPrimitive(Long.parseLong(v));
            } catch (NumberFormatException e) {
                throw new ConfigException(envName + " must be an integer", e);
            }
        }
        if (type == boolean.class) {
            if (v.equalsIgnoreCase("true") || v.equals("1")) return new JsonPrimitive(true);
            if (v.equalsIgnoreCase("false") || v.equals("0")) return new JsonPrimitive(false);
            throw new ConfigException(envName + " must be true or false");
        }
        return new JsonPrimitive(v);
    }

    static String toUpperSnake(String camel) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < camel.length(); i++) {
            char c = camel.charAt(i);
            if (Character.isUpperCase(c) && i > 0) sb.append('_');
            sb.append(Character.toUpperCase(c));
        }
        return sb.toString();
    }

    // ---- durations ----

    /** Parses {@code 30s}, {@code 5m}, {@code 2h}, {@code 1d}, {@code 500ms}, ISO-8601, or plain seconds. */
    public static Duration parseDuration(String s) {
        String v = s.trim().toLowerCase(Locale.ROOT);
        if (v.isEmpty()) throw new IllegalArgumentException("empty duration");
        if (v.startsWith("p")) return Duration.parse(v.toUpperCase(Locale.ROOT));
        try {
            if (v.endsWith("ms")) return Duration.ofMillis(Long.parseLong(v.substring(0, v.length() - 2).trim()));
            char unit = v.charAt(v.length() - 1);
            if (Character.isDigit(unit)) return Duration.ofSeconds(Long.parseLong(v));
            long n = Long.parseLong(v.substring(0, v.length() - 1).trim());
            return switch (unit) {
                case 's' -> Duration.ofSeconds(n);
                case 'm' -> Duration.ofMinutes(n);
                case 'h' -> Duration.ofHours(n);
                case 'd' -> Duration.ofDays(n);
                default -> throw new IllegalArgumentException("invalid duration: " + s);
            };
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException("invalid duration: " + s, e);
        }
    }

    public static String formatDuration(Duration d) {
        long secs = d.getSeconds();
        if (d.getNano() != 0) return d.toMillis() + "ms";
        if (secs != 0 && secs % 86400 == 0) return secs / 86400 + "d";
        if (secs != 0 && secs % 3600 == 0) return secs / 3600 + "h";
        if (secs != 0 && secs % 60 == 0) return secs / 60 + "m";
        return secs + "s";
    }

    private static final class DurationAdapter extends TypeAdapter<Duration> {
        @Override
        public void write(JsonWriter out, Duration value) throws IOException {
            out.value(formatDuration(value));
        }

        @Override
        public Duration read(JsonReader in) throws IOException {
            if (in.peek() == JsonToken.NUMBER) {
                return Duration.ofSeconds(in.nextLong());
            }
            return parseDuration(in.nextString());
        }
    }

    public static final class ConfigException extends IOException {
        public ConfigException(String message) {
            super(message);
        }

        public ConfigException(String message, Throwable cause) {
            super(message, cause);
        }
    }
}
