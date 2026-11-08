package io.siggi.simplemailer;

import io.siggi.http.HTTPRequest;
import io.siggi.http.HTTPServer;
import io.siggi.http.HTTPServerBuilder;
import io.siggi.simplemailer.api.Auth;
import io.siggi.simplemailer.api.MessagesResponder;
import io.siggi.simplemailer.api.StatusResponder;
import io.siggi.simplemailer.config.Config;
import io.siggi.simplemailer.model.Job;
import io.siggi.simplemailer.store.JobStore;
import io.siggi.tools.io.ServerSocketHandler;

import java.io.IOException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.function.Consumer;

/**
 * Entry point: loads the configuration and starts the HTTP API (PLAN.md §8).
 */
public final class Main implements AutoCloseable {
    private static final int BACKLOG = 128;

    private final Config config;
    private final ServerSocket serverSocket;
    private final HTTPServer httpServer;
    private final ExecutorService executor;
    private final Auth auth;
    private final JobStore store;

    private Main(Config config, ServerSocket serverSocket) throws IOException {
        this.config = config;
        this.serverSocket = serverSocket;
        this.executor = Executors.newVirtualThreadPerTaskExecutor();
        this.auth = Auth.fromConfig(config);
        this.store = new JobStore(Path.of(config.dataDir));

        Path tmpDir = Path.of(config.dataDir, "tmp");
        Files.createDirectories(tmpDir);
        this.httpServer = new HTTPServerBuilder()
                .setTmpDir(tmpDir.toFile())
                .setExecutor(executor)
                .build();
        httpServer.setServerName("SimpleMailer");
        httpServer.setUploadLimit(config.maxMessageBytes);
        for (String proxy : config.trustedProxies) {
            httpServer.trustIP(proxy);
        }
        httpServer.responderRegistry.register("/health", Main::health);
        // Exact path for POST; the trailing-slash registration covers /v1/messages/{id}.
        httpServer.responderRegistry.register(MessagesResponder.PATH,
                auth.protect(Auth.Scope.SENDER, new MessagesResponder(config, store, this::enqueue)));
        httpServer.responderRegistry.register(StatusResponder.PREFIX,
                auth.protect(Auth.Scope.SENDER, new StatusResponder(config, store)));
    }

    public static void main(String[] args) throws Exception {
        Config config = Config.load();
        Main main = start(config);
        System.out.println("SimpleMailer listening on " + config.bindAddress + ":" + main.port());
    }

    /** Binds {@code config.bindAddress:config.listenPort} and starts serving. */
    public static Main start(Config config) throws IOException {
        ServerSocket socket = new ServerSocket(config.listenPort, BACKLOG, InetAddress.getByName(config.bindAddress));
        return start(config, socket);
    }

    /** Starts serving on an already bound socket (used by tests to listen on an ephemeral port). */
    public static Main start(Config config, ServerSocket serverSocket) throws IOException {
        Main main;
        try {
            main = new Main(config, serverSocket);
        } catch (IOException | RuntimeException e) {
            serverSocket.close();
            throw e;
        }
        main.listen();
        return main;
    }

    private void listen() {
        new ServerSocketHandler(serverSocket, this::accept).start();
    }

    private void accept(Socket socket) {
        try {
            httpServer.handle(socket);
        } catch (RuntimeException e) {
            try {
                socket.close();
            } catch (IOException ignored) {
            }
        }
    }

    public int port() {
        return serverSocket.getLocalPort();
    }

    public Config config() {
        return config;
    }

    public HTTPServer httpServer() {
        return httpServer;
    }

    public Auth auth() {
        return auth;
    }

    public JobStore store() {
        return store;
    }

    private volatile Consumer<Job> deliveryQueue = job -> {
    };

    /** Sets where newly created jobs are handed for delivery (the delivery engine arrives in a later step). */
    public void setDeliveryQueue(Consumer<Job> queue) {
        this.deliveryQueue = queue;
    }

    private void enqueue(Job job) {
        deliveryQueue.accept(job);
    }

    /** {@code GET /health}: unauthenticated liveness check. */
    private static void health(HTTPRequest request) throws Exception {
        if (!request.method.equals("GET")) {
            request.response.setHeader("405 Method Not Allowed");
            request.response.setHeader("Allow", "GET");
            sendJson(request, "{\"error\":\"method_not_allowed\"}");
            return;
        }
        request.response.setHeader("200 OK");
        request.response.doNotCache();
        sendJson(request, "{\"status\":\"ok\"}");
    }

    private static void sendJson(HTTPRequest request, String json) throws IOException {
        byte[] body = json.getBytes(StandardCharsets.UTF_8);
        request.response.setContentType("application/json; charset=utf-8");
        request.response.contentLength(body.length);
        request.response.write(body);
    }

    @Override
    public void close() throws IOException {
        try {
            serverSocket.close();
        } finally {
            executor.shutdownNow();
        }
    }
}
