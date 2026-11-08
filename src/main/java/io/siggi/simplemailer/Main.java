package io.siggi.simplemailer;

import io.siggi.http.HTTPRequest;
import io.siggi.http.HTTPServer;
import io.siggi.http.HTTPServerBuilder;
import io.siggi.simplemailer.api.Auth;
import io.siggi.simplemailer.api.BounceResponder;
import io.siggi.simplemailer.api.MessagesResponder;
import io.siggi.simplemailer.api.StatusResponder;
import io.siggi.simplemailer.callback.CallbackDispatcher;
import io.siggi.simplemailer.config.Config;
import io.siggi.simplemailer.delivery.DeliveryEngine;
import io.siggi.simplemailer.delivery.RetryScheduler;
import io.siggi.simplemailer.inbound.BounceProcessor;
import io.siggi.simplemailer.inbound.InboundSmtpServer;
import io.siggi.simplemailer.inbound.VerpAddress;
import io.siggi.simplemailer.mime.AttachmentFetcher;
import io.siggi.simplemailer.mime.JobPreparer;
import io.siggi.simplemailer.model.Job;
import io.siggi.simplemailer.model.JobStatus;
import io.siggi.simplemailer.smtp.MxResolver;
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
    private final JobPreparer preparer;
    private final DeliveryEngine deliveryEngine;
    private final RetryScheduler retryScheduler;
    private final CallbackDispatcher callbackDispatcher;
    /** Shared by both bounce intakes; null when {@code bounces.domain}/{@code bounces.secret} aren't set. */
    private final BounceProcessor bounceProcessor;
    /** The SMTP bounce listener; null unless {@code bounces.intake} includes {@code smtp}. */
    private volatile InboundSmtpServer inboundSmtpServer;

    private Main(Config config, ServerSocket serverSocket) throws IOException {
        this.config = config;
        this.serverSocket = serverSocket;
        this.executor = Executors.newVirtualThreadPerTaskExecutor();
        this.auth = Auth.fromConfig(config);
        this.store = new JobStore(Path.of(config.dataDir));
        this.callbackDispatcher = new CallbackDispatcher(config, store, executor);
        // deferred recipients are re-run by the retry scheduler at their nextAttemptAt
        this.retryScheduler = new RetryScheduler(config, this::submitRetry);
        DeliveryEngine.Options deliveryOptions = new DeliveryEngine.Options();
        deliveryOptions.retryPolicy = retryScheduler;
        deliveryOptions.onRunFinished = job -> {
            retryScheduler.onRunFinished(job);
            callbackDispatcher.onJobChanged(job);
        };
        // MAIL FROM is the recipient's VERP bounce address whenever bounces.domain/secret are set (PLAN.md §6a),
        // even with bounce intake disabled, so intake can be enabled later
        VerpAddress verp = VerpAddress.fromConfig(config);
        if (verp != null) deliveryOptions.envelopeSender = verp.envelopeSender();
        this.bounceProcessor = verp == null ? null
                : new BounceProcessor(Path.of(config.dataDir), store, verp, callbackDispatcher);
        this.deliveryEngine = new DeliveryEngine(config, store, MxResolver.system(), executor, deliveryOptions);
        this.deliveryQueue = deliveryEngine::submit;
        this.preparer = new JobPreparer(config, store, AttachmentFetcher.fromConfig(config), executor,
                this::enqueue, callbackDispatcher::onJobChanged);

        Path tmpDir = Path.of(config.dataDir, "tmp");
        Files.createDirectories(tmpDir);
        this.httpServer = new HTTPServerBuilder()
                .setTmpDir(tmpDir.toFile())
                .setExecutor(executor)
                .build();
        httpServer.setServerName("SimpleMailer");
        // multipart/form-data bodies (file parts and the JSON "message" field) are bounded by maxMessageBytes
        httpServer.setUploadLimit(config.maxMessageBytes);
        httpServer.setPostLimit((int) Math.min(config.maxMessageBytes, Integer.MAX_VALUE));
        for (String proxy : config.trustedProxies) {
            httpServer.trustIP(proxy);
        }
        httpServer.responderRegistry.register("/health", Main::health);
        // Exact path for POST; the trailing-slash registration covers /v1/messages/{id}.
        httpServer.responderRegistry.register(MessagesResponder.PATH,
                auth.protect(Auth.Scope.SENDER, new MessagesResponder(config, store, this::acceptJob)));
        httpServer.responderRegistry.register(StatusResponder.PREFIX,
                auth.protect(Auth.Scope.SENDER, new StatusResponder(config, store)));
        // POST /v1/bounces exists only with the api bounce intake (PLAN.md §6a); bounce keys only
        if (config.bounces.apiIntake()) {
            if (bounceProcessor == null) {
                throw new IllegalStateException("API bounce intake needs bounces.domain and bounces.secret");
            }
            httpServer.responderRegistry.register(BounceResponder.PATH, auth.protect(Auth.Scope.BOUNCE,
                    new BounceResponder(bounceProcessor, config.bounces.smtpMaxMessageBytes)));
        }
    }

    public static void main(String[] args) throws Exception {
        Config config = Config.load();
        Main main = start(config);
        System.out.println("SimpleMailer listening on " + config.bindAddress + ":" + main.port());
        if (main.inboundSmtpServer() != null) {
            System.out.println("SMTP bounce intake listening on " + config.bindAddress + ":"
                    + main.inboundSmtpServer().port());
        }
    }

    /** Binds {@code config.bindAddress:config.listenPort} and starts serving. */
    public static Main start(Config config) throws IOException {
        ServerSocket socket = new ServerSocket(config.listenPort, BACKLOG, InetAddress.getByName(config.bindAddress));
        return start(config, socket);
    }

    /** Starts serving on an already bound socket (used by tests to listen on an ephemeral port). */
    public static Main start(Config config, ServerSocket serverSocket) throws IOException {
        ServerSocket smtpSocket = null;
        if (config.bounces.smtpIntake()) {
            try {
                smtpSocket = new ServerSocket(config.bounces.smtpPort, BACKLOG,
                        InetAddress.getByName(config.bindAddress));
            } catch (IOException | RuntimeException e) {
                serverSocket.close();
                throw e;
            }
        }
        return start(config, serverSocket, smtpSocket);
    }

    /**
     * Starts serving on already bound sockets; {@code smtpSocket} is used for the SMTP bounce intake when
     * {@code bounces.intake} includes {@code smtp} (otherwise it must be null). Used by tests.
     */
    public static Main start(Config config, ServerSocket serverSocket, ServerSocket smtpSocket) throws IOException {
        Main main;
        try {
            main = new Main(config, serverSocket);
            if (config.bounces.smtpIntake()) {
                if (smtpSocket == null) throw new IllegalArgumentException("SMTP bounce intake needs a socket");
                if (main.bounceProcessor == null) {
                    throw new IllegalStateException("SMTP bounce intake needs bounces.domain and bounces.secret");
                }
                main.inboundSmtpServer = new InboundSmtpServer(main.bounceProcessor,
                        InboundSmtpServer.Options.fromConfig(config));
            } else if (smtpSocket != null) {
                throw new IllegalArgumentException("SMTP bounce intake is not enabled");
            }
        } catch (IOException | RuntimeException e) {
            serverSocket.close();
            if (smtpSocket != null) smtpSocket.close();
            throw e;
        }
        main.listen();
        if (main.inboundSmtpServer != null) main.inboundSmtpServer.start(smtpSocket);
        main.executor.execute(main::resumePreparing);
        main.executor.execute(main::resumeDelivery);
        main.executor.execute(main::resumeCallbacks);
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

    private volatile Consumer<Job> deliveryQueue;
    private volatile Consumer<Job> preparationQueue;

    /**
     * Replaces where queued jobs are handed for delivery (by default the {@link DeliveryEngine}): new jobs without
     * URL attachments, and {@code preparing} jobs once their attachments are fetched. For tests.
     */
    public void setDeliveryQueue(Consumer<Job> queue) {
        this.deliveryQueue = queue;
    }

    /** Replaces where new {@code preparing} jobs are handed (by default the {@link JobPreparer}); for tests. */
    public void setPreparationQueue(Consumer<Job> queue) {
        this.preparationQueue = queue;
    }

    public DeliveryEngine deliveryEngine() {
        return deliveryEngine;
    }

    private boolean submitRetry(Job job) {
        return deliveryEngine.submit(job);
    }

    public RetryScheduler retryScheduler() {
        return retryScheduler;
    }

    public CallbackDispatcher callbackDispatcher() {
        return callbackDispatcher;
    }

    /** The bounce processor, or null when no bounce domain and secret are configured. */
    public BounceProcessor bounceProcessor() {
        return bounceProcessor;
    }

    /** The SMTP bounce listener, or null when the {@code smtp} intake is disabled. */
    public InboundSmtpServer inboundSmtpServer() {
        return inboundSmtpServer;
    }

    public JobPreparer preparer() {
        return preparer;
    }

    /** New jobs from the API: {@code preparing} ones go to the preparer first, the rest straight to delivery. */
    private void acceptJob(Job job) {
        if (job.status == JobStatus.PREPARING) {
            Consumer<Job> queue = preparationQueue;
            if (queue != null) queue.accept(job);
            else preparer.submit(job);
        } else {
            enqueue(job);
        }
    }

    private void enqueue(Job job) {
        deliveryQueue.accept(job);
    }

    /** Startup: jobs left in {@code preparing} by a restart continue fetching (already fetched files are kept). */
    private void resumePreparing() {
        try {
            preparer.resumeAll();
        } catch (IOException e) {
            System.err.println("Could not resume preparing jobs: " + e);
        }
    }

    /**
     * Startup: jobs left {@code queued}, {@code sending} or {@code deferred} by a restart are re-enqueued; only their
     * unfinished recipients are attempted, and deferred ones keep their retry time (PLAN.md §4).
     */
    private void resumeDelivery() {
        try {
            deliveryEngine.resumeAll(retryScheduler::schedule);
        } catch (IOException e) {
            System.err.println("Could not resume unfinished deliveries: " + e);
        }
    }

    /** Startup: callback events left pending by a restart are retried at their scheduled time. */
    private void resumeCallbacks() {
        try {
            callbackDispatcher.resumeAll();
        } catch (IOException e) {
            System.err.println("Could not resume pending callbacks: " + e);
        }
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
            InboundSmtpServer smtp = inboundSmtpServer;
            if (smtp != null) smtp.close();
        } finally {
            retryScheduler.close();
            callbackDispatcher.close();
            executor.shutdownNow();
        }
    }
}
