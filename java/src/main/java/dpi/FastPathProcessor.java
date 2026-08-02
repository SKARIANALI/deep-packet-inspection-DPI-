package dpi;

import java.util.Optional;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;

public class FastPathProcessor {
    private final int fpId;
    private final ThreadSafeQueue<Types.PacketJob> inputQueue;
    private final ConnectionTracker connectionTracker;
    private final RuleManager ruleManager;
    private final PacketOutputCallback outputCallback;
    private final AtomicLong packetsProcessed = new AtomicLong();
    private final AtomicLong packetsForwarded = new AtomicLong();
    private final AtomicLong packetsDropped = new AtomicLong();
    private final AtomicLong sniExtractions = new AtomicLong();
    private final AtomicLong classificationHits = new AtomicLong();
    private final AtomicBoolean running = new AtomicBoolean(false);
    private Thread thread;

    public interface PacketOutputCallback {
        void onOutput(Types.PacketJob job, Types.PacketAction action);
    }

    public FastPathProcessor(int fpId, RuleManager ruleManager, PacketOutputCallback outputCallback, ThreadSafeQueue<Types.PacketJob> inputQueue) {
        this.fpId = fpId;
        this.inputQueue = inputQueue;
        this.connectionTracker = new ConnectionTracker(fpId, 100000);
        this.ruleManager = ruleManager;
        this.outputCallback = outputCallback;
    }

    public int getId() {
        return fpId;
    }

    public void start() {
        if (running.getAndSet(true)) {
            return;
        }
        thread = new Thread(this::run, "FP-" + fpId);
        thread.start();
    }

    public void stop() {
        if (!running.getAndSet(false)) {
            return;
        }
        inputQueue.shutdown();
        if (thread != null) {
            try {
                thread.join();
            } catch (InterruptedException ignored) {
                Thread.currentThread().interrupt();
            }
        }
    }

    public ThreadSafeQueue<Types.PacketJob> getInputQueue() {
        return inputQueue;
    }

    public ConnectionTracker getConnectionTracker() {
        return connectionTracker;
    }

    public FPStats getStats() {
        FPStats stats = new FPStats();
        stats.packetsProcessed = packetsProcessed.get();
        stats.packetsForwarded = packetsForwarded.get();
        stats.packetsDropped = packetsDropped.get();
        stats.connectionsTracked = connectionTracker.getActiveCount();
        stats.sniExtractions = sniExtractions.get();
        stats.classificationHits = classificationHits.get();
        return stats;
    }

    private void run() {
        while (running.get()) {
            var jobOpt = inputQueue.popWithTimeout(100);
            if (jobOpt.isEmpty()) {
                connectionTracker.cleanupStale(java.time.Duration.ofSeconds(300));
                continue;
            }
            Types.PacketJob job = jobOpt.get();
            packetsProcessed.incrementAndGet();
            Types.PacketAction action = processPacket(job);
            if (outputCallback != null) {
                outputCallback.onOutput(job, action);
            }
            if (action == Types.PacketAction.DROP) {
                packetsDropped.incrementAndGet();
            } else {
                packetsForwarded.incrementAndGet();
            }
        }
    }

    private Types.PacketAction processPacket(Types.PacketJob job) {
        Types.Connection conn = connectionTracker.getOrCreateConnection(job.tuple);
        if (conn == null) {
            return Types.PacketAction.FORWARD;
        }
        connectionTracker.updateConnection(conn, job.data.length, true);
        if (job.tuple.protocol == 6) {
            updateTcpState(conn, job.tcpFlags);
        }
        if (conn.state == Types.ConnectionState.BLOCKED) {
            return Types.PacketAction.DROP;
        }
        if (conn.state != Types.ConnectionState.CLASSIFIED && job.payloadLength > 0) {
            inspectPayload(job, conn);
        }
        return checkRules(job, conn);
    }

    private void inspectPayload(Types.PacketJob job, Types.Connection conn) {
        if (job.payloadLength == 0 || job.payloadOffset >= job.data.length) {
            return;
        }
        byte[] payload = new byte[job.payloadLength];
        System.arraycopy(job.data, job.payloadOffset, payload, 0, job.payloadLength);
        if (tryExtractSni(job, payload, conn)) {
            return;
        }
        if (tryExtractHttpHost(job, payload, conn)) {
            return;
        }
        if (job.tuple.dstPort == 53 || job.tuple.srcPort == 53) {
            Optional<String> domain = SNIExtractor.DNSExtractor.extractQuery(payload);
            if (domain.isPresent()) {
                connectionTracker.classifyConnection(conn, Types.AppType.DNS, domain.get());
            }
            return;
        }
        if (job.tuple.dstPort == 80) {
            connectionTracker.classifyConnection(conn, Types.AppType.HTTP, "");
        } else if (job.tuple.dstPort == 443) {
            connectionTracker.classifyConnection(conn, Types.AppType.HTTPS, "");
        }
    }

    private boolean tryExtractSni(Types.PacketJob job, byte[] payload, Types.Connection conn) {
        if (job.tuple.dstPort != 443 && payload.length < 50) {
            return false;
        }
        Optional<String> sni = SNIExtractor.extract(payload);
        if (sni.isPresent()) {
            sniExtractions.incrementAndGet();
            Types.AppType app = Types.sniToAppType(sni.get());
            connectionTracker.classifyConnection(conn, app, sni.get());
            System.out.println("[FP" + fpId + "] Classified via SNI: src=" + Types.ipToString(job.tuple.srcIp) + ":" + (job.tuple.srcPort & 0xFFFF) + " dst=" + Types.ipToString(job.tuple.dstIp) + ":" + (job.tuple.dstPort & 0xFFFF) + " sni=" + sni.get() + " app=" + Types.appTypeToString(app));
            if (app != Types.AppType.UNKNOWN && app != Types.AppType.HTTPS) {
                classificationHits.incrementAndGet();
            }
            return true;
        }
        return false;
    }

    private boolean tryExtractHttpHost(Types.PacketJob job, byte[] payload, Types.Connection conn) {
        if (job.tuple.dstPort != 80) {
            return false;
        }
        Optional<String> host = SNIExtractor.HTTPHostExtractor.extract(payload);
        if (host.isPresent()) {
            Types.AppType app = Types.sniToAppType(host.get());
            connectionTracker.classifyConnection(conn, app, host.get());
            if (app != Types.AppType.UNKNOWN && app != Types.AppType.HTTP) {
                classificationHits.incrementAndGet();
            }
            return true;
        }
        return false;
    }

    private Types.PacketAction checkRules(Types.PacketJob job, Types.Connection conn) {
        if (ruleManager == null) {
            return Types.PacketAction.FORWARD;
        }
        // Debug: show classification and SNI before rule check
        System.out.println("[FP" + fpId + "] Checking rules: src=" + Types.ipToString(job.tuple.srcIp) + ":" + (job.tuple.srcPort & 0xFFFF) + " app=" + Types.appTypeToString(conn.appType) + " sni=" + conn.sni);
        Optional<RuleManager.BlockReason> reason = ruleManager.shouldBlock(
                job.tuple.srcIp,
                job.tuple.dstPort,
                conn.appType,
                conn.sni
        );
        if (reason.isPresent()) {
            conn.state = Types.ConnectionState.BLOCKED;
            conn.action = Types.PacketAction.DROP;
            switch (reason.get().type) {
                case IP -> System.out.println("[FP" + fpId + "] BLOCKED packet: IP " + reason.get().detail);
                case APP -> System.out.println("[FP" + fpId + "] BLOCKED packet: App " + reason.get().detail);
                case DOMAIN -> System.out.println("[FP" + fpId + "] BLOCKED packet: Domain " + reason.get().detail);
                case PORT -> System.out.println("[FP" + fpId + "] BLOCKED packet: Port " + reason.get().detail);
            }
            return Types.PacketAction.DROP;
        }
        return Types.PacketAction.FORWARD;
    }

    private void updateTcpState(Types.Connection conn, int tcpFlags) {
        boolean syn = (tcpFlags & 0x02) != 0;
        boolean ack = (tcpFlags & 0x10) != 0;
        boolean fin = (tcpFlags & 0x01) != 0;
        boolean rst = (tcpFlags & 0x04) != 0;
        if (syn) {
            if (ack) {
                conn.synAckSeen = true;
            } else {
                conn.synSeen = true;
            }
        }
        if (conn.synSeen && conn.synAckSeen && ack && conn.state == Types.ConnectionState.NEW) {
            conn.state = Types.ConnectionState.ESTABLISHED;
        }
        if (fin) {
            conn.finSeen = true;
        }
        if (rst) {
            conn.state = Types.ConnectionState.CLOSED;
        }
        if (conn.finSeen && ack) {
            conn.state = Types.ConnectionState.CLOSED;
        }
    }

    public static class FPStats {
        public long packetsProcessed;
        public long packetsForwarded;
        public long packetsDropped;
        public int connectionsTracked;
        public long sniExtractions;
        public long classificationHits;
    }
}
