package dpi;

import java.time.Duration;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicLong;

public class ConnectionTracker {
    private final int maxConnections;
    private final Map<Types.FiveTuple, Types.Connection> connections;
    private final AtomicLong totalSeen = new AtomicLong();
    private final AtomicLong classifiedCount = new AtomicLong();
    private final AtomicLong blockedCount = new AtomicLong();

    public ConnectionTracker(int fpId, int maxConnections) {
        this.maxConnections = maxConnections;
        this.connections = new LinkedHashMap<>(16, 0.75f, false);
    }

    public synchronized Types.Connection getOrCreateConnection(Types.FiveTuple tuple) {
        Types.Connection existing = connections.get(tuple);
        if (existing != null) {
            return existing;
        }
        if (connections.size() >= maxConnections) {
            evictOldest();
        }
        Types.Connection conn = new Types.Connection();
        conn.tuple = tuple;
        conn.state = Types.ConnectionState.NEW;
        conn.firstSeen = System.nanoTime();
        conn.lastSeen = conn.firstSeen;
        connections.put(tuple, conn);
        totalSeen.incrementAndGet();
        return conn;
    }

    public synchronized Types.Connection getConnection(Types.FiveTuple tuple) {
        Types.Connection conn = connections.get(tuple);
        if (conn != null) {
            return conn;
        }
        return connections.get(tuple.reverse());
    }

    public synchronized void updateConnection(Types.Connection conn, int packetSize, boolean isOutbound) {
        if (conn == null) {
            return;
        }
        conn.lastSeen = System.nanoTime();
        if (isOutbound) {
            conn.packetsOut++;
            conn.bytesOut += packetSize;
        } else {
            conn.packetsIn++;
            conn.bytesIn += packetSize;
        }
    }

    public synchronized void classifyConnection(Types.Connection conn, Types.AppType app, String sni) {
        if (conn == null || conn.state == Types.ConnectionState.CLASSIFIED) {
            return;
        }
        conn.appType = app;
        conn.sni = sni != null ? sni : "";
        conn.state = Types.ConnectionState.CLASSIFIED;
        classifiedCount.incrementAndGet();
    }

    public synchronized void blockConnection(Types.Connection conn) {
        if (conn == null) {
            return;
        }
        conn.state = Types.ConnectionState.BLOCKED;
        conn.action = Types.PacketAction.DROP;
        blockedCount.incrementAndGet();
    }

    public synchronized void closeConnection(Types.FiveTuple tuple) {
        Types.Connection conn = connections.get(tuple);
        if (conn != null) {
            conn.state = Types.ConnectionState.CLOSED;
        }
    }

    public synchronized int cleanupStale(Duration timeout) {
        long now = System.nanoTime();
        List<Types.FiveTuple> toRemove = new ArrayList<>();
        for (Map.Entry<Types.FiveTuple, Types.Connection> entry : connections.entrySet()) {
            Types.Connection conn = entry.getValue();
            Duration age = Duration.ofNanos(now - conn.lastSeen);
            if (age.compareTo(timeout) > 0 || conn.state == Types.ConnectionState.CLOSED) {
                toRemove.add(entry.getKey());
            }
        }
        for (Types.FiveTuple key : toRemove) {
            connections.remove(key);
        }
        return toRemove.size();
    }

    public synchronized List<Types.Connection> getAllConnections() {
        return new ArrayList<>(connections.values());
    }

    public synchronized int getActiveCount() {
        return connections.size();
    }

    public TrackerStats getStats() {
        TrackerStats stats = new TrackerStats();
        stats.activeConnections = getActiveCount();
        stats.totalConnectionsSeen = totalSeen.get();
        stats.classifiedConnections = classifiedCount.get();
        stats.blockedConnections = blockedCount.get();
        return stats;
    }

    public synchronized void clear() {
        connections.clear();
    }

    public synchronized void forEach(java.util.function.Consumer<Types.Connection> callback) {
        connections.values().forEach(callback);
    }

    private void evictOldest() {
        Types.FiveTuple oldestKey = connections.entrySet().stream()
                .min(Comparator.comparingLong(e -> e.getValue().lastSeen))
                .map(Map.Entry::getKey)
                .orElse(null);
        if (oldestKey != null) {
            connections.remove(oldestKey);
        }
    }

    public static class TrackerStats {
        public int activeConnections;
        public long totalConnectionsSeen;
        public long classifiedConnections;
        public long blockedConnections;
    }
}
