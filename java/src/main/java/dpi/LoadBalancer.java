package dpi;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;

public class LoadBalancer {
    private final int lbId;
    private final List<ThreadSafeQueue<Types.PacketJob>> fpQueues;
    private final ThreadSafeQueue<Types.PacketJob> inputQueue;
    private final AtomicLong packetsReceived = new AtomicLong();
    private final AtomicLong packetsDispatched = new AtomicLong();
    private final long[] perFpCounts;
    private final AtomicBoolean running = new AtomicBoolean(false);
    private Thread thread;

    public LoadBalancer(int lbId, List<ThreadSafeQueue<Types.PacketJob>> fpQueues, int fpStartId) {
        this.lbId = lbId;
        this.fpQueues = new ArrayList<>(fpQueues);
        this.inputQueue = new ThreadSafeQueue<>(10000);
        this.perFpCounts = new long[fpQueues.size()];
    }

    public void start() {
        if (running.getAndSet(true)) {
            return;
        }
        thread = new Thread(this::run, "LB-" + lbId);
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

    public LBStats getStats() {
        LBStats stats = new LBStats();
        stats.packetsReceived = packetsReceived.get();
        stats.packetsDispatched = packetsDispatched.get();
        stats.perFpPackets = new ArrayList<>();
        for (long count : perFpCounts) {
            stats.perFpPackets.add(count);
        }
        return stats;
    }

    private void run() {
        while (running.get()) {
            var packetOpt = inputQueue.popWithTimeout(100);
            if (packetOpt.isEmpty()) {
                continue;
            }
            Types.PacketJob job = packetOpt.get();
            packetsReceived.incrementAndGet();
            int fpIndex = selectFP(job.tuple);
            fpQueues.get(fpIndex).push(job);
            packetsDispatched.incrementAndGet();
            perFpCounts[fpIndex]++;
        }
    }

    private int selectFP(Types.FiveTuple tuple) {
        return Math.floorMod(Objects.hash(tuple.srcIp, tuple.dstIp, tuple.srcPort, tuple.dstPort, tuple.protocol), fpQueues.size());
    }

    public static class LBStats {
        public long packetsReceived;
        public long packetsDispatched;
        public List<Long> perFpPackets;
    }
}

class LBManager {
    private final List<LoadBalancer> lbs = new ArrayList<>();

    public LBManager(int numLbs, int fpsPerLb, List<ThreadSafeQueue<Types.PacketJob>> fpQueues) {
        for (int lbId = 0; lbId < numLbs; lbId++) {
            int start = lbId * fpsPerLb;
            List<ThreadSafeQueue<Types.PacketJob>> queues = new ArrayList<>();
            for (int i = 0; i < fpsPerLb; i++) {
                queues.add(fpQueues.get(start + i));
            }
            lbs.add(new LoadBalancer(lbId, queues, start));
        }
    }

    public void startAll() {
        lbs.forEach(LoadBalancer::start);
    }

    public void stopAll() {
        lbs.forEach(LoadBalancer::stop);
    }

    public LoadBalancer getLBForPacket(Types.FiveTuple tuple) {
        int lbIndex = Math.floorMod(Objects.hash(tuple.srcIp, tuple.dstIp, tuple.srcPort, tuple.dstPort, tuple.protocol), lbs.size());
        return lbs.get(lbIndex);
    }

    public AggregatedStats getAggregatedStats() {
        AggregatedStats result = new AggregatedStats();
        for (LoadBalancer lb : lbs) {
            LoadBalancer.LBStats stats = lb.getStats();
            result.totalReceived += stats.packetsReceived;
            result.totalDispatched += stats.packetsDispatched;
        }
        return result;
    }

    public static class AggregatedStats {
        public long totalReceived;
        public long totalDispatched;
    }
}
