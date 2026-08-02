package dpi;

import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;
import packetanalyzer.PacketParser;
import packetanalyzer.PcapReader;

public class DPIEngine {
    public static class Config {
        public int numLoadBalancers = 2;
        public int fpsPerLb = 2;
        public int queueSize = 10000;
        public String rulesFile = "";
        public boolean verbose = false;
    }

    private final RuleManager ruleManager;
    private final List<FastPathProcessor> fps = new ArrayList<>();
    private final List<ThreadSafeQueue<Types.PacketJob>> fpQueues = new ArrayList<>();
    private final LBManager lbManager;
    private final ThreadSafeQueue<Types.PacketJob> outputQueue;
    private final DPIStats stats = new DPIStats();
    private final AtomicBoolean running = new AtomicBoolean(false);
    private final AtomicBoolean processingComplete = new AtomicBoolean(false);
    private Thread outputThread;
    private Thread readerThread;
    private OutputStream outputStream;

    public DPIEngine(Config config) {
        this.ruleManager = new RuleManager();
        this.outputQueue = new ThreadSafeQueue<>(config.queueSize);
        int totalFps = config.numLoadBalancers * config.fpsPerLb;
        for (int i = 0; i < totalFps; i++) {
            fpQueues.add(new ThreadSafeQueue<>(config.queueSize));
        }
        LBManager manager = new LBManager(config.numLoadBalancers, config.fpsPerLb, fpQueues);
        this.lbManager = manager;

        for (int i = 0; i < totalFps; i++) {
            FastPathProcessor.PacketOutputCallback callback = this::handleOutput;
            FastPathProcessor fp = new FastPathProcessor(i, ruleManager, callback, fpQueues.get(i));
            fps.add(fp);
        }

        if (!config.rulesFile.isEmpty()) {
            ruleManager.loadRules(config.rulesFile);
        }
    }

    public boolean initialize() {
        return true;
    }

    public void start() {
        if (running.getAndSet(true)) {
            return;
        }
        outputThread = new Thread(this::outputThreadFunc, "OutputThread");
        outputThread.start();
        fps.forEach(FastPathProcessor::start);
        lbManager.startAll();
    }

    public void stop() {
        if (!running.getAndSet(false)) {
            return;
        }
        lbManager.stopAll();
        fps.forEach(FastPathProcessor::stop);
        outputQueue.shutdown();
        if (outputThread != null) {
            try {
                outputThread.join();
            } catch (InterruptedException ignored) {
                Thread.currentThread().interrupt();
            }
        }
    }

    public void waitForCompletion() {
        if (readerThread != null) {
            try {
                readerThread.join();
            } catch (InterruptedException ignored) {
                Thread.currentThread().interrupt();
            }
        }
        processingComplete.set(true);
    }

    public Set<String> collectDomains(String inputFile) {
        Set<String> domains = new HashSet<>();
        try (PcapReader reader = new PcapReader(inputFile)) {
            PcapReader.RawPacket raw = new PcapReader.RawPacket();
            PacketParser.ParsedPacket parsed = new PacketParser.ParsedPacket();
            int packetId = 0;
            while (reader.readNextPacket(raw)) {
                if (!PacketParser.parse(raw, parsed)) {
                    continue;
                }
                if (!parsed.hasIp || (!parsed.hasTcp && !parsed.hasUdp)) {
                    continue;
                }
                Types.PacketJob job = createPacketJob(raw, parsed, packetId++);
                addDomainsFromJob(job, domains);
            }
        } catch (IOException e) {
            System.err.println("Failed to collect domains: " + e.getMessage());
        }
        return domains;
    }

    public Set<String> collectAppSources(String inputFile, String appName) {
        Set<String> sources = new HashSet<>();
        Types.AppType targetApp = parseAppType(appName);
        try (PcapReader reader = new PcapReader(inputFile)) {
            PcapReader.RawPacket raw = new PcapReader.RawPacket();
            PacketParser.ParsedPacket parsed = new PacketParser.ParsedPacket();
            int packetId = 0;
            while (reader.readNextPacket(raw)) {
                if (!PacketParser.parse(raw, parsed)) {
                    continue;
                }
                if (!parsed.hasIp || (!parsed.hasTcp && !parsed.hasUdp)) {
                    continue;
                }
                Types.PacketJob job = createPacketJob(raw, parsed, packetId++);
                Types.AppType app = determineAppType(job);
                if (matchesApp(app, appName, targetApp)) {
                    sources.add(Types.ipToString(job.tuple.srcIp) + ":" + (job.tuple.srcPort & 0xFFFF));
                }
            }
        } catch (IOException e) {
            System.err.println("Failed to collect app sources: " + e.getMessage());
        }
        return sources;
    }

    public Map<String, Integer> collectDomainStats(String inputFile) {
        Map<String, Integer> domainStats = new HashMap<>();
        try (PcapReader reader = new PcapReader(inputFile)) {
            PcapReader.RawPacket raw = new PcapReader.RawPacket();
            PacketParser.ParsedPacket parsed = new PacketParser.ParsedPacket();
            int packetId = 0;
            while (reader.readNextPacket(raw)) {
                if (!PacketParser.parse(raw, parsed)) {
                    continue;
                }
                if (!parsed.hasIp || (!parsed.hasTcp && !parsed.hasUdp)) {
                    continue;
                }
                Types.PacketJob job = createPacketJob(raw, parsed, packetId++);
                addDomainsFromJob(job, new HashSet<>());
                if (job.payloadLength > 0 && job.payloadOffset < job.data.length) {
                    int end = Math.min(job.data.length, job.payloadOffset + job.payloadLength);
                    byte[] payload = new byte[end - job.payloadOffset];
                    System.arraycopy(job.data, job.payloadOffset, payload, 0, payload.length);
                    SNIExtractor.extract(payload).ifPresent(domain -> domainStats.merge(domain, 1, Integer::sum));
                    if (job.tuple.dstPort == 80) {
                        SNIExtractor.HTTPHostExtractor.extract(payload).ifPresent(domain -> domainStats.merge(domain, 1, Integer::sum));
                    }
                    if (job.tuple.dstPort == 53 || job.tuple.srcPort == 53) {
                        SNIExtractor.DNSExtractor.extractQuery(payload).ifPresent(domain -> domainStats.merge(domain, 1, Integer::sum));
                    }
                }
            }
        } catch (IOException e) {
            System.err.println("Failed to collect domain stats: " + e.getMessage());
        }
        return sortByValueDescending(domainStats);
    }

    public Map<String, Integer> collectAppStats(String inputFile) {
        Map<String, Integer> appStats = new HashMap<>();
        try (PcapReader reader = new PcapReader(inputFile)) {
            PcapReader.RawPacket raw = new PcapReader.RawPacket();
            PacketParser.ParsedPacket parsed = new PacketParser.ParsedPacket();
            int packetId = 0;
            while (reader.readNextPacket(raw)) {
                if (!PacketParser.parse(raw, parsed)) {
                    continue;
                }
                if (!parsed.hasIp || (!parsed.hasTcp && !parsed.hasUdp)) {
                    continue;
                }
                Types.PacketJob job = createPacketJob(raw, parsed, packetId++);
                Types.AppType app = determineAppType(job);
                appStats.merge(Types.appTypeToString(app), 1, Integer::sum);
            }
        } catch (IOException e) {
            System.err.println("Failed to collect app stats: " + e.getMessage());
        }
        return sortByValueDescending(appStats);
    }

    private Map<String, Integer> sortByValueDescending(Map<String, Integer> input) {
        List<Map.Entry<String, Integer>> entries = new ArrayList<>(input.entrySet());
        entries.sort(Map.Entry.comparingByValue(Comparator.reverseOrder()));
        Map<String, Integer> result = new LinkedHashMap<>();
        for (Map.Entry<String, Integer> entry : entries) {
            result.put(entry.getKey(), entry.getValue());
        }
        return result;
    }

    private Types.AppType parseAppType(String appName) {
        try {
            return Types.AppType.valueOf(appName.toUpperCase());
        } catch (IllegalArgumentException e) {
            return null;
        }
    }

    private boolean matchesApp(Types.AppType app, String appName, Types.AppType targetApp) {
        if (targetApp != null) {
            return app == targetApp;
        }
        return Types.appTypeToString(app).equalsIgnoreCase(appName) || app.name().equalsIgnoreCase(appName);
    }

    private Types.AppType determineAppType(Types.PacketJob job) {
        if (job.payloadLength <= 0 || job.payloadOffset >= job.data.length) {
            return portDefaultApp(job);
        }
        int end = Math.min(job.data.length, job.payloadOffset + job.payloadLength);
        byte[] payload = new byte[end - job.payloadOffset];
        System.arraycopy(job.data, job.payloadOffset, payload, 0, payload.length);

        Optional<String> sni = SNIExtractor.extract(payload);
        if (sni.isPresent()) {
            return Types.sniToAppType(sni.get());
        }
        if (job.tuple.dstPort == 80) {
            Optional<String> host = SNIExtractor.HTTPHostExtractor.extract(payload);
            if (host.isPresent()) {
                return Types.sniToAppType(host.get());
            }
            return Types.AppType.HTTP;
        }
        if (job.tuple.dstPort == 53 || job.tuple.srcPort == 53) {
            return Types.AppType.DNS;
        }
        return portDefaultApp(job);
    }

    private Types.AppType portDefaultApp(Types.PacketJob job) {
        if (job.tuple.dstPort == 80) {
            return Types.AppType.HTTP;
        }
        if (job.tuple.dstPort == 443) {
            return Types.AppType.HTTPS;
        }
        if (job.tuple.dstPort == 53 || job.tuple.srcPort == 53) {
            return Types.AppType.DNS;
        }
        return Types.AppType.UNKNOWN;
    }

    private void addDomainsFromJob(Types.PacketJob job, Set<String> domains) {
        if (job.payloadLength <= 0 || job.payloadOffset >= job.data.length) {
            return;
        }
        int end = Math.min(job.data.length, job.payloadOffset + job.payloadLength);
        byte[] payload = new byte[end - job.payloadOffset];
        System.arraycopy(job.data, job.payloadOffset, payload, 0, payload.length);

        SNIExtractor.extract(payload).ifPresent(domains::add);
        if (job.tuple.dstPort == 80) {
            SNIExtractor.HTTPHostExtractor.extract(payload).ifPresent(domains::add);
        }
        if (job.tuple.dstPort == 53 || job.tuple.srcPort == 53) {
            SNIExtractor.DNSExtractor.extractQuery(payload).ifPresent(domains::add);
        }
    }

    public boolean processFile(String inputFile, String outputFile) {
        if (!initialize()) {
            return false;
        }
        try {
            outputStream = new FileOutputStream(outputFile);
            start();
            readerThread = new Thread(() -> readerThreadFunc(inputFile), "ReaderThread");
            readerThread.start();
            waitForCompletion();
            Thread.sleep(200);
            stop();
            System.out.println(generateReport());
            System.out.println(generateClassificationReport());
            return true;
        } catch (IOException | InterruptedException e) {
            System.err.println("Failed to process PCAP file: " + e.getMessage());
            Thread.currentThread().interrupt();
            return false;
        } finally {
            if (outputStream != null) {
                try {
                    outputStream.close();
                } catch (IOException ignored) {
                }
                outputStream = null;
            }
        }
    }

    private void readerThreadFunc(String inputFile) {
        try (PcapReader reader = new PcapReader(inputFile)) {
            if (outputStream != null) {
                writeOutputHeader(outputStream, reader.getGlobalHeader());
            }
            PcapReader.RawPacket raw = new PcapReader.RawPacket();
            PacketParser.ParsedPacket parsed = new PacketParser.ParsedPacket();
            int packetId = 0;
            while (reader.readNextPacket(raw)) {
                if (!PacketParser.parse(raw, parsed)) {
                    continue;
                }
                if (!parsed.hasIp || (!parsed.hasTcp && !parsed.hasUdp)) {
                    continue;
                }
                Types.PacketJob job = createPacketJob(raw, parsed, packetId++);
                stats.totalPackets.incrementAndGet();
                stats.totalBytes.addAndGet(raw.data.length);
                if (parsed.hasTcp) {
                    stats.tcpPackets.incrementAndGet();
                } else if (parsed.hasUdp) {
                    stats.udpPackets.incrementAndGet();
                }
                LoadBalancer lb = lbManager.getLBForPacket(job.tuple);
                lb.getInputQueue().push(job);
            }
        } catch (IOException e) {
            System.err.println("Failed to read packet stream: " + e.getMessage());
        }
    }

    private Types.PacketJob createPacketJob(PcapReader.RawPacket raw, PacketParser.ParsedPacket parsed, int packetId) {
        Types.PacketJob job = new Types.PacketJob();
        job.packetId = packetId;
        job.tsSec = raw.header.tsSec;
        job.tsUsec = raw.header.tsUsec;
        job.tuple.srcIp = Types.parseIp(parsed.srcIp);
        job.tuple.dstIp = Types.parseIp(parsed.destIp);
        job.tuple.srcPort = parsed.srcPort;
        job.tuple.dstPort = parsed.destPort;
        job.tuple.protocol = parsed.protocol;
        job.tcpFlags = parsed.tcpFlags;
        job.data = raw.data.clone();
        job.ethOffset = 0;
        job.ipOffset = 14;
        if (job.data.length > 14) {
            int ipIhl = job.data[14] & 0x0F;
            int ipHeaderLen = ipIhl * 4;
            job.transportOffset = 14 + ipHeaderLen;
            if (parsed.hasTcp && job.data.length > job.transportOffset) {
                int tcpOffset = job.transportOffset;
                int tcpDataOffset = (job.data[tcpOffset + 12] >> 4) & 0x0F;
                int tcpHeaderLen = tcpDataOffset * 4;
                job.payloadOffset = tcpOffset + tcpHeaderLen;
            } else if (parsed.hasUdp) {
                job.payloadOffset = job.transportOffset + 8;
            }
            if (job.payloadOffset < job.data.length) {
                job.payloadLength = job.data.length - job.payloadOffset;
            }
        }
        return job;
    }

    private void outputThreadFunc() {
        while (running.get() || !outputQueue.isEmpty()) {
            var jobOpt = outputQueue.popWithTimeout(100);
            if (jobOpt.isPresent() && outputStream != null) {
                writePacket(outputStream, jobOpt.get());
            }
        }
    }

    private void handleOutput(Types.PacketJob job, Types.PacketAction action) {
        if (action == Types.PacketAction.DROP) {
            stats.droppedPackets.incrementAndGet();
            return;
        }
        stats.forwardedPackets.incrementAndGet();
        outputQueue.push(job);
    }

    private void writeOutputHeader(OutputStream outputStream, PcapReader.PcapGlobalHeader header) throws IOException {
        byte[] bytes = new byte[24];
        writeInt(bytes, 0, header.magicNumber);
        writeShort(bytes, 4, header.versionMajor);
        writeShort(bytes, 6, header.versionMinor);
        writeInt(bytes, 8, header.thiszone);
        writeInt(bytes, 12, header.sigfigs);
        writeInt(bytes, 16, header.snaplen);
        writeInt(bytes, 20, header.network);
        outputStream.write(bytes);
    }

    private void writePacket(OutputStream outputStream, Types.PacketJob job) {
        try {
            byte[] headerBytes = new byte[16];
            writeInt(headerBytes, 0, (int) job.tsSec);
            writeInt(headerBytes, 4, (int) job.tsUsec);
            writeInt(headerBytes, 8, job.data.length);
            writeInt(headerBytes, 12, job.data.length);
            outputStream.write(headerBytes);
            outputStream.write(job.data);
        } catch (IOException e) {
            System.err.println("Failed to write packet output: " + e.getMessage());
        }
    }

    private void writeInt(byte[] array, int offset, int value) {
        array[offset] = (byte) ((value >> 24) & 0xFF);
        array[offset + 1] = (byte) ((value >> 16) & 0xFF);
        array[offset + 2] = (byte) ((value >> 8) & 0xFF);
        array[offset + 3] = (byte) (value & 0xFF);
    }

    private void writeShort(byte[] array, int offset, short value) {
        array[offset] = (byte) ((value >> 8) & 0xFF);
        array[offset + 1] = (byte) (value & 0xFF);
    }

    public void blockIp(String ip) {
        ruleManager.blockIp(ip);
    }

    public void unblockIp(String ip) {
        ruleManager.unblockIp(ip);
    }

    public void blockApp(Types.AppType app) {
        ruleManager.blockApp(app);
    }

    public void blockApp(String appName) {
        for (Types.AppType value : Types.AppType.values()) {
            if (Types.appTypeToString(value).equalsIgnoreCase(appName) || value.name().equalsIgnoreCase(appName)) {
                ruleManager.blockApp(value);
                return;
            }
        }
    }

    public void unblockApp(Types.AppType app) {
        ruleManager.unblockApp(app);
    }

    public void unblockApp(String appName) {
        for (Types.AppType value : Types.AppType.values()) {
            if (Types.appTypeToString(value).equalsIgnoreCase(appName) || value.name().equalsIgnoreCase(appName)) {
                ruleManager.unblockApp(value);
                return;
            }
        }
    }

    public boolean isAppBlocked(Types.AppType app) {
        return ruleManager.isAppBlocked(app);
    }

    public boolean isAppBlocked(String appName) {
        for (Types.AppType value : Types.AppType.values()) {
            if (Types.appTypeToString(value).equalsIgnoreCase(appName) || value.name().equalsIgnoreCase(appName)) {
                return ruleManager.isAppBlocked(value);
            }
        }
        return false;
    }

    public boolean isDomainBlocked(String domain) {
        return ruleManager.isDomainBlocked(domain);
    }

    public Set<String> getBlockedDomains() {
        return new HashSet<>(ruleManager.getBlockedDomains());
    }

    public void blockDomain(String domain) {
        ruleManager.blockDomain(domain);
    }

    public void unblockDomain(String domain) {
        ruleManager.unblockDomain(domain);
    }

    public void blockPort(int port) {
        ruleManager.blockPort(port);
    }

    public boolean loadRules(String filename) {
        return ruleManager.loadRules(filename);
    }

    public boolean saveRules(String filename) {
        return ruleManager.saveRules(filename);
    }

    public String generateReport() {
        StringBuilder sb = new StringBuilder();
        sb.append("\n=== DPI ENGINE STATISTICS ===\n");
        sb.append("Total Packets: ").append(stats.totalPackets.get()).append('\n');
        sb.append("Total Bytes: ").append(stats.totalBytes.get()).append('\n');
        sb.append("TCP Packets: ").append(stats.tcpPackets.get()).append('\n');
        sb.append("UDP Packets: ").append(stats.udpPackets.get()).append('\n');
        sb.append("Forwarded: ").append(stats.forwardedPackets.get()).append('\n');
        sb.append("Dropped: ").append(stats.droppedPackets.get()).append('\n');
        return sb.toString();
    }

    public String generateClassificationReport() {
        StringBuilder sb = new StringBuilder();
        sb.append("\n=== CLASSIFICATION REPORT ===\n");
        for (FastPathProcessor fp : fps) {
            FastPathProcessor.FPStats fpStats = fp.getStats();
            sb.append("FP").append(fp.getId()).append(": processed=").append(fpStats.packetsProcessed)
                    .append(", forwarded=").append(fpStats.packetsForwarded)
                    .append(", dropped=").append(fpStats.packetsDropped).append('\n');
        }
        return sb.toString();
    }

    public DPIStats getStats() {
        return stats;
    }

    public void printStatus() {
        System.out.println("Packets=" + stats.totalPackets.get() + " Forwarded=" + stats.forwardedPackets.get() + " Dropped=" + stats.droppedPackets.get());
    }

    public static class DPIStats {
        public final java.util.concurrent.atomic.AtomicLong totalPackets = new java.util.concurrent.atomic.AtomicLong();
        public final java.util.concurrent.atomic.AtomicLong totalBytes = new java.util.concurrent.atomic.AtomicLong();
        public final java.util.concurrent.atomic.AtomicLong forwardedPackets = new java.util.concurrent.atomic.AtomicLong();
        public final java.util.concurrent.atomic.AtomicLong droppedPackets = new java.util.concurrent.atomic.AtomicLong();
        public final java.util.concurrent.atomic.AtomicLong tcpPackets = new java.util.concurrent.atomic.AtomicLong();
        public final java.util.concurrent.atomic.AtomicLong udpPackets = new java.util.concurrent.atomic.AtomicLong();
    }
}
