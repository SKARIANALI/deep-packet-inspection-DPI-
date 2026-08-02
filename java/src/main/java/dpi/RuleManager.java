package dpi;

import java.io.*;
import java.util.*;
import java.util.concurrent.locks.ReentrantReadWriteLock;

public class RuleManager {
    public static class BlockReason {
        public enum Type { IP, APP, DOMAIN, PORT }
        public final Type type;
        public final String detail;

        public BlockReason(Type type, String detail) {
            this.type = type;
            this.detail = detail;
        }
    }

    private final Set<Integer> blockedIps = new HashSet<>();
    private final Set<Types.AppType> blockedApps = new HashSet<>();
    private final Set<String> blockedDomains = new HashSet<>();
    private final List<String> domainPatterns = new ArrayList<>();
    private final Set<Integer> blockedPorts = new HashSet<>();
    private final ReentrantReadWriteLock lock = new ReentrantReadWriteLock();

    public void blockIp(int ip) {
        lock.writeLock().lock();
        try {
            blockedIps.add(ip);
        } finally {
            lock.writeLock().unlock();
        }
    }

    public void blockIp(String ip) {
        try {
            blockIp(Types.parseIp(ip));
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException("Invalid IP address: " + ip, e);
        }
    }

    public void unblockIp(int ip) {
        lock.writeLock().lock();
        try {
            blockedIps.remove(ip);
        } finally {
            lock.writeLock().unlock();
        }
    }

    public void unblockIp(String ip) {
        unblockIp(Types.parseIp(ip));
    }

    public boolean isIpBlocked(int ip) {
        lock.readLock().lock();
        try {
            return blockedIps.contains(ip);
        } finally {
            lock.readLock().unlock();
        }
    }

    public List<String> getBlockedIps() {
        lock.readLock().lock();
        try {
            List<String> result = new ArrayList<>();
            for (Integer ip : blockedIps) {
                result.add(Types.ipToString(ip));
            }
            return result;
        } finally {
            lock.readLock().unlock();
        }
    }

    public void blockApp(Types.AppType app) {
        lock.writeLock().lock();
        try {
            blockedApps.add(app);
            System.out.println("RuleManager: blocked app " + Types.appTypeToString(app));
        } finally {
            lock.writeLock().unlock();
        }
    }

    public void unblockApp(Types.AppType app) {
        lock.writeLock().lock();
        try {
            blockedApps.remove(app);
            System.out.println("RuleManager: unblocked app " + Types.appTypeToString(app));
        } finally {
            lock.writeLock().unlock();
        }
    }

    public boolean isAppBlocked(Types.AppType app) {
        lock.readLock().lock();
        try {
            return blockedApps.contains(app);
        } finally {
            lock.readLock().unlock();
        }
    }

    public void blockDomain(String domain) {
        lock.writeLock().lock();
        try {
            if (domain.contains("*")) {
                domainPatterns.add(domain);
            } else {
                blockedDomains.add(domain);
            }
        } finally {
            lock.writeLock().unlock();
        }
    }

    public void unblockDomain(String domain) {
        lock.writeLock().lock();
        try {
            blockedDomains.remove(domain);
            domainPatterns.remove(domain);
        } finally {
            lock.writeLock().unlock();
        }
    }

    public boolean isDomainBlocked(String domain) {
        lock.readLock().lock();
        try {
            if (blockedDomains.contains(domain)) {
                return true;
            }
            String lowerDomain = domain.toLowerCase(Locale.US);
            for (String pattern : domainPatterns) {
                if (domainMatchesPattern(lowerDomain, pattern.toLowerCase(Locale.US))) {
                    return true;
                }
            }
            return false;
        } finally {
            lock.readLock().unlock();
        }
    }

    public List<String> getBlockedDomains() {
        lock.readLock().lock();
        try {
            List<String> result = new ArrayList<>(blockedDomains);
            result.addAll(domainPatterns);
            return result;
        } finally {
            lock.readLock().unlock();
        }
    }

    public void blockPort(int port) {
        lock.writeLock().lock();
        try {
            blockedPorts.add(port);
        } finally {
            lock.writeLock().unlock();
        }
    }

    public void unblockPort(int port) {
        lock.writeLock().lock();
        try {
            blockedPorts.remove(port);
        } finally {
            lock.writeLock().unlock();
        }
    }

    public boolean isPortBlocked(int port) {
        lock.readLock().lock();
        try {
            return blockedPorts.contains(port);
        } finally {
            lock.readLock().unlock();
        }
    }

    public Optional<BlockReason> shouldBlock(int srcIp, int dstPort, Types.AppType app, String domain) {
        if (isIpBlocked(srcIp)) {
            return Optional.of(new BlockReason(BlockReason.Type.IP, Types.ipToString(srcIp)));
        }
        if (isPortBlocked(dstPort)) {
            return Optional.of(new BlockReason(BlockReason.Type.PORT, Integer.toString(dstPort)));
        }
        if (isAppBlocked(app)) {
            return Optional.of(new BlockReason(BlockReason.Type.APP, Types.appTypeToString(app)));
        }
        if (domain != null && !domain.isEmpty() && isDomainBlocked(domain)) {
            return Optional.of(new BlockReason(BlockReason.Type.DOMAIN, domain));
        }
        return Optional.empty();
    }

    public boolean saveRules(String filename) {
        lock.readLock().lock();
        try (BufferedWriter writer = new BufferedWriter(new FileWriter(filename))) {
            writer.write("[BLOCKED_IPS]\n");
            for (String ip : getBlockedIps()) {
                writer.write(ip);
                writer.write('\n');
            }
            writer.write("\n[BLOCKED_APPS]\n");
            for (Types.AppType app : blockedApps) {
                writer.write(Types.appTypeToString(app));
                writer.write('\n');
            }
            writer.write("\n[BLOCKED_DOMAINS]\n");
            for (String domain : getBlockedDomains()) {
                writer.write(domain);
                writer.write('\n');
            }
            writer.write("\n[BLOCKED_PORTS]\n");
            for (Integer port : blockedPorts) {
                writer.write(String.valueOf(port));
                writer.write('\n');
            }
            return true;
        } catch (IOException e) {
            return false;
        } finally {
            lock.readLock().unlock();
        }
    }

    public boolean loadRules(String filename) {
        lock.writeLock().lock();
        try (BufferedReader reader = new BufferedReader(new FileReader(filename))) {
            String line;
            String section = "";
            while ((line = reader.readLine()) != null) {
                line = line.trim();
                if (line.isEmpty()) continue;
                if (line.startsWith("[")) {
                    section = line;
                    continue;
                }
                switch (section) {
                    case "[BLOCKED_IPS]" -> blockIp(line);
                    case "[BLOCKED_APPS]" -> {
                        for (Types.AppType app : Types.AppType.values()) {
                            if (Types.appTypeToString(app).equals(line)) {
                                blockApp(app);
                                break;
                            }
                        }
                    }
                    case "[BLOCKED_DOMAINS]" -> blockDomain(line);
                    case "[BLOCKED_PORTS]" -> blockPort(Integer.parseInt(line));
                    default -> {
                    }
                }
            }
            return true;
        } catch (IOException e) {
            return false;
        } finally {
            lock.writeLock().unlock();
        }
    }

    public void clearAll() {
        lock.writeLock().lock();
        try {
            blockedIps.clear();
            blockedApps.clear();
            blockedDomains.clear();
            domainPatterns.clear();
            blockedPorts.clear();
        } finally {
            lock.writeLock().unlock();
        }
    }

    public RuleStats getStats() {
        lock.readLock().lock();
        try {
            RuleStats stats = new RuleStats();
            stats.blockedIps = blockedIps.size();
            stats.blockedApps = blockedApps.size();
            stats.blockedDomains = blockedDomains.size() + domainPatterns.size();
            stats.blockedPorts = blockedPorts.size();
            return stats;
        } finally {
            lock.readLock().unlock();
        }
    }

    private boolean domainMatchesPattern(String domain, String pattern) {
        if (pattern.startsWith("*.")) {
            return domain.endsWith(pattern.substring(1)) || domain.equals(pattern.substring(2));
        }
        return false;
    }

    public static class RuleStats {
        public int blockedIps;
        public int blockedApps;
        public int blockedDomains;
        public int blockedPorts;
    }
}
