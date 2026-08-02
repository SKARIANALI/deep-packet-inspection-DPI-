package dpi;

import java.util.Locale;
import java.util.concurrent.atomic.AtomicLong;

public class Types {
    public enum AppType {
        UNKNOWN,
        HTTP,
        HTTPS,
        DNS,
        TLS,
        QUIC,
        GOOGLE,
        FACEBOOK,
        YOUTUBE,
        TWITTER,
        INSTAGRAM,
        NETFLIX,
        AMAZON,
        MICROSOFT,
        APPLE,
        WHATSAPP,
        TELEGRAM,
        TIKTOK,
        SPOTIFY,
        ZOOM,
        DISCORD,
        GITHUB,
        CLOUDFLARE
    }

    public enum ConnectionState {
        NEW,
        ESTABLISHED,
        CLASSIFIED,
        BLOCKED,
        CLOSED
    }

    public enum PacketAction {
        FORWARD,
        DROP,
        INSPECT,
        LOG_ONLY
    }

    public static class FiveTuple {
        public int srcIp;
        public int dstIp;
        public int srcPort;
        public int dstPort;
        public int protocol;

        public FiveTuple() {
        }

        public FiveTuple(int srcIp, int dstIp, int srcPort, int dstPort, int protocol) {
            this.srcIp = srcIp;
            this.dstIp = dstIp;
            this.srcPort = srcPort;
            this.dstPort = dstPort;
            this.protocol = protocol;
        }

        public FiveTuple reverse() {
            return new FiveTuple(dstIp, srcIp, dstPort, srcPort, protocol);
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (!(o instanceof FiveTuple)) return false;
            FiveTuple that = (FiveTuple) o;
            return srcIp == that.srcIp && dstIp == that.dstIp && srcPort == that.srcPort && dstPort == that.dstPort && protocol == that.protocol;
        }

        @Override
        public int hashCode() {
            int result = Integer.hashCode(srcIp);
            result = 31 * result + Integer.hashCode(dstIp);
            result = 31 * result + Integer.hashCode(srcPort);
            result = 31 * result + Integer.hashCode(dstPort);
            result = 31 * result + Integer.hashCode(protocol);
            return result;
        }

        @Override
        public String toString() {
            return ipToString(srcIp) + ":" + (srcPort & 0xFFFF) + " -> " + ipToString(dstIp) + ":" + (dstPort & 0xFFFF)
                    + " (" + (protocol == 6 ? "TCP" : protocol == 17 ? "UDP" : "?") + ")";
        }
    }

    public static class Connection {
        public FiveTuple tuple;
        public ConnectionState state = ConnectionState.NEW;
        public AppType appType = AppType.UNKNOWN;
        public String sni = "";
        public long packetsIn;
        public long packetsOut;
        public long bytesIn;
        public long bytesOut;
        public long firstSeen;
        public long lastSeen;
        public PacketAction action = PacketAction.FORWARD;
        public boolean synSeen;
        public boolean synAckSeen;
        public boolean finSeen;
    }

    public static class PacketJob {
        public int packetId;
        public FiveTuple tuple = new FiveTuple();
        public byte[] data = new byte[0];
        public int ethOffset;
        public int ipOffset;
        public int transportOffset;
        public int payloadOffset;
        public int payloadLength;
        public int tcpFlags;
        public long tsSec;
        public long tsUsec;
    }

    public static class DPIStats {
        public final AtomicLong totalPackets = new AtomicLong();
        public final AtomicLong totalBytes = new AtomicLong();
        public final AtomicLong forwardedPackets = new AtomicLong();
        public final AtomicLong droppedPackets = new AtomicLong();
        public final AtomicLong tcpPackets = new AtomicLong();
        public final AtomicLong udpPackets = new AtomicLong();
        public final AtomicLong otherPackets = new AtomicLong();
        public final AtomicLong activeConnections = new AtomicLong();
    }

    public static String appTypeToString(AppType type) {
        return switch (type) {
            case UNKNOWN -> "Unknown";
            case HTTP -> "HTTP";
            case HTTPS -> "HTTPS";
            case DNS -> "DNS";
            case TLS -> "TLS";
            case QUIC -> "QUIC";
            case GOOGLE -> "Google";
            case FACEBOOK -> "Facebook";
            case YOUTUBE -> "YouTube";
            case TWITTER -> "Twitter/X";
            case INSTAGRAM -> "Instagram";
            case NETFLIX -> "Netflix";
            case AMAZON -> "Amazon";
            case MICROSOFT -> "Microsoft";
            case APPLE -> "Apple";
            case WHATSAPP -> "WhatsApp";
            case TELEGRAM -> "Telegram";
            case TIKTOK -> "TikTok";
            case SPOTIFY -> "Spotify";
            case ZOOM -> "Zoom";
            case DISCORD -> "Discord";
            case GITHUB -> "GitHub";
            case CLOUDFLARE -> "Cloudflare";
        };
    }

    public static AppType sniToAppType(String sni) {
        if (sni == null || sni.isEmpty()) {
            return AppType.UNKNOWN;
        }
        String lower = sni.toLowerCase(Locale.US);
        if (lower.contains("youtube") || lower.contains("ytimg") || lower.contains("youtu.be")) {
            return AppType.YOUTUBE;
        }
        if (lower.contains("google") || lower.contains("gstatic") || lower.contains("googleapis") || lower.contains("ggpht") || lower.contains("gvt1")) {
            return AppType.GOOGLE;
        }
        if (lower.contains("facebook") || lower.contains("fbcdn") || lower.contains("fb.com") || lower.contains("fbsbx") || lower.contains("meta.com")) {
            return AppType.FACEBOOK;
        }
        if (lower.contains("instagram") || lower.contains("cdninstagram")) {
            return AppType.INSTAGRAM;
        }
        if (lower.contains("whatsapp") || lower.contains("wa.me")) {
            return AppType.WHATSAPP;
        }
        if (lower.contains("twitter") || lower.contains("twimg") || lower.endsWith(".x.com") || lower.equals("x.com") || lower.endsWith(".t.co") || lower.equals("t.co")) {
            return AppType.TWITTER;
        }
        if (lower.contains("netflix") || lower.contains("nflxvideo") || lower.contains("nflximg")) {
            return AppType.NETFLIX;
        }
        if (lower.contains("amazon") || lower.contains("amazonaws") || lower.contains("cloudfront") || lower.contains("aws")) {
            return AppType.AMAZON;
        }
        if (lower.contains("microsoft") || lower.contains("msn.com") || lower.contains("office") || lower.contains("azure") || lower.contains("live.com") || lower.contains("outlook") || lower.contains("bing")) {
            return AppType.MICROSOFT;
        }
        if (lower.contains("apple") || lower.contains("icloud") || lower.contains("mzstatic") || lower.contains("itunes")) {
            return AppType.APPLE;
        }
        if (lower.contains("telegram") || lower.contains("t.me")) {
            return AppType.TELEGRAM;
        }
        if (lower.contains("tiktok") || lower.contains("tiktokcdn") || lower.contains("musical.ly") || lower.contains("bytedance")) {
            return AppType.TIKTOK;
        }
        if (lower.contains("spotify") || lower.contains("scdn.co")) {
            return AppType.SPOTIFY;
        }
        if (lower.contains("zoom")) {
            return AppType.ZOOM;
        }
        if (lower.contains("discord") || lower.contains("discordapp")) {
            return AppType.DISCORD;
        }
        if (lower.contains("github") || lower.contains("githubusercontent")) {
            return AppType.GITHUB;
        }
        if (lower.contains("cloudflare") || lower.contains("cf-")) {
            return AppType.CLOUDFLARE;
        }
        return AppType.HTTPS;
    }

    public static String ipToString(int ip) {
        return String.format(Locale.US, "%d.%d.%d.%d",
            ip & 0xFF,
            (ip >> 8) & 0xFF,
            (ip >> 16) & 0xFF,
            (ip >> 24) & 0xFF);
    }

    public static int parseIp(String ip) {
        String[] parts = ip.split("\\.");
        int result = 0;
        int shift = 0;
        for (int i = parts.length - 1; i >= 0; i--) {
            result |= (Integer.parseInt(parts[i]) & 0xFF) << shift;
            shift += 8;
        }
        return result;
    }
}
