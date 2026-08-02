package packetanalyzer;

import java.util.Locale;

public class PacketParser {
    public static class ParsedPacket {
        public int timestampSec;
        public int timestampUsec;
        public String srcMac = "";
        public String destMac = "";
        public int etherType;
        public boolean hasIp;
        public int ipVersion;
        public String srcIp = "";
        public String destIp = "";
        public int protocol;
        public int ttl;
        public boolean hasTcp;
        public boolean hasUdp;
        public int srcPort;
        public int destPort;
        public int tcpFlags;
        public long seqNumber;
        public long ackNumber;
        public int payloadLength;
        public byte[] payloadData;
    }

    public static boolean parse(PcapReader.RawPacket raw, ParsedPacket parsed) {
        parsed.timestampSec = raw.header.tsSec;
        parsed.timestampUsec = raw.header.tsUsec;
        byte[] data = raw.data;

        int offset = 0;
        if (!parseEthernet(data, parsed)) {
            return false;
        }
        offset += 14;

        if (parsed.etherType == EtherType.IPV4) {
            int ipHeaderLength = parseIPv4(data, offset, parsed);
            if (ipHeaderLength < 0) {
                return false;
            }
            offset += ipHeaderLength;

            if (parsed.protocol == Protocol.TCP) {
                int tcpHeaderLength = parseTCP(data, offset, parsed);
                if (tcpHeaderLength < 0) {
                    return false;
                }
                offset += tcpHeaderLength;
            } else if (parsed.protocol == Protocol.UDP) {
                int udpHeaderLength = parseUDP(data, offset, parsed);
                if (udpHeaderLength < 0) {
                    return false;
                }
                offset += udpHeaderLength;
            }
        }

        if (offset < data.length) {
            parsed.payloadLength = data.length - offset;
            parsed.payloadData = new byte[parsed.payloadLength];
            System.arraycopy(data, offset, parsed.payloadData, 0, parsed.payloadLength);
        } else {
            parsed.payloadLength = 0;
            parsed.payloadData = new byte[0];
        }

        return true;
    }

    private static boolean parseEthernet(byte[] data, ParsedPacket parsed) {
        if (data.length < 14) {
            return false;
        }

        parsed.destMac = macToString(data, 0);
        parsed.srcMac = macToString(data, 6);
        parsed.etherType = toUnsignedShort(data[12], data[13]);
        return true;
    }

    private static int parseIPv4(byte[] data, int offset, ParsedPacket parsed) {
        if (data.length < offset + 20) {
            return -1;
        }

        int versionIhl = data[offset] & 0xFF;
        parsed.ipVersion = (versionIhl >> 4) & 0x0F;
        int ihl = versionIhl & 0x0F;
        if (parsed.ipVersion != 4 || ihl < 5) {
            return -1;
        }

        int ipHeaderLength = ihl * 4;
        if (data.length < offset + ipHeaderLength) {
            return -1;
        }

        parsed.ttl = data[offset + 8] & 0xFF;
        parsed.protocol = data[offset + 9] & 0xFF;
        parsed.srcIp = ipToString(data, offset + 12);
        parsed.destIp = ipToString(data, offset + 16);
        parsed.hasIp = true;

        return ipHeaderLength;
    }

    private static int parseTCP(byte[] data, int offset, ParsedPacket parsed) {
        if (data.length < offset + 20) {
            return -1;
        }

        parsed.srcPort = toUnsignedShort(data[offset], data[offset + 1]);
        parsed.destPort = toUnsignedShort(data[offset + 2], data[offset + 3]);
        parsed.seqNumber = toUnsignedInt(data, offset + 4);
        parsed.ackNumber = toUnsignedInt(data, offset + 8);
        parsed.tcpFlags = data[offset + 13] & 0xFF;
        parsed.hasTcp = true;
        int dataOffset = (data[offset + 12] >> 4) & 0x0F;
        int tcpHeaderLength = dataOffset * 4;
        if (tcpHeaderLength < 20 || data.length < offset + tcpHeaderLength) {
            return -1;
        }

        return tcpHeaderLength;
    }

    private static int parseUDP(byte[] data, int offset, ParsedPacket parsed) {
        if (data.length < offset + 8) {
            return -1;
        }

        parsed.srcPort = toUnsignedShort(data[offset], data[offset + 1]);
        parsed.destPort = toUnsignedShort(data[offset + 2], data[offset + 3]);
        parsed.hasUdp = true;
        return 8;
    }

    public static String macToString(byte[] data, int offset) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 6; i++) {
            if (i > 0) sb.append(':');
            sb.append(String.format("%02x", data[offset + i]));
        }
        return sb.toString();
    }

    public static String ipToString(byte[] data, int offset) {
        return String.format(Locale.US, "%d.%d.%d.%d",
            data[offset] & 0xFF,
            data[offset + 1] & 0xFF,
            data[offset + 2] & 0xFF,
            data[offset + 3] & 0xFF);
    }

    public static String protocolToString(int protocol) {
        return switch (protocol) {
            case Protocol.ICMP -> "ICMP";
            case Protocol.TCP -> "TCP";
            case Protocol.UDP -> "UDP";
            default -> "Unknown(" + protocol + ")";
        };
    }

    public static String tcpFlagsToString(int flags) {
        StringBuilder sb = new StringBuilder();
        if ((flags & TCPFlags.SYN) != 0) sb.append("SYN ");
        if ((flags & TCPFlags.ACK) != 0) sb.append("ACK ");
        if ((flags & TCPFlags.FIN) != 0) sb.append("FIN ");
        if ((flags & TCPFlags.RST) != 0) sb.append("RST ");
        if ((flags & TCPFlags.PSH) != 0) sb.append("PSH ");
        if ((flags & TCPFlags.URG) != 0) sb.append("URG ");
        if (sb.length() == 0) {
            return "none";
        }
        return sb.toString().trim();
    }

    private static int toUnsignedShort(byte b1, byte b2) {
        return ((b1 & 0xFF) << 8) | (b2 & 0xFF);
    }

    private static long toUnsignedInt(byte[] data, int offset) {
        return ((long)(data[offset] & 0xFF) << 24) |
               ((long)(data[offset + 1] & 0xFF) << 16) |
               ((long)(data[offset + 2] & 0xFF) << 8) |
               ((long)(data[offset + 3] & 0xFF));
    }

    public static class EthernetHeader { }
    public static class IPv4Header { }
    public static class TCPHeader { }
    public static class UDPHeader { }
}

class EtherType {
    public static final int IPV4 = 0x0800;
    public static final int IPV6 = 0x86DD;
    public static final int ARP = 0x0806;
}

class Protocol {
    public static final int ICMP = 1;
    public static final int TCP = 6;
    public static final int UDP = 17;
}

class TCPFlags {
    public static final int FIN = 0x01;
    public static final int SYN = 0x02;
    public static final int RST = 0x04;
    public static final int PSH = 0x08;
    public static final int ACK = 0x10;
    public static final int URG = 0x20;
}
