package packetanalyzer;

import java.io.BufferedOutputStream;
import java.io.DataOutputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Random;

public class GenerateTestPcap {
    private static final Random RANDOM = new Random(0x123456);

    public static void main(String[] args) throws IOException {
        String filename = args.length > 0 ? args[0] : "test_dpi.pcap";
        try (DataOutputStream writer = new DataOutputStream(new BufferedOutputStream(new FileOutputStream(filename)))) {
            writeGlobalHeader(writer);

            String userMac = "00:11:22:33:44:55";
            String userIp = "192.168.1.100";
            String gatewayMac = "aa:bb:cc:dd:ee:ff";

            String[][] tlsConnections = {
                {"142.250.185.206", "www.google.com", "443"},
                {"142.250.185.110", "www.youtube.com", "443"},
                {"157.240.1.35", "www.facebook.com", "443"},
                {"157.240.1.174", "www.instagram.com", "443"},
                {"104.244.42.65", "twitter.com", "443"},
                {"52.94.236.248", "www.amazon.com", "443"},
                {"23.52.167.61", "www.netflix.com", "443"},
                {"140.82.114.4", "github.com", "443"},
                {"104.16.85.20", "discord.com", "443"},
                {"35.186.224.25", "zoom.us", "443"},
                {"35.186.227.140", "web.telegram.org", "443"},
                {"99.86.0.100", "www.tiktok.com", "443"},
                {"35.186.224.47", "open.spotify.com", "443"},
                {"192.0.78.24", "www.cloudflare.com", "443"},
                {"13.107.42.14", "www.microsoft.com", "443"},
                {"17.253.144.10", "www.apple.com", "443"},
            };

            String[][] httpConnections = {
                {"93.184.216.34", "example.com", "80"},
                {"185.199.108.153", "httpbin.org", "80"},
            };

            String[] dnsQueries = {
                "www.google.com",
                "www.youtube.com",
                "www.facebook.com",
                "api.twitter.com",
            };

            int seqBase = 1000;
            long timestamp = 1700000000L;

            for (String[] entry : tlsConnections) {
                String dstIp = entry[0];
                String sni = entry[1];
                int dstPort = Integer.parseInt(entry[2]);
                int srcPort = randomPort();

                byte[] eth = createEthernetHeader(userMac, gatewayMac);
                byte[] tcp = createTcpHeader(srcPort, dstPort, seqBase, 0, 0x02);
                byte[] ip = createIpHeader(userIp, dstIp, 6, tcp.length);
                writePacket(writer, timestamp++, randomMicros(), concat(eth, ip, tcp));

                eth = createEthernetHeader(gatewayMac, userMac);
                tcp = createTcpHeader(dstPort, srcPort, seqBase + 1000, seqBase + 1, 0x12);
                ip = createIpHeader(dstIp, userIp, 6, tcp.length);
                writePacket(writer, timestamp++, randomMicros(), concat(eth, ip, tcp));

                eth = createEthernetHeader(userMac, gatewayMac);
                tcp = createTcpHeader(srcPort, dstPort, seqBase + 1, seqBase + 1001, 0x10);
                ip = createIpHeader(userIp, dstIp, 6, tcp.length);
                writePacket(writer, timestamp++, randomMicros(), concat(eth, ip, tcp));

                byte[] tlsData = createTlsClientHello(sni);
                tcp = createTcpHeader(srcPort, dstPort, seqBase + 1, seqBase + 1001, 0x18);
                ip = createIpHeader(userIp, dstIp, 6, tcp.length + tlsData.length);
                writePacket(writer, timestamp++, randomMicros(), concat(eth, ip, tcp, tlsData));

                seqBase += 10000;
            }

            for (String[] entry : httpConnections) {
                String dstIp = entry[0];
                String host = entry[1];
                int dstPort = Integer.parseInt(entry[2]);
                int srcPort = randomPort();

                byte[] eth = createEthernetHeader(userMac, gatewayMac);
                byte[] tcp = createTcpHeader(srcPort, dstPort, seqBase, 0, 0x02);
                byte[] ip = createIpHeader(userIp, dstIp, 6, tcp.length);
                writePacket(writer, timestamp++, randomMicros(), concat(eth, ip, tcp));

                byte[] httpData = createHttpRequest(host);
                tcp = createTcpHeader(srcPort, dstPort, seqBase + 1, 1, 0x18);
                ip = createIpHeader(userIp, dstIp, 6, tcp.length + httpData.length);
                writePacket(writer, timestamp++, randomMicros(), concat(eth, ip, tcp, httpData));

                seqBase += 10000;
            }

            String dnsServer = "8.8.8.8";
            for (String domain : dnsQueries) {
                int srcPort = randomPort();
                byte[] dnsData = createDnsQuery(domain);
                byte[] eth = createEthernetHeader(userMac, gatewayMac);
                byte[] udp = createUdpHeader(srcPort, 53, dnsData.length);
                byte[] ip = createIpHeader(userIp, dnsServer, 17, udp.length + dnsData.length);
                writePacket(writer, timestamp++, randomMicros(), concat(eth, ip, udp, dnsData));
            }

            String blockedSourceIp = "192.168.1.50";
            for (int i = 0; i < 5; i++) {
                int srcPort = randomPort();
                String dstIp = "172.217.0.100";
                byte[] eth = createEthernetHeader("00:11:22:33:44:56", gatewayMac);
                byte[] tcp = createTcpHeader(srcPort, 443, seqBase, 0, 0x02);
                byte[] ip = createIpHeader(blockedSourceIp, dstIp, 6, tcp.length);
                writePacket(writer, timestamp++, randomMicros(), concat(eth, ip, tcp));
                seqBase += 1000;
            }
        }
        System.out.println("Created test_dpi.pcap with test traffic");
    }

    private static int randomPort() {
        return 49152 + RANDOM.nextInt(65535 - 49152);
    }

    private static int randomMicros() {
        return RANDOM.nextInt(1_000_000);
    }

    private static void writeGlobalHeader(DataOutputStream out) throws IOException {
        ByteBuffer buffer = ByteBuffer.allocate(24).order(ByteOrder.LITTLE_ENDIAN);
        buffer.putInt(0xa1b2c3d4);
        buffer.putShort((short) 2);
        buffer.putShort((short) 4);
        buffer.putInt(0);
        buffer.putInt(0);
        buffer.putInt(65535);
        buffer.putInt(1);
        out.write(buffer.array());
    }

    private static void writePacket(DataOutputStream out, long tsSec, int tsUsec, byte[] data) throws IOException {
        ByteBuffer buffer = ByteBuffer.allocate(16).order(ByteOrder.LITTLE_ENDIAN);
        buffer.putInt((int) tsSec);
        buffer.putInt(tsUsec);
        buffer.putInt(data.length);
        buffer.putInt(data.length);
        out.write(buffer.array());
        out.write(data);
    }

    private static byte[] createEthernetHeader(String srcMac, String dstMac) {
        return concat(parseMac(dstMac), parseMac(srcMac), toBytes((short) 0x0800));
    }

    private static byte[] parseMac(String mac) {
        String[] parts = mac.split(":");
        byte[] result = new byte[6];
        for (int i = 0; i < 6; i++) {
            result[i] = (byte) Integer.parseInt(parts[i], 16);
        }
        return result;
    }

    private static byte[] createIpHeader(String srcIp, String dstIp, int protocol, int payloadLen) {
        int totalLen = 20 + payloadLen;
        int ident = RANDOM.nextInt(0xFFFF) + 1;
        int flagsFrag = 0x4000;
        ByteBuffer buffer = ByteBuffer.allocate(20).order(ByteOrder.BIG_ENDIAN);
        buffer.put((byte) 0x45);
        buffer.put((byte) 0);
        buffer.putShort((short) totalLen);
        buffer.putShort((short) ident);
        buffer.putShort((short) flagsFrag);
        buffer.put((byte) 64);
        buffer.put((byte) protocol);
        buffer.putShort((short) 0);
        buffer.put(parseIpv4(srcIp));
        buffer.put(parseIpv4(dstIp));
        return buffer.array();
    }

    private static byte[] createTcpHeader(int srcPort, int dstPort, long seq, long ack, int flags) {
        ByteBuffer buffer = ByteBuffer.allocate(20).order(ByteOrder.BIG_ENDIAN);
        buffer.putShort((short) srcPort);
        buffer.putShort((short) dstPort);
        buffer.putInt((int) seq);
        buffer.putInt((int) ack);
        buffer.put((byte) (5 << 4));
        buffer.put((byte) flags);
        buffer.putShort((short) 65535);
        buffer.putShort((short) 0);
        buffer.putShort((short) 0);
        return buffer.array();
    }

    private static byte[] createUdpHeader(int srcPort, int dstPort, int payloadLen) {
        ByteBuffer buffer = ByteBuffer.allocate(8).order(ByteOrder.BIG_ENDIAN);
        buffer.putShort((short) srcPort);
        buffer.putShort((short) dstPort);
        buffer.putShort((short) (8 + payloadLen));
        buffer.putShort((short) 0);
        return buffer.array();
    }

    private static byte[] createTlsClientHello(String sni) {
        byte[] sniBytes = sni.getBytes();
        byte[] sniEntry = concat(new byte[]{0}, toBytes((short) sniBytes.length), sniBytes);
        byte[] sniList = concat(toBytes((short) sniEntry.length), sniEntry);
        byte[] sniExt = concat(toBytes((short) 0x0000), toBytes((short) sniList.length), sniList);
        byte[] supportedVersions = concat(toBytes((short) 0x002b), new byte[]{3}, toBytes((short) 0x0304));
        byte[] extensions = concat(sniExt, supportedVersions);
        byte[] extensionsData = concat(toBytes((short) extensions.length), extensions);

        byte[] clientVersion = toBytes((short) 0x0303);
        byte[] randomBytes = new byte[32];
        RANDOM.nextBytes(randomBytes);
        byte[] sessionId = new byte[]{0};
        byte[] cipherSuites = concat(toBytes((short) 4), toBytes((short) 0x1301), toBytes((short) 0x1302));
        byte[] compression = new byte[]{1, 0};
        byte[] clientHelloBody = concat(clientVersion, randomBytes, sessionId, cipherSuites, compression, extensionsData);

        byte[] handshakeLength = int24(clientHelloBody.length);
        byte[] handshake = concat(new byte[]{0x01}, handshakeLength, clientHelloBody);

        byte[] record = concat(new byte[]{0x16}, toBytes((short) 0x0301), toBytes((short) handshake.length), handshake);
        return record;
    }

    private static byte[] createHttpRequest(String host) {
        String request = """
                GET / HTTP/1.1\r
                Host: %s\r
                User-Agent: DPI-Test/1.0\r
                Accept: */*\r
                \r
                """.formatted(host);
        return request.getBytes();
    }

    private static byte[] createDnsQuery(String domain) {
        byte[] txid = toBytes((short) (RANDOM.nextInt(0xFFFF) + 1));
        byte[] flags = toBytes((short) 0x0100);
        byte[] counts = concat(toBytes((short) 1), toBytes((short) 0), toBytes((short) 0), toBytes((short) 0));
        ByteBuffer question = ByteBuffer.allocate(512).order(ByteOrder.BIG_ENDIAN);
        for (String label : domain.split("\\.")) {
            question.put((byte) label.length());
            question.put(label.getBytes());
        }
        question.put((byte) 0);
        question.putShort((short) 1);
        question.putShort((short) 1);
        question.flip();
        byte[] questionBytes = new byte[question.limit()];
        question.get(questionBytes);
        return concat(txid, flags, counts, questionBytes);
    }

    private static byte[] parseIpv4(String ip) {
        String[] parts = ip.split("\\.");
        byte[] result = new byte[4];
        for (int i = 0; i < 4; i++) {
            result[i] = (byte) Integer.parseInt(parts[i]);
        }
        return result;
    }

    private static byte[] toBytes(short value) {
        ByteBuffer b = ByteBuffer.allocate(2).order(ByteOrder.BIG_ENDIAN);
        b.putShort(value);
        return b.array();
    }

    private static byte[] int24(int value) {
        return new byte[]{(byte) ((value >> 16) & 0xFF), (byte) ((value >> 8) & 0xFF), (byte) (value & 0xFF)};
    }

    private static byte[] concat(byte[]... parts) {
        int length = 0;
        for (byte[] part : parts) {
            length += part.length;
        }
        byte[] result = new byte[length];
        int offset = 0;
        for (byte[] part : parts) {
            System.arraycopy(part, 0, result, offset, part.length);
            offset += part.length;
        }
        return result;
    }
}
