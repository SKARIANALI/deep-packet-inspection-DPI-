package packetanalyzer;

import java.io.*;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

public class PcapReader implements Closeable {
    public static final int MAGIC_NATIVE = 0xa1b2c3d4;
    public static final int MAGIC_SWAPPED = 0xd4c3b2a1;

    public static class PcapGlobalHeader {
        public int magicNumber;
        public short versionMajor;
        public short versionMinor;
        public int thiszone;
        public int sigfigs;
        public int snaplen;
        public int network;
    }

    public static class PcapPacketHeader {
        public int tsSec;
        public int tsUsec;
        public int inclLen;
        public int origLen;
    }

    public static class RawPacket {
        public PcapPacketHeader header = new PcapPacketHeader();
        public byte[] data = new byte[0];
    }

    private final DataInputStream input;
    private final boolean needsByteSwap;
    private final PcapGlobalHeader globalHeader;

    public PcapReader(String filename) throws IOException {
        InputStream fileStream = new BufferedInputStream(new FileInputStream(filename));
        this.input = new DataInputStream(fileStream);
        this.globalHeader = readGlobalHeader();
        this.needsByteSwap = globalHeader.magicNumber == MAGIC_SWAPPED;
    }

    private PcapGlobalHeader readGlobalHeader() throws IOException {
        byte[] headerBytes = new byte[24];
        input.readFully(headerBytes);
        ByteBuffer bb = ByteBuffer.wrap(headerBytes).order(ByteOrder.BIG_ENDIAN);
        int magic = bb.getInt();

        PcapGlobalHeader header = new PcapGlobalHeader();
        header.magicNumber = magic;
        if (magic == MAGIC_NATIVE) {
            header.versionMajor = bb.getShort();
            header.versionMinor = bb.getShort();
            header.thiszone = bb.getInt();
            header.sigfigs = bb.getInt();
            header.snaplen = bb.getInt();
            header.network = bb.getInt();
        } else if (magic == MAGIC_SWAPPED) {
            header.versionMajor = swapShort(bb.getShort());
            header.versionMinor = swapShort(bb.getShort());
            header.thiszone = swapInt(bb.getInt());
            header.sigfigs = swapInt(bb.getInt());
            header.snaplen = swapInt(bb.getInt());
            header.network = swapInt(bb.getInt());
        } else {
            throw new IOException("Invalid PCAP magic number: 0x" + Integer.toHexString(magic));
        }

        return header;
    }

    public PcapGlobalHeader getGlobalHeader() {
        return globalHeader;
    }

    public boolean readNextPacket(RawPacket packet) throws IOException {
        try {
            byte[] headerBytes = new byte[16];
            input.readFully(headerBytes);
            ByteBuffer bb = ByteBuffer.wrap(headerBytes).order(ByteOrder.BIG_ENDIAN);
            int tsSec = bb.getInt();
            int tsUsec = bb.getInt();
            int inclLen = bb.getInt();
            int origLen = bb.getInt();

            if (needsByteSwap) {
                tsSec = swapInt(tsSec);
                tsUsec = swapInt(tsUsec);
                inclLen = swapInt(inclLen);
                origLen = swapInt(origLen);
            }

            if (inclLen < 0 || inclLen > globalHeader.snaplen || inclLen > 65535) {
                throw new IOException("Invalid packet length: " + inclLen);
            }

            packet.header.tsSec = tsSec;
            packet.header.tsUsec = tsUsec;
            packet.header.inclLen = inclLen;
            packet.header.origLen = origLen;
            packet.data = new byte[inclLen];
            input.readFully(packet.data);
            return true;
        } catch (EOFException e) {
            return false;
        }
    }

    private static short swapShort(short value) {
        return (short) (((value & 0xff) << 8) | ((value >>> 8) & 0xff));
    }

    private static int swapInt(int value) {
        return Integer.reverseBytes(value);
    }

    @Override
    public void close() throws IOException {
        input.close();
    }
}
