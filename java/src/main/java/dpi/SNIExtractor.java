package dpi;

import java.nio.charset.StandardCharsets;
import java.util.Locale;
import java.util.Optional;

public class SNIExtractor {
    private static final int CONTENT_TYPE_HANDSHAKE = 0x16;
    private static final int HANDSHAKE_CLIENT_HELLO = 0x01;
    private static final int EXTENSION_SNI = 0x0000;
    private static final int SNI_TYPE_HOSTNAME = 0x00;

    public static Optional<String> extract(byte[] payload) {
        if (!isTlsClientHello(payload)) {
            return Optional.empty();
        }

        int offset = 5;
        if (payload.length < offset + 4) {
            return Optional.empty();
        }

        offset += 4;
        if (payload.length < offset + 2 + 32 + 1) {
            return Optional.empty();
        }

        offset += 2 + 32;
        if (offset >= payload.length) {
            return Optional.empty();
        }

        int sessionIdLength = payload[offset] & 0xFF;
        offset += 1 + sessionIdLength;
        if (offset + 2 > payload.length) {
            return Optional.empty();
        }

        int cipherSuitesLength = readUint16BE(payload, offset);
        offset += 2 + cipherSuitesLength;
        if (offset >= payload.length) {
            return Optional.empty();
        }

        int compressionMethodsLength = payload[offset] & 0xFF;
        offset += 1 + compressionMethodsLength;
        if (offset + 2 > payload.length) {
            return Optional.empty();
        }

        int extensionsLength = readUint16BE(payload, offset);
        offset += 2;
        int extensionsEnd = Math.min(payload.length, offset + extensionsLength);

        while (offset + 4 <= extensionsEnd) {
            int extensionType = readUint16BE(payload, offset);
            int extensionLength = readUint16BE(payload, offset + 2);
            offset += 4;
            if (offset + extensionLength > extensionsEnd) {
                break;
            }
            if (extensionType == EXTENSION_SNI && extensionLength >= 5) {
                int sniListLength = readUint16BE(payload, offset);
                if (sniListLength < 3 || offset + 2 + sniListLength > extensionsEnd) {
                    break;
                }
                int sniType = payload[offset + 2] & 0xFF;
                int sniLength = readUint16BE(payload, offset + 3);
                if (sniType != SNI_TYPE_HOSTNAME || sniLength > extensionLength - 5) {
                    break;
                }
                int nameOffset = offset + 5;
                if (nameOffset + sniLength > payload.length) {
                    break;
                }
                String hostname = new String(payload, nameOffset, sniLength, StandardCharsets.UTF_8);
                return Optional.of(hostname);
            }
            offset += extensionLength;
        }

        return Optional.empty();
    }

    public static boolean isTlsClientHello(byte[] payload) {
        if (payload == null || payload.length < 9) {
            return false;
        }
        if ((payload[0] & 0xFF) != CONTENT_TYPE_HANDSHAKE) {
            return false;
        }
        int version = readUint16BE(payload, 1);
        if (version < 0x0300 || version > 0x0304) {
            return false;
        }
        int recordLength = readUint16BE(payload, 3);
        if (recordLength > payload.length - 5) {
            return false;
        }
        return (payload[5] & 0xFF) == HANDSHAKE_CLIENT_HELLO;
    }

    private static int readUint16BE(byte[] data, int offset) {
        return ((data[offset] & 0xFF) << 8) | (data[offset + 1] & 0xFF);
    }

    public static class QUICSNIExtractor {
        public static Optional<String> extract(byte[] payload) {
            if (!isQuicInitial(payload)) {
                return Optional.empty();
            }
            for (int i = 0; i + 5 < payload.length; i++) {
                if ((payload[i] & 0xFF) == HANDSHAKE_CLIENT_HELLO && i >= 5) {
                    byte[] candidate = new byte[payload.length - (i - 5)];
                    System.arraycopy(payload, i - 5, candidate, 0, candidate.length);
                    Optional<String> extracted = SNIExtractor.extract(candidate);
                    if (extracted.isPresent()) {
                        return extracted;
                    }
                }
            }
            return Optional.empty();
        }

        public static boolean isQuicInitial(byte[] payload) {
            if (payload == null || payload.length < 5) {
                return false;
            }
            return (payload[0] & 0x80) != 0;
        }
    }

    public static class HTTPHostExtractor {
        private static final String HOST_PREFIX = "host:";

        public static Optional<String> extract(byte[] payload) {
            if (!isHttpRequest(payload)) {
                return Optional.empty();
            }
            String text = new String(payload, StandardCharsets.ISO_8859_1);
            String lower = text.toLowerCase(Locale.US);
            int hostIndex = lower.indexOf(HOST_PREFIX);
            if (hostIndex < 0) {
                return Optional.empty();
            }
            int start = hostIndex + HOST_PREFIX.length();
            while (start < text.length() && (text.charAt(start) == ' ' || text.charAt(start) == '\t')) {
                start++;
            }
            int end = start;
            while (end < text.length() && text.charAt(end) != '\r' && text.charAt(end) != '\n') {
                end++;
            }
            if (end <= start) {
                return Optional.empty();
            }
            String host = text.substring(start, end).trim();
            int colon = host.indexOf(':');
            if (colon > 0) {
                host = host.substring(0, colon);
            }
            return Optional.of(host);
        }

        public static boolean isHttpRequest(byte[] payload) {
            if (payload == null || payload.length < 4) {
                return false;
            }
            String[] methods = {"GET ", "POST", "PUT ", "HEAD", "DELE", "PATC", "OPTI"};
            String prefix = new String(payload, 0, Math.min(4, payload.length), StandardCharsets.ISO_8859_1);
            for (String method : methods) {
                if (prefix.equalsIgnoreCase(method)) {
                    return true;
                }
            }
            return false;
        }
    }

    public static class DNSExtractor {
        public static Optional<String> extractQuery(byte[] payload) {
            if (!isDnsQuery(payload)) {
                return Optional.empty();
            }
            int offset = 12;
            StringBuilder domain = new StringBuilder();
            while (offset < payload.length) {
                int len = payload[offset] & 0xFF;
                if (len == 0) {
                    break;
                }
                if (offset + 1 + len > payload.length) {
                    return Optional.empty();
                }
                if (domain.length() > 0) {
                    domain.append('.');
                }
                domain.append(new String(payload, offset + 1, len, StandardCharsets.ISO_8859_1));
                offset += len + 1;
            }
            return domain.length() > 0 ? Optional.of(domain.toString()) : Optional.empty();
        }

        public static boolean isDnsQuery(byte[] payload) {
            if (payload == null || payload.length < 12) {
                return false;
            }
            int flags = payload[2] & 0xFF;
            if ((flags & 0x80) != 0) {
                return false;
            }
            int qdcount = readUint16BE(payload, 4);
            return qdcount > 0;
        }
    }
}
