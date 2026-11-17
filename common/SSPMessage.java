import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;

/**
 * One SSP message as it travels on the wire: a 9-byte plaintext header
 * (version u16 | release u16 | type u8 | payload length u32, big-endian) followed by the payload.
 * Also holds the length-prefixed field codecs (str, bytes) every payload uses.
 * Layout: docs/PROTOCOL.md §2.
 */
final class SSPMessage {

    static final int VERSION = 1;
    static final int RELEASE = 1;
    static final int HEADER_LEN = 9;
    static final int MAX_PAYLOAD = 16384;
    static final int MAX_FIELD = 4096;

    static final int HELLO = 1;
    static final int CHALLENGE = 2;
    static final int RESPONSE = 3;
    static final int DATA = 4;
    static final int END = 5;
    static final int STREAM_INFO = 6;
    static final int ALERT = 255;

    final int type;
    final byte[] header;
    final byte[] payload;

    private SSPMessage(int type, byte[] header, byte[] payload) {
        this.type = type;
        this.header = header;
        this.payload = payload;
    }

    /** The exact bytes that were on the wire, used for the transcript hashes. */
    byte[] bytes() {
        return concat(header, payload);
    }

    int wireLength() {
        return header.length + payload.length;
    }

    static byte[] header(int type, int payloadLength) {
        return ByteBuffer.allocate(HEADER_LEN)
                .putShort((short) VERSION)
                .putShort((short) RELEASE)
                .put((byte) type)
                .putInt(payloadLength)
                .array();
    }

    static byte[] encode(int type, byte[] payload) {
        return concat(header(type, payload.length), payload);
    }

    /**
     * Reads exactly one message. Rejects an unknown version or an oversized payload before
     * allocating anything. Throws EOFException if the peer closed the connection.
     */
    static SSPMessage read(InputStream in) throws IOException, ProtocolAlert {
        DataInputStream din = new DataInputStream(in);
        byte[] header = new byte[HEADER_LEN];
        din.readFully(header);

        ByteBuffer h = ByteBuffer.wrap(header);
        int version = h.getShort() & 0xffff;
        int release = h.getShort() & 0xffff;
        int type = h.get() & 0xff;
        long length = h.getInt() & 0xffffffffL;
        if (version != VERSION || release != RELEASE) {
            // Printable first bytes mean the peer does not speak SSP at all, e.g. "GET " from a browser
            String first = new String(header, 0, 4, StandardCharsets.US_ASCII);
            boolean text = first.chars().allMatch(c -> c >= 0x20 && c < 0x7f);
            throw new ProtocolAlert(ProtocolAlert.UNSUPPORTED_VERSION, "got " + version + ":" + release
                    + ", expected " + VERSION + ":" + RELEASE + (text ? " (starts with \"" + first + "\": not an SSP peer)" : ""));
        }
        if (length > MAX_PAYLOAD) {
            throw new ProtocolAlert(ProtocolAlert.RECORD_TOO_LARGE, length + " bytes");
        }

        byte[] payload = new byte[(int) length];
        din.readFully(payload);
        return new SSPMessage(type, header, payload);
    }

    // ---- field codecs: str = u16 length | UTF-8, bytes = u16 length | raw ----

    static void writeStr(DataOutputStream out, String s) throws IOException {
        writeBytes(out, s.getBytes(StandardCharsets.UTF_8));
    }

    static void writeBytes(DataOutputStream out, byte[] b) throws IOException {
        if (b.length > MAX_FIELD) throw new IllegalArgumentException("field longer than " + MAX_FIELD + " bytes");
        out.writeShort(b.length);
        out.write(b);
    }

    static String readStr(DataInputStream in) throws IOException, ProtocolAlert {
        return new String(readBytes(in), StandardCharsets.UTF_8);
    }

    static byte[] readBytes(DataInputStream in) throws IOException, ProtocolAlert {
        int length = in.readUnsignedShort();
        if (length > MAX_FIELD) throw new ProtocolAlert(ProtocolAlert.DECODE_ERROR, "field of " + length + " bytes");
        byte[] b = new byte[length];
        in.readFully(b);
        return b;
    }

    static byte[] concat(byte[]... parts) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (byte[] p : parts) out.writeBytes(p);
        return out.toByteArray();
    }
}
