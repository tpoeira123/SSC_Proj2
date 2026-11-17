import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.security.SecureRandom;
import java.util.Arrays;

import static java.nio.charset.StandardCharsets.US_ASCII;

/**
 * Plaintext layout of every SSP payload (docs/PROTOCOL.md §3). Both peers use these codecs,
 * so the proxy and the server cannot drift apart. Every decode rejects truncated input,
 * oversized fields and trailing bytes with DECODE_ERROR.
 */
final class Payloads {

    static final int SRV_LEN = 32; // 256-bit challenge, as the assignment specifies
    private static final byte[] END_MARK = "END".getBytes(US_ASCII);
    private static final int END_RANDOM_LEN = 16;
    private static final SecureRandom RANDOM = new SecureRandom();

    private Payloads() {}

    /**
     * Type 1, sent in clear: SEQX | PCC as in the assignment, then the additions (MAC, key
     * exchange, hash, key sizes) and the proxy's ephemeral DH public key.
     */
    record Hello(long seqX, String pcc, String macAlg, String kexAlg, String hashAlg,
                 int keyBits, int macKeyBits, byte[] dhPub) {
        byte[] encode() {
            return write(out -> {
                out.writeLong(seqX);
                SSPMessage.writeStr(out, pcc);
                SSPMessage.writeStr(out, macAlg);
                SSPMessage.writeStr(out, kexAlg);
                SSPMessage.writeStr(out, hashAlg);
                out.writeShort(keyBits);
                out.writeShort(macKeyBits);
                SSPMessage.writeBytes(out, dhPub);
            });
        }

        static Hello decode(byte[] payload) throws ProtocolAlert {
            Hello h = read(payload, in -> new Hello(in.readLong(), SSPMessage.readStr(in), SSPMessage.readStr(in),
                    SSPMessage.readStr(in), SSPMessage.readStr(in), in.readUnsignedShort(), in.readUnsignedShort(),
                    SSPMessage.readBytes(in)));
            // Sent in clear by anyone: algorithm names are printable ASCII, so no CR/LF can reach the logs
            if (!isPrintableAscii(h.pcc) || !isPrintableAscii(h.macAlg) || !isPrintableAscii(h.kexAlg)
                    || !isPrintableAscii(h.hashAlg)) {
                throw new ProtocolAlert(ProtocolAlert.DECODE_ERROR, "HELLO with non-printable characters");
            }
            return h;
        }
    }

    /**
     * Type 2 encrypted part: SEQY | SRV (the server's challenge) | CCC (confirmed configuration)
     * as in the assignment, then the server's ephemeral DH public key (addition).
     */
    record Challenge(long seqY, byte[] srv, String ccc, byte[] dhPub) {
        byte[] encode() {
            return write(out -> {
                out.writeLong(seqY);
                out.write(srv);
                SSPMessage.writeStr(out, ccc);
                SSPMessage.writeBytes(out, dhPub);
            });
        }

        static Challenge decode(byte[] plaintext) throws ProtocolAlert {
            return read(plaintext, in -> new Challenge(in.readLong(), fixed(in, SRV_LEN), SSPMessage.readStr(in),
                    SSPMessage.readBytes(in)));
        }
    }

    /**
     * Type 3 encrypted part: SEQZ | R = H(SRV) | MEDIA as in the assignment, then the byte range
     * for seeking (addition, see PROTOCOL.md §3). R is length-prefixed since its size follows the hash.
     */
    record Response(long seqZ, byte[] r, String media, long rangeStart, long rangeEnd) {
        byte[] encode() {
            return write(out -> {
                out.writeLong(seqZ);
                SSPMessage.writeBytes(out, r);
                SSPMessage.writeStr(out, media);
                out.writeLong(rangeStart);
                out.writeLong(rangeEnd);
            });
        }

        static Response decode(byte[] plaintext) throws ProtocolAlert {
            Response r = read(plaintext, in -> new Response(in.readLong(), SSPMessage.readBytes(in), SSPMessage.readStr(in),
                    in.readLong(), in.readLong()));
            // MEDIA comes from the browser's URL and is logged: UTF-8 names are fine, control characters are not
            if (r.media.chars().anyMatch(c -> c < 0x20 || c == 0x7f)) {
                throw new ProtocolAlert(ProtocolAlert.DECODE_ERROR, "MEDIA with control characters");
            }
            return r;
        }
    }

    /** Type 6 encrypted part: what the proxy needs to answer the browser (status, size, range, type). */
    record StreamInfo(int status, long fileSize, long start, long end, String contentType) {
        static final int OK = 0;
        static final int PARTIAL = 1;
        static final int NOT_FOUND = 2;
        static final int RANGE_NOT_SATISFIABLE = 3;

        boolean hasBody() {
            return status == OK || status == PARTIAL;
        }

        long length() {
            return hasBody() ? end - start + 1 : 0;
        }

        byte[] encode() {
            return write(out -> {
                out.writeByte(status);
                out.writeLong(fileSize);
                out.writeLong(start);
                out.writeLong(end);
                SSPMessage.writeStr(out, contentType);
            });
        }

        static StreamInfo decode(byte[] plaintext) throws ProtocolAlert {
            StreamInfo info = read(plaintext, in -> new StreamInfo(in.readUnsignedByte(), in.readLong(),
                    in.readLong(), in.readLong(), SSPMessage.readStr(in)));
            boolean rangeOk = 0 <= info.start && info.start <= info.end && info.end < info.fileSize;
            if (info.status > RANGE_NOT_SATISFIABLE
                    || (info.hasBody() && !rangeOk)
                    || (info.status == OK && (info.start != 0 || info.end != info.fileSize - 1))
                    || !isPrintableAscii(info.contentType)) { // copied into an HTTP header: no CR/LF injection
                throw new ProtocolAlert(ProtocolAlert.DECODE_ERROR, "STREAM_INFO " + info);
            }
            return info;
        }
    }

    /**
     * Type 5 encrypted part: ENDBLOCK = SEQF | "END" | random as in the assignment, then the
     * totals the proxy checks to detect a truncated stream (addition).
     */
    record End(long seqF, long totalBlocks, long totalBytes) {
        byte[] encode() {
            byte[] random = new byte[END_RANDOM_LEN];
            RANDOM.nextBytes(random);
            return write(out -> {
                out.writeLong(seqF);
                out.write(END_MARK);
                out.write(random);
                out.writeLong(totalBlocks);
                out.writeLong(totalBytes);
            });
        }

        static End decode(byte[] plaintext) throws ProtocolAlert {
            return read(plaintext, in -> {
                long seqF = in.readLong();
                if (!Arrays.equals(fixed(in, END_MARK.length), END_MARK)) {
                    throw new ProtocolAlert(ProtocolAlert.DECODE_ERROR, "END mark");
                }
                fixed(in, END_RANDOM_LEN);
                return new End(seqF, in.readLong(), in.readLong());
            });
        }
    }

    /** Type 255 body: one byte, the alert code. */
    static byte[] alert(int code) {
        return new byte[]{(byte) code};
    }

    static int alertCode(byte[] body) throws ProtocolAlert {
        if (body.length != 1) throw new ProtocolAlert(ProtocolAlert.DECODE_ERROR, "ALERT of " + body.length + " bytes");
        return body[0] & 0xff;
    }

    // ---- helpers ----

    private static boolean isPrintableAscii(String s) {
        return s.chars().allMatch(c -> c >= 0x20 && c < 0x7f);
    }

    private interface Writer {
        void write(DataOutputStream out) throws IOException;
    }

    private interface Parser<T> {
        T parse(DataInputStream in) throws IOException, ProtocolAlert;
    }

    private static byte[] write(Writer w) {
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        try {
            w.write(new DataOutputStream(buffer));
        } catch (IOException e) {
            throw new IllegalStateException(e); // a ByteArrayOutputStream never fails
        }
        return buffer.toByteArray();
    }

    private static <T> T read(byte[] data, Parser<T> p) throws ProtocolAlert {
        DataInputStream in = new DataInputStream(new ByteArrayInputStream(data));
        try {
            T value = p.parse(in);
            if (in.available() != 0) throw new ProtocolAlert(ProtocolAlert.DECODE_ERROR, "trailing bytes");
            return value;
        } catch (IOException e) { // EOFException: the payload was shorter than its layout
            throw new ProtocolAlert(ProtocolAlert.DECODE_ERROR, "truncated payload");
        }
    }

    private static byte[] fixed(DataInputStream in, int length) throws IOException {
        byte[] b = new byte[length];
        in.readFully(b);
        return b;
    }
}
