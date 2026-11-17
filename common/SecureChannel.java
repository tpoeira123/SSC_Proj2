import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

/**
 * Protects and checks SSP messages for one connection and one key phase (handshake or
 * application), in both directions (docs/PROTOCOL.md §5).
 *
 *   types 4, 5, 6, 255:  payload = SEQ | CIPHERTEXT | TAG or MAC     (SEQ in clear, as in Type 4)
 *   types 2, 3:          payload = CIPHERTEXT | TAG or MAC           (SEQ only inside, as in the PDF)
 *
 * AAD = HEADER | SEQ, always: when the SEQ is not on the wire the receiver uses the SEQ it
 * expects, so the tag/MAC binds the SEQ in every message type. The IV is derived from
 * (TYPE, SEQ). The caller passes the SEQ it expects: a replayed, reordered, dropped or duplicated
 * message carries another SEQ (BAD_SEQUENCE) or, when the SEQ is not in clear, fails the tag/MAC
 * (BAD_RECORD_MAC). Not thread-safe: one instance per connection.
 */
final class SecureChannel {

    private static final int SEQ_LEN = 8;

    private final CipherSuite suite;
    private final SessionKeys sendKeys;
    private final SessionKeys recvKeys;
    private final Cipher cipher;
    private final Cipher ivCipher;
    private final Mac mac;
    private final Map<Integer, Long> lastSealedSeq = new HashMap<>();

    SecureChannel(CipherSuite suite, SessionKeys sendKeys, SessionKeys recvKeys) throws GeneralSecurityException {
        this.suite = suite;
        this.sendKeys = sendKeys;
        this.recvKeys = recvKeys;
        this.cipher = suite.newCipher();
        this.ivCipher = suite.newIvCipher();
        this.mac = suite.newMac();
    }

    static boolean seqInClear(int type) {
        return type != SSPMessage.CHALLENGE && type != SSPMessage.RESPONSE;
    }

    /** Builds a complete protected message (header included), ready to write to the socket. */
    byte[] seal(int type, long seq, byte[] plaintext) throws GeneralSecurityException {
        // Last line of defence against IV reuse: (type, seq) must grow for every message we send
        Long previous = lastSealedSeq.put(type, seq);
        if (previous != null && seq <= previous) throw new IllegalStateException("SEQ " + seq + " reused for type " + type);

        cipher.init(Cipher.ENCRYPT_MODE, sendKeys.encKey(), suite.params(sendKeys, type, seq, ivCipher));
        byte[] clearSeq = seqInClear(type) ? seqBytes(seq) : new byte[0];
        int ciphertextLen = cipher.getOutputSize(plaintext.length); // includes the tag for AEAD
        int macLen = suite.aead ? 0 : mac.getMacLength();

        byte[] header = SSPMessage.header(type, clearSeq.length + ciphertextLen + macLen);
        byte[] aad = SSPMessage.concat(header, seqBytes(seq));

        byte[] body;
        if (suite.aead) {
            cipher.updateAAD(aad);
            body = cipher.doFinal(plaintext);
        } else { // encrypt-then-MAC: the MAC covers the AAD and the ciphertext
            byte[] ciphertext = cipher.doFinal(plaintext);
            mac.init(sendKeys.macKey());
            mac.update(aad);
            body = SSPMessage.concat(ciphertext, mac.doFinal(ciphertext));
        }
        if (body.length != ciphertextLen + macLen) throw new IllegalStateException("message length mismatch");
        return SSPMessage.concat(header, clearSeq, body); // header | [seq] | ciphertext | tag
    }

    /**
     * Verifies and decrypts a protected message that must carry expectedSeq. Order of checks:
     * length, SEQ, tag/MAC, then decryption (nothing is decrypted before it is authenticated).
     */
    byte[] open(SSPMessage m, long expectedSeq) throws ProtocolAlert {
        byte[] p = m.payload;
        int bodyStart = seqInClear(m.type) ? SEQ_LEN : 0;
        int tagLen = suite.aead ? CipherSuite.TAG_LEN : mac.getMacLength();
        if (p.length < bodyStart + tagLen) throw new ProtocolAlert(ProtocolAlert.DECODE_ERROR, "message too short");

        if (bodyStart > 0) {
            long seq = ByteBuffer.wrap(p, 0, SEQ_LEN).getLong();
            if (seq != expectedSeq) {
                throw new ProtocolAlert(ProtocolAlert.BAD_SEQUENCE, "expected " + expectedSeq + ", got " + seq);
            }
        }
        byte[] aad = SSPMessage.concat(m.header, seqBytes(expectedSeq));

        try {
            if (suite.aead) {
                cipher.init(Cipher.DECRYPT_MODE, recvKeys.encKey(), suite.params(recvKeys, m.type, expectedSeq, ivCipher));
                cipher.updateAAD(aad);
                return cipher.doFinal(p, bodyStart, p.length - bodyStart); // checks the tag first
            }
            int ciphertextLen = p.length - bodyStart - tagLen;
            mac.init(recvKeys.macKey());
            mac.update(aad);
            mac.update(p, bodyStart, ciphertextLen);
            byte[] received = Arrays.copyOfRange(p, bodyStart + ciphertextLen, p.length);
            if (!MessageDigest.isEqual(mac.doFinal(), received)) { // constant-time comparison
                throw new ProtocolAlert(ProtocolAlert.BAD_RECORD_MAC, "MAC mismatch (type " + m.type + ", SEQ " + expectedSeq + ")");
            }
            cipher.init(Cipher.DECRYPT_MODE, recvKeys.encKey(), suite.params(recvKeys, m.type, expectedSeq, ivCipher));
            return cipher.doFinal(p, bodyStart, ciphertextLen);
        } catch (AEADBadTagException e) {
            throw new ProtocolAlert(ProtocolAlert.BAD_RECORD_MAC, "tag mismatch (type " + m.type + ", SEQ " + expectedSeq + ")");
        } catch (GeneralSecurityException e) { // authenticated but undecryptable: the sender is broken
            throw new ProtocolAlert(ProtocolAlert.DECODE_ERROR, "cannot decrypt (" + e.getMessage() + ")");
        }
    }

    private static byte[] seqBytes(long seq) {
        return ByteBuffer.allocate(SEQ_LEN).putLong(seq).array();
    }
}
