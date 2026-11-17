import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.Arrays;

import static java.nio.charset.StandardCharsets.US_ASCII;

/**
 * HKDF key schedule (docs/PROTOCOL.md §4), with the hash chosen in <HashSuite>:
 *
 *   stage 1 (before DH):  PRK = HKDF-Extract(IKM = PSK)                 -> keys for message 2
 *   stage 2 (after DH):   PRK = HKDF-Extract(salt = PSK, IKM = DH)      -> message 3 and the stream
 *   every key:            HKDF-Expand(PRK, "3S " || label || transcript hash, length)
 *
 * The PSK authenticates (no PSK, no keys: no man-in-the-middle); the ephemeral DH secret gives
 * forward secrecy to the stream; the transcript hash binds each key to the exact messages seen.
 * HKDF is written here with Mac (RFC 5869) so the code runs on JDK 21+; javax.crypto.KDF only
 * exists from JDK 25 and gives the same bytes.
 */
final class KeySchedule {

    private static final byte[] LABEL_PREFIX = "3S ".getBytes(US_ASCII);

    private final String hashAlgorithm;
    private final String macAlgorithm; // HmacSHA256 | HmacSHA384 | HmacSHA512
    private final byte[] psk;
    private byte[] prk;

    KeySchedule(String hashAlgorithm, byte[] psk) throws GeneralSecurityException {
        this.hashAlgorithm = hashAlgorithm;
        this.macAlgorithm = "Hmac" + hashAlgorithm.replace("-", "");
        this.psk = psk.clone();
        prk = extract(new byte[Mac.getInstance(macAlgorithm).getMacLength()], this.psk); // no salt = HashLen zeros
    }

    /** Stage 2: from now on every key also depends on the ephemeral Diffie-Hellman secret. */
    void mixDiffieHellman(byte[] dhSecret) throws GeneralSecurityException {
        prk = extract(psk, dhSecret);
    }

    /** Keys for one direction of one phase, e.g. keys(suite, "hs s2p", th1). */
    SessionKeys keys(CipherSuite suite, String label, byte[] transcriptHash) throws GeneralSecurityException {
        byte[] info = SSPMessage.concat(LABEL_PREFIX, label.getBytes(US_ASCII), transcriptHash);
        return suite.split(expand(info, suite.keyMaterialLength()));
    }

    /** Hash of the concatenated arguments: transcript hashes (exact wire bytes) and R = H(SRV). */
    byte[] hash(byte[]... parts) throws GeneralSecurityException {
        MessageDigest md = MessageDigest.getInstance(hashAlgorithm);
        for (byte[] p : parts) md.update(p);
        return md.digest();
    }

    // ---- HKDF (RFC 5869) ----

    /** PRK = HMAC(salt, IKM) */
    private byte[] extract(byte[] salt, byte[] ikm) throws GeneralSecurityException {
        Mac mac = Mac.getInstance(macAlgorithm);
        mac.init(new SecretKeySpec(salt, macAlgorithm));
        return mac.doFinal(ikm);
    }

    /** OKM = first length bytes of T(1) | T(2) | ..., where T(i) = HMAC(PRK, T(i-1) | info | i) */
    private byte[] expand(byte[] info, int length) throws GeneralSecurityException {
        Mac mac = Mac.getInstance(macAlgorithm);
        if (length > 255 * mac.getMacLength()) throw new IllegalArgumentException("HKDF output too long");
        mac.init(new SecretKeySpec(prk, macAlgorithm));
        ByteArrayOutputStream okm = new ByteArrayOutputStream();
        byte[] t = new byte[0];
        for (int i = 1; okm.size() < length; i++) {
            mac.update(t);
            mac.update(info);
            mac.update((byte) i);
            t = mac.doFinal();
            okm.writeBytes(t);
        }
        return Arrays.copyOf(okm.toByteArray(), length);
    }
}
