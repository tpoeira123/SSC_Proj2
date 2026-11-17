import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.ChaCha20ParameterSpec;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Security;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;

/**
 * Turns a CryptoConfig into JCA objects: which Cipher transformation and Mac to use, how long
 * the session keys are, and how each message's IV is built (docs/PROTOCOL.md §5 and §6).
 * Immutable, so one instance is shared by all connections.
 */
final class CipherSuite {

    enum Kind { GCM, CHACHA20_POLY1305, CHACHA20, CTR, OFB, CBC, CFB }

    static final int TAG_LEN = 16; // GCM and Poly1305 tags

    final Kind kind;
    final boolean aead;
    final String transformation;
    final String keyAlgorithm;
    final String macAlgorithm; // JCA name, e.g. HmacSHA256; null for AEAD
    final int encKeyLen;       // bytes
    final int macKeyLen;       // bytes, 0 for AEAD
    final int ivLen;           // bytes: 12 (GCM, ChaCha20) or 16 (CTR, OFB, CBC, CFB)
    private final byte[] configuredIv;

    CipherSuite(CryptoConfig c) throws GeneralSecurityException {
        String alg = c.algorithm;
        if (alg.equals("RC6")) ensureBouncyCastle();

        if (alg.equals("ChaCha20")) {
            kind = c.mode == null ? Kind.CHACHA20 : Kind.CHACHA20_POLY1305;
            transformation = c.mode == null ? "ChaCha20" : "ChaCha20-Poly1305";
        } else {
            kind = Kind.valueOf(c.mode);
            transformation = alg + "/" + c.mode + "/" + (kind == Kind.CBC ? c.padding : "NoPadding");
        }
        aead = c.isAead();
        keyAlgorithm = alg;
        macAlgorithm = c.macAlgorithm == null ? null : c.macAlgorithm.replace("HMAC-", "Hmac");
        encKeyLen = c.keyBits / 8;
        macKeyLen = c.macKeyBits / 8;
        ivLen = c.ivBits / 8;
        configuredIv = c.iv;

        // Fail at startup, not on the first connection, if this JVM lacks an algorithm
        Cipher.getInstance(transformation);
        if (macAlgorithm != null) Mac.getInstance(macAlgorithm);
    }

    Cipher newCipher() throws GeneralSecurityException {
        return Cipher.getInstance(transformation);
    }

    Mac newMac() throws GeneralSecurityException {
        return aead ? null : Mac.getInstance(macAlgorithm);
    }

    /** Only CBC and CFB need it: a raw block cipher used to turn the nonce into an unpredictable IV. */
    Cipher newIvCipher() throws GeneralSecurityException {
        return kind == Kind.CBC || kind == Kind.CFB ? Cipher.getInstance(keyAlgorithm + "/ECB/NoPadding") : null;
    }

    /** How many HKDF output bytes one direction needs: ENC_KEY | MAC_KEY | IV_BASE. */
    int keyMaterialLength() {
        return encKeyLen + macKeyLen + ivLen;
    }

    /** Cuts HKDF output into keys; a configured IV replaces the derived IV_BASE. */
    SessionKeys split(byte[] material) {
        SecretKeySpec enc = new SecretKeySpec(material, 0, encKeyLen, keyAlgorithm);
        SecretKeySpec mac = aead ? null : new SecretKeySpec(material, encKeyLen, macKeyLen, macAlgorithm);
        byte[] ivBase = configuredIv != null ? configuredIv.clone()
                : Arrays.copyOfRange(material, encKeyLen + macKeyLen, keyMaterialLength());
        return new SessionKeys(enc, mac, ivBase);
    }

    /**
     * The IV of one message: IV_BASE XOR (0 0 0 | TYPE | SEQ), as TLS 1.3 does with SEQ alone.
     * Every key belongs to one direction of one phase, and within a key each (TYPE, SEQ) pair is
     * used once, so within a connection no IV repeats under the same key even though the base IV is fixed
     * (a replayed HELLO is the exception for message 2: docs/PROTOCOL.md §4).
     */
    AlgorithmParameterSpec params(SessionKeys keys, int type, long seq, Cipher ivCipher) throws GeneralSecurityException {
        byte[] n = keys.ivBase().clone();
        n[3] ^= (byte) type;
        for (int i = 0; i < 8; i++) n[4 + i] ^= (byte) (seq >>> (56 - 8 * i));
        return switch (kind) {
            case GCM -> new GCMParameterSpec(TAG_LEN * 8, n);
            case CHACHA20_POLY1305 -> new IvParameterSpec(n);
            case CHACHA20 -> new ChaCha20ParameterSpec(n, 0);
            case CTR -> { // last 4 bytes: the block counter inside this message, always starting at 0
                Arrays.fill(n, 12, 16, (byte) 0);
                yield new IvParameterSpec(n);
            }
            case OFB -> new IvParameterSpec(n); // OFB only needs a unique IV, like CTR (NIST SP 800-38A, Appendix C)
            case CBC, CFB -> { // CBC and CFB need an unpredictable IV: encrypt the nonce (NIST SP 800-38A, Appendix C)
                ivCipher.init(Cipher.ENCRYPT_MODE, keys.encKey());
                yield new IvParameterSpec(ivCipher.doFinal(n));
            }
        };
    }

    @Override
    public String toString() {
        return transformation + (aead ? "" : " + " + macAlgorithm);
    }

    // RC6 is not in the JDK: load BouncyCastle by name so it is only needed when RC6 is configured
    private static void ensureBouncyCastle() throws NoSuchAlgorithmException {
        if (Security.getProvider("BC") != null) return;
        try {
            Security.addProvider((Provider) Class.forName("org.bouncycastle.jce.provider.BouncyCastleProvider")
                    .getDeclaredConstructor().newInstance());
        } catch (ReflectiveOperationException e) {
            throw new NoSuchAlgorithmException("RC6 needs BouncyCastle (lib/bcprov-jdk18on-1.86.jar) on the classpath");
        }
    }
}
