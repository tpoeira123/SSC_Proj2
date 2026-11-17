import javax.crypto.KeyAgreement;
import javax.crypto.interfaces.DHPublicKey;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;

/**
 * One ephemeral Diffie-Hellman key pair for one session (X25519, X448 or DH-3072, chosen in the
 * config). Public keys travel in X.509 encoding. A fresh pair per connection, discarded at the
 * end, is what gives forward secrecy (docs/PROTOCOL.md §4).
 */
final class KeyExchange {

    private final String jcaAlgorithm;
    private final KeyPair keyPair;

    private KeyExchange(String jcaAlgorithm, KeyPair keyPair) {
        this.jcaAlgorithm = jcaAlgorithm;
        this.keyPair = keyPair;
    }

    static KeyExchange generate(String configAlgorithm) throws GeneralSecurityException {
        KeyPairGenerator g;
        if (configAlgorithm.equals("DH-3072")) {
            g = KeyPairGenerator.getInstance("DH");
            g.initialize(3072); // the JDK's predefined 3072-bit safe-prime group, identical on both peers
        } else {
            g = KeyPairGenerator.getInstance(configAlgorithm); // X25519 | X448
        }
        return new KeyExchange(g.getAlgorithm(), g.generateKeyPair());
    }

    byte[] publicKey() {
        return keyPair.getPublic().getEncoded();
    }

    /** Computes the shared secret with the peer's encoded public key; a bad key is a DECODE_ERROR. */
    byte[] agree(byte[] peerPublicKey) throws ProtocolAlert {
        try {
            PublicKey peer = KeyFactory.getInstance(jcaAlgorithm).generatePublic(new X509EncodedKeySpec(peerPublicKey));
            if (peer instanceof DHPublicKey p && keyPair.getPublic() instanceof DHPublicKey mine
                    && !(p.getParams().getP().equals(mine.getParams().getP())
                    && p.getParams().getG().equals(mine.getParams().getG()))) {
                throw new ProtocolAlert(ProtocolAlert.DECODE_ERROR, "peer uses a different DH group");
            }
            KeyAgreement ka = KeyAgreement.getInstance(jcaAlgorithm);
            ka.init(keyPair.getPrivate());
            ka.doPhase(peer, true);
            return ka.generateSecret();
        } catch (GeneralSecurityException e) { // malformed key, wrong algorithm, or a small-order point
            throw new ProtocolAlert(ProtocolAlert.DECODE_ERROR, "invalid DH public key (" + e.getMessage() + ")");
        }
    }
}
