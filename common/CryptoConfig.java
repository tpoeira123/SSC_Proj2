import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import javax.xml.parsers.DocumentBuilderFactory;
import java.nio.file.Path;
import java.util.Base64;
import java.util.HexFormat;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * Cryptographic configuration read from proxycrypto.config / servercrypto.config, in the format
 * of the assignment (§2.2.2) plus two additions, <KeyExchange> and <HashSuite>
 * (docs/PROTOCOL.md §6). Nothing cryptographic is hard-coded in the programs: algorithms, sizes,
 * IV and pre-shared keys all come from this file. Tag names are matched ignoring case, because
 * the assignment itself writes both <MACsuite> and </MACSuite>. Unsafe or inconsistent
 * combinations are rejected when the file is loaded, so a bad config never reaches the network.
 */
final class CryptoConfig {

    // Both spellings used in the assignment (HMAC-SHA256 and HMAC-SHA-512) map to one canonical name
    private static final Map<String, String> MACS = Map.of(
            "HMAC-SHA256", "HMAC-SHA256", "HMAC-SHA-256", "HMAC-SHA256",
            "HMAC-SHA384", "HMAC-SHA384", "HMAC-SHA-384", "HMAC-SHA384",
            "HMAC-SHA512", "HMAC-SHA512", "HMAC-SHA-512", "HMAC-SHA512");
    private static final Set<String> KEY_EXCHANGES = Set.of("X25519", "X448", "DH-3072");
    private static final Set<String> HASHES = Set.of("SHA-256", "SHA-384", "SHA-512");

    final String algorithm;     // AES | ChaCha20 | RC6
    final String mode;          // GCM | Poly1305 | CBC | CTR | OFB | CFB | null (plain ChaCha20)
    final int ivBits;
    final byte[] iv;            // configured IV, or null to derive it with HKDF
    final String padding;       // PKCS5Padding | null
    final String macAlgorithm;  // HMAC-SHA256 | HMAC-SHA384 | HMAC-SHA512 | null (AEAD)
    final String keyExchange;   // X25519 | X448 | DH-3072
    final String hashAlgorithm; // SHA-256 | SHA-384 | SHA-512: HKDF, transcript hashes and R
    final int keyBits;
    final int macKeyBits;       // 0 when there is no MAC
    private final byte[] psk;   // SKey || MacKey: only ever used inside HKDF, never to encrypt directly

    private CryptoConfig(Element root) {
        Element sym = child(root, "SymCipherSuite");
        Element ivElement = child(sym, "InitializationVector");
        Element keys = child(root, "ConfiguredKeys");
        Element symKey = child(keys, "SymmetricKey");
        Element macKey = child(keys, "MACKey");

        algorithm = canonical(text(sym, "Algorithm"));
        mode = nullable(text(sym, "Mode"));
        padding = nullable(text(sym, "Padding"));
        String mac = nullable(text(child(root, "MACsuite"), "Algorithm"));
        macAlgorithm = mac == null ? null : MACS.get(mac.toUpperCase(Locale.ROOT));
        keyExchange = text(child(root, "KeyExchange"), "Algorithm");
        hashAlgorithm = text(child(root, "HashSuite"), "Algorithm").toUpperCase(Locale.ROOT);
        keyBits = number(text(symKey, "Keysize"), "Keysize");
        String macKeySize = nullable(text(macKey, "MacKeySize"));
        macKeyBits = macKeySize == null ? 0 : number(macKeySize, "MacKeySize");

        boolean aead = isAead();
        int defaultIvBits = aead || algorithm.equals("ChaCha20") ? 96 : 128;
        String ivSize = nullable(text(ivElement, "IVSize"));
        ivBits = ivSize == null ? defaultIvBits : number(ivSize, "IVSize");
        String ivText = nullable(text(ivElement, "IV"));
        iv = ivText == null ? null : decode(ivText, "IV");

        byte[] sKey = decode(text(symKey, "SKey"), "SKey");
        String mKeyText = nullable(text(macKey, "MacKey"));
        byte[] mKey = mKeyText == null ? new byte[0] : decode(mKeyText, "MacKey");
        psk = SSPMessage.concat(sKey, mKey);

        // ---- validation: everything that could make the channel weak or the peers disagree ----
        switch (algorithm) {
            case "AES" -> require(Set.of("GCM", "CBC", "CTR", "OFB", "CFB").contains(String.valueOf(mode)),
                    "AES mode must be GCM, CBC, CTR, OFB or CFB");
            case "ChaCha20" -> require(mode == null || mode.equals("Poly1305"), "ChaCha20 mode must be Poly1305 or NULL");
            case "RC6" -> require(Set.of("CBC", "CTR", "OFB", "CFB").contains(String.valueOf(mode)),
                    "RC6 mode must be CBC, CTR, OFB or CFB");
            default -> throw new IllegalStateException();
        }
        require(ivBits == defaultIvBits, "IVSize must be " + defaultIvBits + " (or NULL) for " + algorithm + "/" + orNull(mode));
        require(iv == null || iv.length * 8 == ivBits, "IV has " + (iv == null ? 0 : iv.length * 8) + " bits but IVSize is " + ivBits);
        require("CBC".equals(mode) == "PKCS5Padding".equals(padding),
                "Padding must be PKCS5Padding with CBC and NULL otherwise");
        if (aead) {
            require(mac == null && macKeyBits == 0, "AEAD modes (GCM, Poly1305) authenticate already: MAC must be NULL");
        } else {
            require(macAlgorithm != null, "non-AEAD modes need a MAC: HMAC-SHA256, HMAC-SHA384 or HMAC-SHA512");
            require(macKeyBits >= 128 && macKeyBits % 8 == 0, "MacKeySize must be at least 128 bits");
        }
        require(Set.of(128, 192, 256).contains(keyBits), "Keysize must be 128, 192 or 256");
        require(!algorithm.equals("ChaCha20") || keyBits == 256, "ChaCha20 needs a 256-bit key");
        require(sKey.length * 8 == keyBits, "SKey has " + sKey.length * 8 + " bits but Keysize is " + keyBits);
        require(mKey.length == 0 || mKey.length * 8 == macKeyBits, "MacKey length does not match MacKeySize");
        require(KEY_EXCHANGES.contains(keyExchange), "KeyExchange must be one of " + KEY_EXCHANGES);
        require(HASHES.contains(hashAlgorithm), "HashSuite must be one of " + HASHES);
    }

    /** Loads and validates a config file; IllegalArgumentException explains what is wrong. */
    static CryptoConfig load(Path file) {
        try {
            DocumentBuilderFactory f = DocumentBuilderFactory.newInstance();
            // No DTDs at all: rules out XXE / entity-expansion attacks through the config file
            f.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            f.setXIncludeAware(false);
            f.setExpandEntityReferences(false);
            return new CryptoConfig(f.newDocumentBuilder().parse(file.toFile()).getDocumentElement());
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException(file + ": " + e.getMessage(), e);
        } catch (Exception e) {
            throw new IllegalArgumentException(file + ": cannot read config (" + e.getMessage() + ")", e);
        }
    }

    boolean isAead() {
        return "GCM".equals(mode) || "Poly1305".equals(mode);
    }

    /** PCC / CCC of messages 1 and 2, as in the assignment: ALG/MODE/IV/Padding (IV in hex or NULL). */
    String pcc() {
        return algorithm + "/" + orNull(mode) + "/" + (iv == null ? "NULL" : HexFormat.of().formatHex(iv))
                + "/" + orNull(padding);
    }

    byte[] psk() {
        return psk.clone();
    }

    Payloads.Hello hello(long seqX, byte[] dhPub) {
        return new Payloads.Hello(seqX, pcc(), orNull(macAlgorithm), keyExchange, hashAlgorithm,
                keyBits, macKeyBits, dhPub);
    }

    /** Server-side check of a HELLO: every proposed parameter must equal this config. */
    boolean accepts(Payloads.Hello h) {
        return h.pcc().equals(pcc()) && h.macAlg().equals(orNull(macAlgorithm)) && h.kexAlg().equals(keyExchange)
                && h.hashAlg().equals(hashAlgorithm) && h.keyBits() == keyBits && h.macKeyBits() == macKeyBits;
    }

    @Override
    public String toString() {
        return pcc() + " | MAC " + orNull(macAlgorithm) + " | " + keyExchange + " | " + hashAlgorithm
                + " | key " + keyBits + " bits";
    }

    // ---- XML helpers ----

    private static Element child(Element parent, String name) {
        NodeList nodes = parent.getChildNodes();
        for (int i = 0; i < nodes.getLength(); i++) {
            Node n = nodes.item(i);
            if (n instanceof Element e && e.getTagName().equalsIgnoreCase(name)) return e;
        }
        throw new IllegalArgumentException("missing <" + name + "> inside <" + parent.getTagName() + ">");
    }

    private static String text(Element parent, String name) {
        String t = child(parent, name).getTextContent().trim();
        if (t.isEmpty()) throw new IllegalArgumentException("<" + name + "> is empty (write NULL if unused)");
        return t;
    }

    private static String nullable(String s) {
        return s.equalsIgnoreCase("NULL") ? null : s;
    }

    private static String orNull(String s) {
        return s == null ? "NULL" : s;
    }

    private static String canonical(String value) {
        for (String a : new String[]{"AES", "ChaCha20", "RC6"})
            if (a.equalsIgnoreCase(value))
                return a;
        throw new IllegalArgumentException("unsupported algorithm " + value);
    }

    private static int number(String s, String field) {
        try {
            return Integer.parseInt(s);
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException(field + " is not a number: " + s);
        }
    }

    /** Key or IV material in hexadecimal or Base64, as the assignment allows both. */
    private static byte[] decode(String s, String field) {
        try {
            if (s.matches("[0-9a-fA-F]+")) {
                if (s.length() % 2 != 0) throw new IllegalArgumentException(field + " has an odd number of hex digits (" + s.length() + ")");
                return HexFormat.of().parseHex(s);
            }
            return Base64.getDecoder().decode(s);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException(e.getMessage().startsWith(field) ? e.getMessage()
                    : field + " is neither hexadecimal nor Base64");
        }
    }

    private static void require(boolean condition, String message) {
        if (!condition) throw new IllegalArgumentException(message);
    }
}
