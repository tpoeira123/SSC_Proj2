import javax.crypto.SecretKey;

/**
 * Keys for one direction of one phase, cut from an HKDF output: ENC_KEY | MAC_KEY (null for
 * AEAD) | IV_BASE (the configured IV if there is one). See docs/PROTOCOL.md §4.
 */
record SessionKeys(SecretKey encKey, SecretKey macKey, byte[] ivBase) {}
