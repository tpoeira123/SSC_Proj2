import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;

/**
 * Server side of the SSP handshake, the mirror of ProxyHandshake (docs/PROTOCOL.md §3-§4):
 *
 *   recv [1] HELLO     clear: SEQX, proposal, DH_pub_P        -> must equal our config
 *   send [2] CHALLENGE hs s2p (PSK only, TH1): SEQX+1, SRV, CCC, DH_pub_S
 *   recv [3] RESPONSE  hs p2s (PSK + DH, TH2): SEQX+2, R = H(SRV), MEDIA, RANGE
 *   then stream keys from TH3: the server sends with "app s2p" and receives with "app p2s"
 *
 * Only a proxy holding the same pre-shared key can decrypt message 2 and produce a valid message 3,
 * and any change to the messages gives different keys on each side, so the next tag fails. Any
 * failure throws ProtocolAlert; the caller answers it with sendAlert.
 */
final class ServerHandshake {
    private static final SecureRandom RANDOM = new SecureRandom();

    private final InputStream in;        // from the proxy
    private final OutputStream out;      // to the proxy
    private final CryptoConfig config;   // servercrypto.config: what we accept, and the PSK
    private final CipherSuite suite;     // the config as JCA objects (cipher, MAC, key and IV sizes)

    private Payloads.Hello hello;        // message 1 decoded: the proxy's proposal and DH public key
    private KeyExchange kex;             // our ephemeral DH key pair, new for every connection
    private KeySchedule ks;              // HKDF state: PSK only after message 1, PSK + DH after message 2
    private long seqX;                   // the proxy's random first SEQ; 2 = SEQX+1, 3 = SEQX+2, stream from SEQX+3
    private byte[] srv;                  // our 256-bit random challenge; the proxy must answer R = H(SRV)
    private byte[] msg1;                 // exact wire bytes of message 1 (header included), for TH1/TH2/TH3
    private byte[] msg2;                 // exact wire bytes of message 2 as we sent it, for TH2/TH3
    private SecureChannel channel;       // app keys after a valid message 3; null before (alerts go in clear)
    private boolean alertSent;           // at most one ALERT per connection

    ServerHandshake(InputStream in, OutputStream out, CryptoConfig config, CipherSuite suite) {
        this.in = in;
        this.out = out;
        this.config = config;
        this.suite = suite;
    }

    /** Runs the handshake and returns what the proxy asked for (media name and byte range). */
    Payloads.Response run() throws IOException, ProtocolAlert, GeneralSecurityException {
        receiveHello();
        sendChallenge();
        return receiveResponse();
    }

    SecureChannel channel() {
        return channel;
    }

    /** SEQ of STREAM_INFO: SEQZ + 1. */
    long streamInfoSeq() {
        return seqX + 3;
    }

    /** SEQ of the first DATA block: SEQZ + 1, as ProxyHandshake.firstDataSeq() (other type, so another IV). */
    long firstDataSeq() {
        return seqX + 3;
    }

    private void receiveHello() throws IOException, ProtocolAlert {
        SSPMessage message = SSPMessage.read(in);
        if(message.type == SSPMessage.ALERT) {
            throw ProtocolAlert.fromPeer(Payloads.alertCode(message.payload), false);
        }
        if(message.type != SSPMessage.HELLO) {
            throw new ProtocolAlert(ProtocolAlert.UNEXPECTED_MESSAGE, "Expected HELLO, got type " + message.type);
        }
        this.hello = Payloads.Hello.decode(message.payload); // decode and validate (DECODE_ERROR if malformed)

        // The proxy keeps the 2 top bits at 0, so SEQX + n can never overflow
        if((hello.seqX() >>> 62) != 0) {
            throw new ProtocolAlert(ProtocolAlert.DECODE_ERROR, "SEQX must be 62 bits, got " + hello.seqX());
        }
        // The proposal must be exactly our configuration (also stops downgrade attacks)
        if(!config.accepts(hello)) {
            // Whole proposal, not just the PCC: the difference may be in the MAC, key exchange, hash or key sizes
            throw new ProtocolAlert(ProtocolAlert.INCOMPATIBLE_SUITE, "proxy proposed " + hello.pcc()
                    + " | MAC " + hello.macAlg() + " | " + hello.kexAlg() + " | " + hello.hashAlg()
                    + " | key " + hello.keyBits() + " bits, but this server uses " + config);
        }

        this.msg1 = message.bytes(); // store the exact wire bytes of message 1 for later transcript hash calculations
        this.seqX = hello.seqX();
    }

    private void sendChallenge() throws IOException, GeneralSecurityException {
        this.kex = KeyExchange.generate(config.keyExchange); // generate ephemeral DH key pair
        this.srv = new byte[Payloads.SRV_LEN];
        RANDOM.nextBytes(srv);  // 256-bit random challenge

        this.ks = new KeySchedule(config.hashAlgorithm, config.psk()); //  start the key schedule with the PSK only
        byte[] th1 = ks.hash(msg1); // transcript hash of message 1
        SessionKeys keys = ks.keys(suite, "hs s2p", th1);   // derive the keys for message 2 (server to proxy) using the transcript hash of message 1

        Payloads.Challenge challenge = new Payloads.Challenge(seqX + 1, srv, config.pcc(), kex.publicKey()); // create the challenge payload

        // Local channel, send keys only: this.channel stays null until message 3 is verified
        SecureChannel canal = new SecureChannel(suite, keys, null);

        // seal returns the whole protected message (header | ciphertext | tag): that is what we send,
        // and its exact bytes are msg2 for TH2/TH3
        this.msg2 = canal.seal(SSPMessage.CHALLENGE, seqX + 1, challenge.encode());
        out.write(this.msg2);
        out.flush();
    }

    private Payloads.Response receiveResponse() throws IOException, ProtocolAlert, GeneralSecurityException {
        SSPMessage m3 = SSPMessage.read(in);
        if(m3.type == SSPMessage.ALERT) {
            throw ProtocolAlert.fromPeer(Payloads.alertCode(m3.payload), false);
        }
        if(m3.type != SSPMessage.RESPONSE) {
            throw new ProtocolAlert(ProtocolAlert.UNEXPECTED_MESSAGE, "Expected RESPONSE, got type " + m3.type);
        }

        byte[] secretDH = kex.agree(hello.dhPub()); // our private DH key with the proxy's public key from message 1
        this.ks.mixDiffieHellman(secretDH); // mix the DH secret into the key schedule

        byte[] th2 = this.ks.hash(msg1, msg2); // transcript hash of messages 1 and 2
        SessionKeys keys = this.ks.keys(suite, "hs p2s", th2); // derive the keys for message 3 (proxy to server) using the transcript hash of messages 1 and 2

        SecureChannel canal = new SecureChannel(suite, null, keys); // receive keys only: open() uses the 3rd argument
        byte[] plainText = canal.open(m3, this.seqX + 2); // decrypt and verify the message 3 using the derived keys and the expected SEQ (SEQX + 2)

        Payloads.Response response = Payloads.Response.decode(plainText); // decode and validate the response payload (DECODE_ERROR if malformed)
        if (response.seqZ() != this.seqX + 2) {
            throw new ProtocolAlert(ProtocolAlert.BAD_SEQUENCE, "SEQZ != SEQX+2");
        }
        if (!MessageDigest.isEqual(response.r(), this.ks.hash(this.srv))) {
            throw new ProtocolAlert(ProtocolAlert.CHALLENGE_FAILED, "R != H(SRV)");
        }

        byte[] th3 = this.ks.hash(msg1, msg2, m3.bytes()); // transcript hash of messages 1, 2, and 3
        this.channel = new SecureChannel(suite, this.ks.keys(suite, "app s2p", th3), this.ks.keys(suite, "app p2s", th3)); // derive the app keys for the stream and create a secure channel with them

        return response;
    }

    /**
     * Sends one ALERT and never another. Before message 3 is verified there are no shared keys,
     * so it goes in clear; after, it is sealed with the app keys at seq, the SEQ the proxy expects
     * next (streamInfoSeq() if STREAM_INFO was not sent yet).
     */
    void sendAlert(int code, long seq) {
        if(this.alertSent) {
            return; // only one ALERT per connection
        }
        this.alertSent = true;
        try {
            // Shared keys only exist after a verified message 3: sealed then, in clear before
            byte[] alert = this.channel != null
                    ? this.channel.seal(SSPMessage.ALERT, seq, Payloads.alert(code))
                    : SSPMessage.encode(SSPMessage.ALERT, Payloads.alert(code));
            out.write(alert);
            out.flush();
        } catch(IOException | GeneralSecurityException ignored) {
            // We are failing and closing anyway: if the proxy is gone, there is nothing more to do
        }
    }
}
