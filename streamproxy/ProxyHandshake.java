import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;

final class ProxyHandshake {
    private static final SecureRandom RANDOM = new SecureRandom();

    private final InputStream in;
    private final OutputStream out;
    private final CryptoConfig config;
    private final CipherSuite suite;

    private KeyExchange kex;
    private KeySchedule ks;
    private long seqX;
    private long seqZ;
    private byte[] msg1;
    private byte[] msg2;
    private byte[] msg3;
    private Payloads.Challenge challenge;
    private SecureChannel channel;
    private boolean alertSent;

    ProxyHandshake(InputStream in, OutputStream out, CryptoConfig config, CipherSuite suite) {
        this.in = in;
        this.out = out;
        this.config = config;
        this.suite = suite;
    }

    Payloads.StreamInfo run(String media, long rangeStart, long rangeEnd)
            throws IOException, ProtocolAlert, GeneralSecurityException {
        sendHello();
        receiveChallenge();
        sendResponse(media, rangeStart, rangeEnd);
        deriveStreamKeys();
        return receiveStreamInfo();
    }

    SecureChannel channel() {
        return channel;
    }

    long firstDataSeq() {
        return seqZ + 1;
    }

    private void sendHello() throws IOException, GeneralSecurityException {
        kex = KeyExchange.generate(config.keyExchange);
        seqX = RANDOM.nextLong() >>> 2;
        Payloads.Hello hello = config.hello(seqX, kex.publicKey());
        msg1 = SSPMessage.encode(SSPMessage.HELLO, hello.encode());
        out.write(msg1);
        out.flush();
    }

    private void receiveChallenge() throws IOException, ProtocolAlert, GeneralSecurityException {
        SSPMessage m2 = SSPMessage.read(in);

        if (m2.type == SSPMessage.ALERT) throw ProtocolAlert.fromPeer(Payloads.alertCode(m2.payload), false);
        if (m2.type != SSPMessage.CHALLENGE) throw new ProtocolAlert(ProtocolAlert.UNEXPECTED_MESSAGE, "expected CHALLENGE, got type " + m2.type);

        ks = new KeySchedule(config.hashAlgorithm, config.psk());
        byte[] th1 = ks.hash(msg1);
        SessionKeys keys = ks.keys(suite, "hs s2p", th1);
        SecureChannel canal = new SecureChannel(suite, null, keys);

        byte[] plaintext = canal.open(m2, seqX + 1);

        Payloads.Challenge c = Payloads.Challenge.decode(plaintext);
        if (c.seqY() != seqX + 1) throw new ProtocolAlert(ProtocolAlert.BAD_SEQUENCE, "SEQY != SEQX+1");
        if (!c.ccc().equals(config.pcc())) throw new ProtocolAlert(ProtocolAlert.INCOMPATIBLE_SUITE, "CCC != PCC");

        msg2 = m2.bytes();
        challenge = c;
    }

    private void sendResponse(String media, long rangeStart, long rangeEnd) throws IOException, ProtocolAlert, GeneralSecurityException {
        byte[] secretDH = kex.agree(challenge.dhPub());
        ks.mixDiffieHellman(secretDH);
        byte[] th2 = ks.hash(msg1, msg2);
        SessionKeys keys = ks.keys(suite, "hs p2s", th2);
        SecureChannel canal = new SecureChannel(suite, keys, null);

        seqZ = seqX + 2;
        byte[] r = ks.hash(challenge.srv());

        Payloads.Response response = new Payloads.Response(seqZ, r, media, rangeStart, rangeEnd);
        msg3 = canal.seal(SSPMessage.RESPONSE, seqZ, response.encode());
        out.write(msg3);
        out.flush();
    }

    private void deriveStreamKeys() throws GeneralSecurityException {
        byte[] th3 = ks.hash(msg1, msg2, msg3);
        SessionKeys sendKeys = ks.keys(suite, "app p2s", th3);
        SessionKeys recvKeys = ks.keys(suite, "app s2p", th3);
        channel = new SecureChannel(suite, sendKeys, recvKeys);
    }

    private Payloads.StreamInfo receiveStreamInfo() throws IOException, ProtocolAlert {
        SSPMessage m6 = SSPMessage.read(in);

        if (m6.type == SSPMessage.ALERT) throw peerAlert(m6, seqZ + 1);
        if (m6.type != SSPMessage.STREAM_INFO) throw new ProtocolAlert(ProtocolAlert.UNEXPECTED_MESSAGE, "expected STREAM_INFO, got type " + m6.type);

        byte[] plaintext = channel.open(m6, seqZ + 1);
        return Payloads.StreamInfo.decode(plaintext);
    }

    ProtocolAlert peerAlert(SSPMessage alert, long expectedSeq) {
        if (channel != null) {
            try {
                return ProtocolAlert.fromPeer(Payloads.alertCode(channel.open(alert, expectedSeq)), true);
            } catch (ProtocolAlert notAuthenticated) {
            }
        }
        if (alert.payload.length == 1) return ProtocolAlert.fromPeer(alert.payload[0] & 0xff, false);
        return new ProtocolAlert(ProtocolAlert.DECODE_ERROR, "unreadable ALERT from peer");
    }

    void sendAlert(int code) {
        if (alertSent) return;
        alertSent = true;
        try {
            byte[] alert = channel != null
                    ? channel.seal(SSPMessage.ALERT, seqZ + 1, Payloads.alert(code))
                    : SSPMessage.encode(SSPMessage.ALERT, Payloads.alert(code));
            out.write(alert);
            out.flush();
        } catch (IOException | GeneralSecurityException ignored) {
        }
    }
}
