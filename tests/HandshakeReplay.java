import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.util.Arrays;

/**
 * Replays a recorded handshake to the server (threat model: an attacker on the network who does not
 * know the pre-shared key).
 *
 *   curl -> proxy -> HandshakeReplay (listen port) -> server
 *
 * It relays one connection, recording messages 1, 2 and 3, and when it ends it opens new connections
 * to the server with the recorded bytes:
 *   HELLO twice     the server answers each one with a CHALLENGE. In modes that use a keystream, the
 *                   first ciphertext bytes (the encrypted SEQY) repeat: the known limitation of
 *                   message 2, docs/PROTOCOL.md §4. In CBC the first block also holds random bytes,
 *                   so nothing repeats on the wire.
 *   old RESPONSE    must be rejected with BAD_RECORD_MAC: a new handshake has new DH keys.
 *
 * Run it straight from the source (no javac needed), from the project root, then make one request:
 *   java tests/HandshakeReplay.java <listen port> <server host> <server port>
 */
public class HandshakeReplay {

    static final int HEADER_LEN = 9;
    static final int CHALLENGE = 2;
    static final int ALERT = 255;
    static final int BAD_RECORD_MAC = 5;
    static final int SEQ_LEN = 8;

    public static void main(String[] args) throws Exception {
        if (args.length != 3) {
            System.err.println("usage: java tests/HandshakeReplay.java <listen port> <server host> <server port>");
            System.exit(1);
        }
        int listenPort = Integer.parseInt(args[0]);
        String host = args[1];
        int port = Integer.parseInt(args[2]);

        byte[] hello;
        byte[] challenge;
        byte[] response;
        try (ServerSocket listener = new ServerSocket(listenPort)) {
            System.out.println("Replay relay on port " + listenPort + " -> " + host + ":" + port + ". Waiting for one request...");
            try (Socket proxy = listener.accept(); Socket server = new Socket(host, port)) {
                hello = forwardOne(proxy, server);
                challenge = forwardOne(server, proxy);
                response = forwardOne(proxy, server);
                Thread up = pump(proxy, server);
                Thread down = pump(server, proxy);
                up.join();
                down.join();
            }
        }
        System.out.println("Recorded one handshake. Replaying it to the server, with no keys:");

        byte[] replyA = helloReply(host, port, hello);
        byte[] replyB = helloReply(host, port, hello);
        boolean challenged = replyA != null && replyB != null && type(replyA) == CHALLENGE && type(replyB) == CHALLENGE;
        if (challenged) {
            int prefix = commonPrefix(replyA, replyB);
            System.out.println("  HELLO replayed twice: the server answered with 2 new CHALLENGEs, "
                    + prefix + " equal ciphertext bytes at the start ("
                    + (prefix >= SEQ_LEN ? "key and nonce reused: known limitation" : "not visible in this mode") + ")");
        } else {
            System.out.println("  HELLO replayed twice: FAILED, the server did not answer with a CHALLENGE");
        }

        boolean rejected = oldResponseRejected(host, port, hello, response);
        System.out.println("  Old RESPONSE on a new connection: "
                + (rejected ? "rejected with BAD_RECORD_MAC" : "FAILED, not rejected with BAD_RECORD_MAC"));

        boolean ok = challenged && rejected;
        System.out.println(ok ? "RESULT: OK" : "RESULT: FAILED");
        if (!ok) System.exit(1);
    }

    /** Reads one whole SSP message (header + payload), or returns null at end of stream. */
    static byte[] readMessage(InputStream in) throws IOException {
        DataInputStream data = new DataInputStream(in);
        byte[] header = new byte[HEADER_LEN];
        try {
            data.readFully(header);
            int length = ByteBuffer.wrap(header, 5, 4).getInt();
            if (length < 0 || length > 16384) throw new IOException("bad length " + length);
            byte[] message = Arrays.copyOf(header, HEADER_LEN + length);
            data.readFully(message, HEADER_LEN, length);
            return message;
        } catch (java.io.EOFException e) {
            return null;
        }
    }

    static byte[] forwardOne(Socket from, Socket to) throws IOException {
        byte[] message = readMessage(from.getInputStream());
        if (message == null) throw new IOException("connection closed during the handshake");
        to.getOutputStream().write(message);
        return message;
    }

    static Thread pump(Socket from, Socket to) {
        Thread t = new Thread(() -> {
            try {
                from.getInputStream().transferTo(to.getOutputStream());
            } catch (IOException ignored) {
                // A peer closed the connection: the other direction ends too
            }
            try {
                to.shutdownOutput();
            } catch (IOException ignored) {
            }
        });
        t.start();
        return t;
    }

    static byte[] helloReply(String host, int port, byte[] hello) throws IOException {
        try (Socket s = new Socket(host, port)) {
            OutputStream out = s.getOutputStream();
            out.write(hello);
            return readMessage(s.getInputStream());
        }
    }

    static boolean oldResponseRejected(String host, int port, byte[] hello, byte[] response) throws IOException {
        try (Socket s = new Socket(host, port)) {
            s.setSoTimeout(5000);
            OutputStream out = s.getOutputStream();
            out.write(hello);
            if (readMessage(s.getInputStream()) == null) return false;
            out.write(response);
            byte[] answer = readMessage(s.getInputStream());
            return answer != null && type(answer) == ALERT && answer.length == HEADER_LEN + 1
                    && (answer[HEADER_LEN] & 0xff) == BAD_RECORD_MAC;
        }
    }

    static int type(byte[] message) {
        return message[4] & 0xff;
    }

    /** Equal bytes at the start of two payloads (the header is skipped). */
    static int commonPrefix(byte[] a, byte[] b) {
        int i = 0;
        while (HEADER_LEN + i < a.length && HEADER_LEN + i < b.length && a[HEADER_LEN + i] == b[HEADER_LEN + i]) i++;
        return i;
    }
}
