import java.io.DataInputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Man-in-the-middle relay for the attack tests (threat model: an attacker who controls the network
 * between the Secure Proxy and the Secure Stream Server, but does not know the pre-shared key).
 *
 *   browser/curl -> proxy -> MitmRelay (listen port) -> server
 *
 * It cuts the TCP stream into SSP messages (9-byte header, docs/PROTOCOL.md §2) and, in every
 * connection, attacks the n-th DATA message (type 4) sent by the server, or the HELLO sent by the proxy.
 * It knows no keys: it can only change, repeat, reorder, drop or cut the bytes it sees.
 *
 * Run it straight from the source (no javac needed), from the project root:
 *   java tests/MitmRelay.java <listen port> <server host> <server port> <attack> [n = 10]
 *
 * Attacks and the alert the proxy is expected to report:
 *   none          forwards everything unchanged (sanity check: the video must still play)
 *   tamper        flips one bit in the ciphertext of DATA #n        -> BAD_RECORD_MAC
 *   replay        sends DATA #n twice                                -> BAD_SEQUENCE
 *   reorder       swaps DATA #n and DATA #n+1                        -> BAD_SEQUENCE
 *   drop          deletes DATA #n                                    -> BAD_SEQUENCE
 *   truncate      closes the connection right after DATA #n          -> TRUNCATED_STREAM
 *   tamper-hello  flips one bit in the proxy's DH public key (HELLO) -> BAD_RECORD_MAC on the CHALLENGE (type 2)
 */
public class MitmRelay {

    static final int HEADER_LEN = 9;
    static final int HELLO = 1;
    static final int DATA = 4;
    static final int SEQ_LEN = 8; // DATA payload = SEQ | ciphertext | tag/MAC

    static String attack;
    static int n;
    static final AtomicInteger connections = new AtomicInteger();

    public static void main(String[] args) throws IOException {
        if (args.length < 4) {
            System.err.println("usage: java tests/MitmRelay.java <listen port> <server host> <server port>"
                    + " <none|tamper|replay|reorder|drop|truncate|tamper-hello> [n = 10]");
            System.exit(1);
        }
        int listenPort = Integer.parseInt(args[0]);
        String serverHost = args[1];
        int serverPort = Integer.parseInt(args[2]);
        attack = args[3];
        n = args.length > 4 ? Integer.parseInt(args[4]) : 10;
        if (!java.util.Set.of("none", "tamper", "replay", "reorder", "drop", "truncate", "tamper-hello").contains(attack)) {
            System.err.println("unknown attack " + attack);
            System.exit(1);
        }

        try (ServerSocket listener = new ServerSocket(listenPort)) {
            System.out.println("MITM relay on port " + listenPort + " -> " + serverHost + ":" + serverPort
                    + "  | attack: " + attack + (attack.equals("none") || attack.equals("tamper-hello") ? "" : " on DATA #" + n));
            while (true) {
                Socket proxy = listener.accept();
                int id = connections.incrementAndGet();
                new Thread(() -> relay(id, proxy, serverHost, serverPort)).start();
            }
        }
    }

    static void relay(int id, Socket proxy, String serverHost, int serverPort) {
        try (proxy; Socket server = new Socket(serverHost, serverPort)) {
            // proxy -> server in a second thread, server -> proxy in this one
            Thread up = new Thread(() -> proxyToServer(id, proxy, server));
            up.start();
            serverToProxy(id, server, proxy);
            up.join();
        } catch (IOException | InterruptedException e) {
            log(id, "connection error: " + e.getMessage());
        }
    }

    static void proxyToServer(int id, Socket proxy, Socket server) {
        try {
            InputStream in = proxy.getInputStream();
            OutputStream out = server.getOutputStream();
            byte[] m;
            while ((m = readMessage(in)) != null) {
                if (type(m) == HELLO && attack.equals("tamper-hello")) {
                    m[m.length - 1] ^= 0x01; // the DH public key is the last field of the HELLO
                    log(id, "HELLO: flipped 1 bit of the proxy's DH public key");
                }
                out.write(m);
                out.flush();
            }
        } catch (IOException ignored) {
            // the other side closed: nothing more to forward
        } finally {
            closeQuietly(server);
        }
    }

    static void serverToProxy(int id, Socket server, Socket proxy) {
        int dataSeen = 0;
        int forwarded = 0;
        byte[] held = null; // reorder: DATA #n waiting to be sent after DATA #n+1
        try {
            InputStream in = server.getInputStream();
            OutputStream out = proxy.getOutputStream();
            byte[] m;
            while ((m = readMessage(in)) != null) {
                if (type(m) != DATA) {
                    if (held != null) { out.write(held); held = null; } // short stream: send what was held
                    out.write(m);
                    out.flush();
                    continue;
                }
                dataSeen++;
                if (dataSeen == n) {
                    switch (attack) {
                        case "tamper" -> {
                            int i = HEADER_LEN + SEQ_LEN + 10; // inside the ciphertext, not the header or SEQ
                            m[i] ^= 0x01;
                            log(id, "DATA #" + n + ": flipped 1 bit of ciphertext byte " + i);
                        }
                        case "replay" -> {
                            out.write(m);
                            forwarded++;
                            log(id, "DATA #" + n + ": sent twice (replay)");
                        }
                        case "reorder" -> {
                            held = m;
                            log(id, "DATA #" + n + ": held back, will be sent after DATA #" + (n + 1));
                            continue;
                        }
                        case "drop" -> {
                            log(id, "DATA #" + n + ": dropped");
                            continue;
                        }
                        default -> { }
                    }
                }
                out.write(m);
                forwarded++;
                if (held != null) {
                    out.write(held);
                    forwarded++;
                    held = null;
                }
                out.flush();
                if (dataSeen == n && attack.equals("truncate")) {
                    log(id, "DATA #" + n + ": forwarded, then connection cut (no more DATA, no END)");
                    break;
                }
            }
        } catch (IOException ignored) {
            // the proxy closed after detecting the attack
        } finally {
            closeQuietly(proxy);
            closeQuietly(server);
            log(id, "closed: " + dataSeen + " DATA messages from the server, " + forwarded + " forwarded to the proxy");
        }
    }

    /** One whole SSP message (header + payload), or null at end of stream. */
    static byte[] readMessage(InputStream in) throws IOException {
        DataInputStream din = new DataInputStream(in);
        byte[] header = new byte[HEADER_LEN];
        try {
            din.readFully(header);
        } catch (EOFException e) {
            return null;
        }
        int length = ByteBuffer.wrap(header, 5, 4).getInt();
        if (length < 0 || length > 1 << 20) throw new IOException("not an SSP message (length " + length + ")");
        byte[] m = new byte[HEADER_LEN + length];
        System.arraycopy(header, 0, m, 0, HEADER_LEN);
        din.readFully(m, HEADER_LEN, length);
        return m;
    }

    static int type(byte[] m) {
        return m[4] & 0xff;
    }

    static void log(int id, String s) {
        System.out.println("[mitm] conn " + id + ": " + s);
    }

    static void closeQuietly(Socket s) {
        try {
            s.close();
        } catch (IOException ignored) {
        }
    }
}
