import java.io.BufferedOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.RandomAccessFile;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.InvalidPathException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.concurrent.Executors;

/**
 * Secure Stream Server, with raw sockets only (java.net.ServerSocket / Socket) and no external
 * libraries. Each connection carries one request of the Secure Streaming Protocol
 * (docs/PROTOCOL.md):
 *
 *   handshake (ServerHandshake)  -> media name and byte range the proxy asked for
 *   STREAM_INFO (type 6)         -> status (200/206/404/416), file size and range
 *   DATA (type 4) x N            -> the file bytes, 1 to 1024 per block, each one encrypted
 *   END (type 5)                 -> totals, so the proxy can tell a complete stream from a cut one
 *
 * The cryptography comes only from the config file. Files are served from mediaDir only.
 *
 * Usage: java OriginSocketServer [port=8081] [mediaDir=media] [configPath=servercrypto.config]
 */
public class OriginSocketServer {

    static final int BLOCK_SIZE = 1024;

    private static final String[] STATUS_NAMES = {"OK", "PARTIAL", "NOT_FOUND", "RANGE_NOT_SATISFIABLE"};

    public static void main(String[] args) throws Exception {
        int port = args.length > 0 ? Integer.parseInt(args[0]) : 8081;
        Path root = Paths.get(args.length > 1 ? args[1] : "media").toAbsolutePath().normalize();
        String configPath = args.length > 2 ? args[2] : "servercrypto.config";

        CipherSuite suite;
        CryptoConfig config;
        try {
            config = CryptoConfig.load(Path.of(configPath));
            suite = new CipherSuite(config);
        } catch (IllegalArgumentException | GeneralSecurityException e) {
            System.err.println("Invalid crypto config: " + e.getMessage());
            System.exit(1);
            return;
        }

        try (ServerSocket server = new ServerSocket(port)) {
            System.out.println("Secure stream server on port " + port + "  (media dir: " + root + ")");
            System.out.println("Crypto config " + configPath + ": " + config + "  (" + suite + ")");

            var pool = Executors.newCachedThreadPool();
            while (true) {
                Socket client = server.accept();
                pool.submit(() -> handle(client, root, config, suite));
            }
        }
    }

    static void handle(Socket socket, Path root, CryptoConfig config, CipherSuite suite) {
        try (socket) {
            socket.setSoTimeout(10_000);

            var in = socket.getInputStream();
            // Buffered: many small writes leave as a few large packets; we flush only at the end of each phase
            var out = new BufferedOutputStream(socket.getOutputStream());

            // Declared before the try so the catch blocks can send an alert
            ServerHandshake hs = new ServerHandshake(in, out, config, suite);
            try {
                Payloads.Response req = hs.run();
                System.out.println("Request: " + req.media() + "  range " + req.rangeStart() + ".." + req.rangeEnd());

                Path file = resolveMediaFile(root, req.media()); // null -> NOT_FOUND below
                Payloads.StreamInfo info = streamInfo(file, req.rangeStart(), req.rangeEnd());

                // STREAM_INFO first: the proxy needs status, size and range to answer the browser
                out.write(hs.channel().seal(SSPMessage.STREAM_INFO, hs.streamInfoSeq(), info.encode()));
                out.flush();
                System.out.println("  " + STATUS_NAMES[info.status()]
                        + (info.hasBody() ? " bytes " + info.start() + "-" + info.end() + " of " + info.fileSize() : ""));
                if (!info.hasBody()) return; // 404 / 416: nothing more to send

                long blocks = sendBlocks(out, hs.channel(), file, info, hs.firstDataSeq());
                System.out.println("  sent " + info.length() + " bytes in " + blocks + " blocks + END");
            } catch (ProtocolAlert e) {
                if (e.fromPeer) {
                    System.out.println("Connection closed by the proxy: " + e.getMessage());
                } else {
                    System.out.println("Connection rejected, ALERT sent: " + e.getMessage());
                    hs.sendAlert(e.code, hs.streamInfoSeq()); // never answer an alert with an alert
                }
            } catch (GeneralSecurityException e) {
                System.out.println("  crypto error: " + e);
                hs.sendAlert(ProtocolAlert.INTERNAL_ERROR, hs.streamInfoSeq());
            }
        } catch (IOException e) {
            // The proxy disconnected or timed out: normal on seek/close, nothing to send.
        }
    }

    /**
     * The file the proxy asked for, or null if the name is not allowed or the file does not exist.
     * No URL decoding here: the proxy already decoded it
     */
    private static Path resolveMediaFile(Path root, String media) {
        // a plain file name only, nothing that can climb or change directory
        if (media.isEmpty() || media.contains("/") || media.contains("\\") || media.contains(".."))
            return null;
        Path file;
        try {
            file = root.resolve(media).normalize();
        } catch (InvalidPathException e) { // characters the OS does not allow, e.g. ':' on Windows
            return null;
        }
        // Whatever the name, the result must stay inside the media folder and be a file
        if (!file.startsWith(root) || !Files.isRegularFile(file))
            return null;
        return file;
    }

    /**
     * What to send for the requested range (docs/PROTOCOL.md §3, "Range"). -1 means "not given", as in
     * the HTTP Range header the proxy received from the browser:
     *   -1, -1  whole file (OK)      S, -1  from S to the end      S, E  S to E      -1, N  last N bytes
     * start and end are inclusive; an end past the file is cut to the last byte.
     */
    static Payloads.StreamInfo streamInfo(Path file, long rangeStart, long rangeEnd) throws IOException {
        if (file == null)
            return new Payloads.StreamInfo(Payloads.StreamInfo.NOT_FOUND, 0, 0, 0, "");

        long size = Files.size(file);
        long start = 0;
        long end = size - 1; // default: the whole file

        if (rangeStart == -1 && rangeEnd != -1) {   // last N bytes
            start = Math.max(0, size - rangeEnd);
        } else if (rangeStart != -1) {     // from S, or S to E
            start = rangeStart;
            if (rangeEnd != -1)
                end = Math.min(rangeEnd, size - 1);
        }

        // Empty file, start past the end, start after end, or a negative value: nothing to send
        if (size == 0 || start < 0 || start >= size || start > end) {
            return new Payloads.StreamInfo(Payloads.StreamInfo.RANGE_NOT_SATISFIABLE, size, 0, 0, "");
        }
        // A browser that asked for a range (even "0-") expects 206, otherwise it thinks seeking is not supported
        int status;
        if (rangeStart == -1 && rangeEnd == -1) {
           status = Payloads.StreamInfo.OK;
        }
        else{
            status = Payloads.StreamInfo.PARTIAL;
        }

        return new Payloads.StreamInfo(status, size, start, end, "video/mp4");
    }

    /**
     * Sends bytes info.start()..info.end() of the file as DATA blocks (1 to BLOCK_SIZE bytes each)
     * at SEQ firstSeq, firstSeq+1, ..., then END. END carries the SEQ of the last DATA block, as
     * the assignment says (SEQF) and as the proxy checks; it is safe because the IV also mixes in
     * the message type, so END and that DATA block never share an IV. Returns the number of blocks.
     */
    static long sendBlocks(OutputStream out, SecureChannel ch, Path file, Payloads.StreamInfo info, long firstSeq)
            throws IOException, GeneralSecurityException {
        long seq = firstSeq;
        long blocks = 0;
        long bytes = 0;

        try (RandomAccessFile raf = new RandomAccessFile(file.toFile(), "r")) {
            raf.seek(info.start());
            byte[] buffer = new byte[BLOCK_SIZE];
            long remaining = info.length();

            while (remaining > 0) {
                int n = raf.read(buffer, 0, (int) Math.min(BLOCK_SIZE, remaining));
                if (n < 0) throw new IOException("file shrank while streaming"); // no END: the proxy sees a truncated stream

                // Exactly n bytes: the last block is usually shorter, and the buffer still holds the previous block
                byte[] block = Arrays.copyOf(buffer, n);
                out.write(ch.seal(SSPMessage.DATA, seq, block));
                seq++;
                blocks++;
                bytes += n;
                remaining -= n;
            }
        }

        long seqF = seq - 1; // the last DATA block's SEQ
        out.write(ch.seal(SSPMessage.END, seqF, new Payloads.End(seqF, blocks, bytes).encode()));
        out.flush();
        return blocks;
    }
}
