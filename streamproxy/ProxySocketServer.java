import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.util.concurrent.Executors;

import static java.nio.charset.StandardCharsets.UTF_8;
/**
 * Proxy implemented with raw sockets only (java.net.ServerSocket / Socket), no
 * com.sun.net.httpserver, no java.net.http.HttpClient, no external libraries.
 * Serves a small page at "/" and relays GET /video/<file> to the origin server,
 * forwarding the Range header and streaming the response body back block by
 * block (no whole-file buffering). Each browser connection handles one request,
 * then closes.
 *
 * Usage: java ProxySocketServer [port=8080] [originHost=localhost] [originPort=8081] [config=proxycrypto.config]
 */
public class ProxySocketServer {

    static final int BLOCK_SIZE = 1024;

    static final String INDEX_HTML = """
            <!doctype html>
            <html><head><meta charset="utf-8"><title>3S Secure Proxy</title></head>
            <body style="font-family:sans-serif;max-width:900px;margin:2rem auto">
              <h1>3S Secure Proxy</h1>
              <p>File: <input id="f" value="dante.mp4">
                 <button onclick="load()">Load</button></p>
              <video id="v" controls preload="metadata" style="width:100%"></video>
              <script>
                function load() {
                  const v = document.getElementById('v');
                  v.src = '/video/' + encodeURIComponent(document.getElementById('f').value);
                  v.load();
                }
                load();
              </script>
            </body></html>
            """;

    public static void main(String[] args) throws Exception {
        int port = args.length > 0 ? Integer.parseInt(args[0]) : 8080;
        String originHost = args.length > 1 ? args[1] : "localhost";
        int originPort = args.length > 2 ? Integer.parseInt(args[2]) : 8081;
        String configPath = args.length >3 ? args[3] : "proxycrypto.config";

        CipherSuite suite;
        CryptoConfig config;

        try{
            config = CryptoConfig.load(Path.of(configPath));
            suite = new CipherSuite(config);
        }catch(IllegalArgumentException | GeneralSecurityException e){
            System.err.println("Invalid crypto config: " + e.getMessage());
            System.exit(1);
            return;
        }

        try (ServerSocket server = new ServerSocket(port)) {
            System.out.println("Proxy on http://localhost:" + port + "/  ->  http://" + originHost + ":" + originPort);
            System.out.println("Crypto config " + configPath + ": " + config + "  (" + suite + ")");
            var pool = Executors.newCachedThreadPool();
            while (true) {
                Socket client = server.accept();
                pool.submit(() -> handle(client, originHost, originPort,config,suite));
            }
        }
    }

    static void handle(Socket browser, String originHost, int originPort, CryptoConfig config, CipherSuite suite) {
        try (browser) {
            // Only reads time out (we never read from the browser while streaming): an idle client cannot hold a thread
            browser.setSoTimeout(20_000);
            InputStream in = browser.getInputStream();
            OutputStream out = browser.getOutputStream();

            String requestLine = HttpUtil.readLine(in);
            String[] requestParts = requestLine == null ? new String[0] : requestLine.split(" ");
            if (requestParts.length < 2 || !requestParts[0].equals("GET")) {
                writeSimpleStatus(out, 400, "Bad Request");
                return;
            }
            String path = requestParts[1];
            int q = path.indexOf('?');
            if (q >= 0) path = path.substring(0, q);

            String rangeHeader = null;
            String line;
            while ((line = HttpUtil.readLine(in)) != null && !line.isEmpty()) {
                int c = line.indexOf(':');
                if (c > 0 && line.substring(0, c).equalsIgnoreCase("Range")) {
                    rangeHeader = line.substring(c + 1).trim();
                }
            }

            if (path.equals("/") || path.isEmpty()) {
                servePage(out);
                return;
            }
            if (!path.startsWith("/video/")) {
                writeSimpleStatus(out, 404, "Not Found");
                return;
            }

            String name = path.substring("/video/".length());
            try{
                name = URLDecoder.decode(name.replace("+", "%2B"), UTF_8);
            }catch (IllegalArgumentException e){
                writeSimpleStatus(out,400, "Bad Request");
                return;
            }
            // A name with CR/LF or other control characters is never a file, and would forge lines in the logs
            if (name.chars().anyMatch(c -> c < 0x20 || c == 0x7f)) {
                writeSimpleStatus(out, 400, "Bad Request");
                return;
            }
            relaySecure(out, originHost, originPort, config, suite, name, rangeHeader);

        } catch (IOException e) {
            // Browser disconnected or origin unreachable mid-stream: nothing to do.
        }
    }

    static void servePage(OutputStream out) throws IOException {
        byte[] page = INDEX_HTML.getBytes(UTF_8);
        StringBuilder headers = new StringBuilder();
        headers.append("HTTP/1.1 200 OK\r\n")
                .append("Content-Type: text/html; charset=utf-8\r\n")
                .append("Content-Length: ").append(page.length).append("\r\n")
                .append("Connection: close\r\n\r\n");
        out.write(headers.toString().getBytes(StandardCharsets.US_ASCII));
        out.write(page);
        out.flush();
    }

    static void relaySecure(OutputStream browserOut, String originHost, int originPort, CryptoConfig config, CipherSuite suite,
                            String name, String rangeHeader) throws IOException{
        long[] range = parseRange(rangeHeader);

        Socket originSocket;
        StreamStats streamStats = new StreamStats(name);
        try {
            originSocket = new Socket(originHost, originPort);
        } catch (IOException e) {
            writeSimpleStatus(browserOut, 502, "Bad Gateway");
            return;
        }

        try(Socket server =originSocket){
            server.setSoTimeout(10_000);
            ProxyHandshake hs = new ProxyHandshake(server.getInputStream(), server.getOutputStream(),config, suite);
            boolean headerSent = false;
            String outcome = "COMPLETED";

            try {
                Payloads.StreamInfo info = hs.run(name,range[0],range[1]);
                streamStats.handshakeDone(info);
                writeResponseHeaders(browserOut,info);
                headerSent = true;
                if (!info.hasBody()) return;
                receiveBlocks(server.getInputStream(),hs,info,browserOut,streamStats);
            }catch (ProtocolAlert a){
                outcome = "ABORTED (" + a.getMessage() + ")";
                if (!a.fromPeer) hs.sendAlert(a.code);
                if (!headerSent) writeSimpleStatus(browserOut, 502, "Bad Gateway");
            }catch (GeneralSecurityException e){
                outcome = "ABORTED (" + e + ")";
                hs.sendAlert(ProtocolAlert.INTERNAL_ERROR);
                if (!headerSent) writeSimpleStatus(browserOut, 502, "Bad Gateway");
            }catch (IOException e ){
                // browser closed (e.g. seek), server dropped or timed out: we cannot tell which side
                outcome = "CONNECTION_CLOSED (" + e.getMessage() + ")";
                if (!headerSent) writeSimpleStatus(browserOut, 502, "Bad Gateway");
            }finally {
                streamStats.finish(outcome);
                System.out.println(streamStats.report());
            }
        }
    }

    static void writeResponseHeaders(OutputStream out, Payloads.StreamInfo info) throws IOException {
        StringBuilder r = new StringBuilder();
        r.append(switch (info.status()) {
            case Payloads.StreamInfo.OK -> "HTTP/1.1 200 OK\r\n";
            case Payloads.StreamInfo.PARTIAL -> "HTTP/1.1 206 Partial Content\r\n";
            case Payloads.StreamInfo.NOT_FOUND -> "HTTP/1.1 404 Not Found\r\n";
            default -> "HTTP/1.1 416 Range Not Satisfiable\r\n";
        });
        if (info.hasBody()) r.append("Content-Type: ").append(info.contentType()).append("\r\n");
        r.append("Accept-Ranges: bytes\r\n");
        if (info.status() == Payloads.StreamInfo.PARTIAL) {
            r.append("Content-Range: bytes ").append(info.start()).append("-").append(info.end())
                    .append("/").append(info.fileSize()).append("\r\n");
        }
        if (info.status() == Payloads.StreamInfo.RANGE_NOT_SATISFIABLE) {
            r.append("Content-Range: bytes */").append(info.fileSize()).append("\r\n");
        }
        r.append("Content-Length: ").append(info.length()).append("\r\n");
        r.append("Connection: close\r\n\r\n");
        out.write(r.toString().getBytes(StandardCharsets.US_ASCII));
        out.flush();
    }

    static void receiveBlocks(InputStream in, ProxyHandshake hs, Payloads.StreamInfo info, OutputStream browserOut,
                              StreamStats stats) throws IOException, ProtocolAlert {
        SecureChannel ch = hs.channel();
        long expectedSeq = hs.firstDataSeq();
        long blocks = 0;
        long bytes = 0;

        while (true) {
            SSPMessage m;
            try {
                m = SSPMessage.read(in);
            } catch (EOFException e) {
                throw new ProtocolAlert(ProtocolAlert.TRUNCATED_STREAM, "server closed before END");
            }

            if (m.type == SSPMessage.DATA) {
                stats.blockReceived(m.wireLength()); // counted before open: a forged block is received, never forwarded
                byte[] block = ch.open(m, expectedSeq);
                if (block.length == 0 || block.length > BLOCK_SIZE || bytes + block.length > info.length()) {
                    throw new ProtocolAlert(ProtocolAlert.DECODE_ERROR, "bad block size " + block.length);
                }
                browserOut.write(block);
                browserOut.flush();
                stats.blockForwarded(block.length);
                expectedSeq++;
                blocks++;
                bytes += block.length;
            } else if (m.type == SSPMessage.END) {
                Payloads.End end = Payloads.End.decode(ch.open(m, expectedSeq - 1));
                if (end.seqF() != expectedSeq - 1) throw new ProtocolAlert(ProtocolAlert.BAD_SEQUENCE, "SEQF");
                if (end.totalBlocks() != blocks || end.totalBytes() != bytes || bytes != info.length()) {
                    throw new ProtocolAlert(ProtocolAlert.TRUNCATED_STREAM, "END totals do not match");
                }
                return;
            } else if (m.type == SSPMessage.ALERT) {
                throw hs.peerAlert(m, expectedSeq);
            } else {
                throw new ProtocolAlert(ProtocolAlert.UNEXPECTED_MESSAGE, "type " + m.type);
            }
        }
    }

    static void writeSimpleStatus(OutputStream out, int code, String reason) throws IOException {
        String resp = "HTTP/1.1 " + code + " " + reason + "\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
        out.write(resp.getBytes(StandardCharsets.US_ASCII));
        out.flush();
    }

    static long[] parseRange(String h){
        long start = -1;
        long end = -1;
        if (h == null || !h.startsWith("bytes=") || h.contains(",")){
            return new long[]{start, end};
        }
        String[] parts = h.substring(6).trim().split("-", -1);
        if (parts.length == 2 ){
            try{
                if (parts[0].isEmpty()) return new long[]{-1, Long.parseLong(parts[1])};
                 start = Long.parseLong(parts[0]);
                 end = parts[1].isEmpty() ? -1 : Long.parseLong(parts[1]);

            }catch (NumberFormatException e){
                return new long[]{-1, -1};
            }
        }
        return new long[]{start,end};
    }
}
