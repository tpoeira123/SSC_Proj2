import java.util.Locale;

/**
 * Instrumentation for one stream (one browser request): counts what the proxy received from the
 * server and what it forwarded to the browser, and prints a single report when the stream ends.
 * One object per stream, used by one thread only, so no synchronization is needed.
 */
final class StreamStats {

    private final String name;
    private final long startNanos;
    private long handshakeNanos;
    private long fileSize;
    private long rangeStart;
    private long rangeEnd;
    private long expectedLength;
    private long firstBlockNanos = -1; // -1 = no block received yet
    private long endNanos;
    private long encryptedBlocksReceived;
    private long decryptedBlocksForwarded;
    private long wireBytes;
    private long plainBytes;
    private String outcome;

    StreamStats(String name) {
        this.name = name;
        this.startNanos = System.nanoTime();
    }

    // Handshake time = handshakeNanos - startNanos.
    // expectedLength vs plainBytes: how much of the requested range reached the browser
    void handshakeDone(Payloads.StreamInfo info) {
        handshakeNanos = System.nanoTime();
        this.fileSize = info.fileSize();
        this.rangeStart = info.start();
        this.rangeEnd = info.end();
        this.expectedLength = info.length();
    }

    void blockReceived(int wireLength) {
        if (firstBlockNanos == -1) {
            firstBlockNanos = System.nanoTime();
        }
        encryptedBlocksReceived++;
        wireBytes += wireLength;
    }

    void blockForwarded(int plainLength) {
        decryptedBlocksForwarded++;
        plainBytes += plainLength;
    }

    void finish(String outcome) {
        this.endNanos = System.nanoTime();
        // COMPLETED, CLIENT_CLOSED, ABORTED (reason)
        this.outcome = outcome;
    }

    String report() {
        StringBuilder r = new StringBuilder();
        r.append("[stats] ").append(name).append("  ").append(outcome).append("\n");

        if (handshakeNanos == 0) { // failed before the server answered: nothing else was measured
            return r.append("  handshake  failed").toString();
        }
        r.append("  handshake  ").append(fmt((handshakeNanos - startNanos) / 1e6)).append(" ms\n");

        r.append("  range      ");
        if (expectedLength > 0) r.append("bytes ").append(rangeStart).append("-").append(rangeEnd);
        else r.append("none");
        r.append(" of ").append(fileSize).append(" B file\n");

        r.append("  blocks     received ").append(encryptedBlocksReceived).append(" encrypted | forwarded ")
                .append(decryptedBlocksForwarded).append(" decrypted\n");

        r.append("  data       plain ").append(plainBytes).append(" B (")
                .append(percent(plainBytes, fileSize)).append(" of file, ")
                .append(percent(plainBytes, expectedLength)).append(" of range) | wire ")
                .append(wireBytes).append(" B (overhead ")
                .append(percent(wireBytes - plainBytes, plainBytes)).append(")\n");

        r.append("  transfer   ");
        if (firstBlockNanos == -1) {
            r.append("n/a (no blocks)");
        } else {
            double seconds = (endNanos - firstBlockNanos) / 1e9;
            r.append(fmt(seconds)).append(" s -> ")
                    .append(seconds > 0 ? fmt(plainBytes / 1e6 / seconds) + " MB/s" : "n/a")
                    .append(" (plain bytes / time from first block to end)");
        }
        return r.toString();
    }

    // Locale.ROOT: always "13.44", never "13,44" on a Portuguese system
    private static String fmt(double value) {
        return String.format(Locale.ROOT, "%.2f", value);
    }

    private static String percent(long part, long whole) {
        return whole > 0 ? fmt(part * 100.0 / whole) + "%" : "n/a";
    }
}
