import java.io.Serial;

/**
 * A fatal Secure Streaming Protocol error. Thrown wherever a check fails; the connection
 * handler turns it into a Type 255 ALERT (unless the alert came from the peer) and closes the
 * connection. Codes: docs/PROTOCOL.md §7.
 */
final class ProtocolAlert extends Exception {

    @Serial
    private static final long serialVersionUID = 1L;

    static final int UNSUPPORTED_VERSION = 1;
    static final int UNEXPECTED_MESSAGE = 2;
    static final int DECODE_ERROR = 3;
    static final int INCOMPATIBLE_SUITE = 4;
    static final int BAD_RECORD_MAC = 5;
    static final int BAD_SEQUENCE = 6;
    static final int CHALLENGE_FAILED = 7;
    static final int RECORD_TOO_LARGE = 8;
    static final int TRUNCATED_STREAM = 9;
    static final int INTERNAL_ERROR = 10;

    final int code;
    final boolean fromPeer; // received in a Type 255: never answer an alert with another alert

    ProtocolAlert(int code, String detail) {
        this(code, detail, false);
    }

    private ProtocolAlert(int code, String detail, boolean fromPeer) {
        super(name(code) + (detail == null ? "" : ": " + detail));
        this.code = code;
        this.fromPeer = fromPeer;
    }

    static ProtocolAlert fromPeer(int code, boolean authenticated) {
        return new ProtocolAlert(code, authenticated ? "sent by peer" : "sent by peer (unauthenticated)", true);
    }

    static String name(int code) {
        return switch (code) {
            case UNSUPPORTED_VERSION -> "UNSUPPORTED_VERSION";
            case UNEXPECTED_MESSAGE -> "UNEXPECTED_MESSAGE";
            case DECODE_ERROR -> "DECODE_ERROR";
            case INCOMPATIBLE_SUITE -> "INCOMPATIBLE_SUITE";
            case BAD_RECORD_MAC -> "BAD_RECORD_MAC";
            case BAD_SEQUENCE -> "BAD_SEQUENCE";
            case CHALLENGE_FAILED -> "CHALLENGE_FAILED";
            case RECORD_TOO_LARGE -> "RECORD_TOO_LARGE";
            case TRUNCATED_STREAM -> "TRUNCATED_STREAM";
            case INTERNAL_ERROR -> "INTERNAL_ERROR";
            default -> "UNKNOWN(" + code + ")";
        };
    }
}
