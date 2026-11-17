# Secure Streaming Solution (Work Assignment 1)

A **Secure Proxy** and a **Secure Stream Server** that stream MP4 video to a browser. Everything between
the proxy and the server is encrypted and authenticated, and the cryptography is chosen in config files
(no recompiling needed to change it).

```
browser ──HTTP──▶ Secure Proxy ──encrypted──▶ Secure Stream Server ──▶ streamserver/media/*.mp4
```

How the protocol works: [docs/PROTOCOL.md](docs/PROTOCOL.md).

## Requirements

**JDK 21 or newer.** RC6 also needs BouncyCastle, which is included in `lib/bcprov-jdk18on-1.86.jar`
(see [RC6](#rc6)); every other configuration uses only the JDK. Docker is optional (see [Docker](#docker)).

## Compile

From the project root:

```bash
javac -d out/server streamserver/*.java common/*.java
javac -d out/proxy  streamproxy/*.java  common/*.java
```

## Run

From the project root (the paths are relative to it), in two terminals. Start the server first:

```bash
java -cp out/server OriginSocketServer 8081 streamserver/media streamserver/servercrypto.config
java -cp out/proxy  ProxySocketServer  8080 localhost 8081 streamproxy/proxycrypto.config
```

Then open **http://localhost:8080/**. `dante.mp4` plays; to play another video, type its name
(`flower.mp4`, `friday.mp4`, or any MP4 you put in `streamserver/media/`) and press *Load*.
`flower.mp4` and `friday.mp4` are CC0 sample videos from MDN (interactive-examples.mdn.mozilla.net/media/cc0-videos).

| Program | Arguments, in order |
|---|---|
| Server | port, media folder, config file |
| Proxy | port, server address, server port, config file |

**On two machines:** start the server on one machine (open port 8081 in its firewall), and on the other
replace `localhost` with the server's IP address in the proxy command.

## Changing the cryptography

The configuration is read only at startup, so to change it stop both programs and start them again with
another pair of config files. Nothing needs to be recompiled. Two ways:

- **Use a tested pair from `configs/`** (see the table below), passing its two files on the command line:

  ```bash
  java -cp out/server OriginSocketServer 8081 streamserver/media configs/aes-cbc-hmac/servercrypto.config
  java -cp out/proxy  ProxySocketServer  8080 localhost 8081 configs/aes-cbc-hmac/proxycrypto.config
  ```

- **Edit** `streamproxy/proxycrypto.config` and `streamserver/servercrypto.config` (the default pair, AES-GCM).

**Both files of a pair must have the same values**, including the keys (`<SKey>`, `<MacKey>`); only the root
tag differs (`<ProxyCryptoConfig>` / `<ServerCryptoConfig>`). Supported options:

| Setting | Options |
|---|---|
| Cipher | AES-GCM, ChaCha20-Poly1305 (no MAC needed) · AES or RC6 in CBC, CTR, OFB, CFB, and ChaCha20 (with HMAC-SHA256/384/512) |
| Key exchange | X25519, X448, DH-3072 |
| Hash | SHA-256, SHA-384, SHA-512 |
| Key size | 128, 192, 256 bits (ChaCha20: 256) |

Rules for a valid pair: GCM and Poly1305 use `MAC NULL`; every other mode needs an HMAC and a `MacKey` of at
least 128 bits. `PKCS5Padding` only with CBC (`NULL` otherwise). `IVSize` 96 for GCM and ChaCha20, 128 for
CBC, CTR, OFB and CFB. The key length in hex characters × 4 must equal `Keysize` (and `MacKeySize`).

If a config is invalid or unsafe (e.g. ECB, a mode without a MAC, a key of the wrong size), the program
refuses to start and says why. When it starts, it prints the configuration it is using:

```
Crypto config streamserver/servercrypto.config: AES/GCM/NULL/NULL | MAC NULL | X25519 | SHA-256 | key 256 bits  (AES/GCM/NoPadding)
```

### Tested configurations (`configs/`)

Each folder has a `proxycrypto.config` and a `servercrypto.config` with its own random keys. All nine were
tested end to end (full file and seeking); the overhead is network bytes vs video bytes.

| Folder | Cipher | MAC | Key exchange | Hash | Key | Overhead |
|---|---|---|---|---|---|---|
| `aes-gcm` | AES-GCM | — (AEAD) | X25519 | SHA-256 | 256 | 3.22% |
| `chacha20-poly1305` | ChaCha20-Poly1305 | — (AEAD) | X448 | SHA-384 | 256 | 3.22% |
| `aes-cbc-hmac` | AES-CBC, PKCS5Padding | HMAC-SHA256 | DH-3072 | SHA-256 | 128 | 6.35% |
| `aes-ctr-hmac` | AES-CTR | HMAC-SHA512 | X25519 | SHA-512 | 192 | 7.91% |
| `aes-ofb-hmac` | AES-OFB | HMAC-SHA256 | X448 | SHA-384 | 256 | 4.79% |
| `aes-cfb-hmac` | AES-CFB | HMAC-SHA384 | DH-3072 | SHA-512 | 128 | 6.35% |
| `chacha20-hmac` | ChaCha20 | HMAC-SHA384 | X448 | SHA-384 | 256 | 6.35% |
| `aes-gcm-fixed-iv` | AES-GCM, fixed `<IV>` in the config | — (AEAD) | X25519 | SHA-256 | 192 | 3.22% |
| `rc6-cbc-hmac` | RC6-CBC, PKCS5Padding (needs `lib/`, see [RC6](#rc6)) | HMAC-SHA256 | X25519 | SHA-256 | 256 | 6.35% |

With a fixed `<IV>`, each message still gets its own nonce (`IV XOR (TYPE ‖ SEQ)`, see PROTOCOL.md), and the
stream keys are new for every connection, so a key/nonce pair is never reused in the stream (for message 2, see the known limitation in PROTOCOL.md §4).

The proxy output of one full download per configuration is in `docs/tests_configs.docx`.

## What you should see

After each request the proxy prints its statistics in its own terminal (AES-GCM shown):

```
[stats] dante.mp4  COMPLETED
  handshake  108.73 ms
  range      bytes 0-25941345 of 25941346 B file
  blocks     received 25334 encrypted | forwarded 25334 decrypted
  data       plain 25941346 B (100.00% of file, 100.00% of range) | wire 26777368 B (overhead 3.22%)
  transfer   0.46 s -> 56.30 MB/s (plain bytes / time from first block to end)
```

The browser makes several requests per video (and one per seek), so you get several reports.
Requests the browser cancels show as `CONNECTION_CLOSED`, which is normal. To measure one complete download,
request the whole file without a browser while both programs run:

```bash
curl -o /dev/null http://localhost:8080/video/dante.mp4    # PowerShell: curl.exe -o NUL ...
```

Quick checks:
- http://localhost:8080/video/nothere.mp4 → 404.
- Different cipher in the two files → the server rejects it (`INCOMPATIBLE_SUITE`).
- Different `<SKey>` in the two files → the proxy rejects the server (`BAD_RECORD_MAC`): this is what stops a man-in-the-middle.
- `<Mode>ECB</Mode>`, or CBC with `MAC NULL` → the program refuses to start.
- `curl localhost:8081/` (a browser or plain HTTP client talking to the server directly) → the server rejects
  it: `Connection rejected, ALERT sent: UNSUPPORTED_VERSION ... not an SSP peer`.

## Concurrent sessions

The server and the proxy handle each connection in its own thread, and every connection has its own
handshake, keys and sequence numbers, so sessions are independent. Several proxies can use one server at once.

**Automatic test** (macOS / Linux / Git Bash): one server, N proxies, every proxy downloads every movie in
`streamserver/media` at the same time plus one seek, and each download is compared byte by byte with the original:

```bash
tests/concurrency.sh                          # configs/aes-gcm, 3 proxies, 2 rounds
tests/concurrency.sh configs/chacha20-hmac 5 3 # config, proxies, rounds
```

It ends with `RESULT: OK` when every download is identical and no proxy aborted (it uses ports 19081 and 19090+).

**In the browser:** start the server once, then two proxies on different ports, and open one tab per proxy
with a different movie:

```bash
java -cp out/server OriginSocketServer 8081 streamserver/media configs/aes-gcm/servercrypto.config
java -cp out/proxy  ProxySocketServer  8080 localhost 8081 configs/aes-gcm/proxycrypto.config
java -cp out/proxy  ProxySocketServer  8090 localhost 8081 configs/aes-gcm/proxycrypto.config
```

http://localhost:8080/ (`dante.mp4`) and http://localhost:8090/ (type `flower.mp4`, *Load*) play at the same time.

## Attack tests

The results of all of these, with the logs of both programs, are in `docs/tests_errors.docx`.

**Invalid configs** (`tests/negative/`): each file differs from a config in `configs/` in one line.

| File | Changed from | Result |
|---|---|---|
| `ecb.config` | `aes-cbc-hmac`: `<Mode>ECB</Mode>` | refused at startup: `AES mode must be GCM, CBC, CTR, OFB or CFB` |
| `no-mac.config` | `aes-cbc-hmac`: MAC `NULL` | refused at startup: `non-AEAD modes need a MAC` |
| `wrong-keysize.config` | `aes-cbc-hmac`: `<Keysize>256</Keysize>` | refused at startup: `SKey has 128 bits but Keysize is 256` |
| `wrong-key-server.config` | `aes-gcm`: one digit of `<SKey>` | starts, but with `configs/aes-gcm/proxycrypto.config` the proxy rejects the server: `BAD_RECORD_MAC` (type 2) |

```bash
java -cp out/server OriginSocketServer 8081 streamserver/media tests/negative/ecb.config
```

**Man-in-the-middle** (`tests/MitmRelay.java`): a relay between the proxy and the server that knows no keys
and attacks the 10th DATA message of every connection (or the HELLO). It runs straight from the source, no
compiling needed. Point the proxy at the relay instead of the server:

```bash
java -cp out/server OriginSocketServer 8081 streamserver/media configs/aes-gcm/servercrypto.config
java tests/MitmRelay.java 9000 localhost 8081 tamper        # relay: port 9000 -> server 8081
java -cp out/proxy  ProxySocketServer  8080 localhost 9000 configs/aes-gcm/proxycrypto.config
curl -s -o /dev/null http://localhost:8080/video/dante.mp4  # PowerShell: curl.exe -s -o NUL ...
```

To try another attack, stop only the relay (Ctrl+C) and start it again with another name. An optional last
argument picks the DATA message to attack (`tamper 500`).

| Attack | What the relay does | The proxy aborts with |
|---|---|---|
| `none` | forwards everything (the file must arrive identical) | — (`COMPLETED`) |
| `tamper` | flips 1 bit in DATA #10 | `BAD_RECORD_MAC` (type 4) |
| `replay` | sends DATA #10 twice | `BAD_SEQUENCE` |
| `reorder` | swaps DATA #10 and #11 | `BAD_SEQUENCE` |
| `drop` | deletes DATA #10 | `BAD_SEQUENCE` |
| `truncate` | cuts the connection after DATA #10 | `TRUNCATED_STREAM` |
| `tamper-hello` | flips 1 bit of the proxy's DH public key | `BAD_RECORD_MAC` (type 2), HTTP 502 |

A forged block is never forwarded to the browser. For the attacks on DATA, curl still shows `200` because the
HTTP header was already sent; the proxy then closes the connection, so the client gets fewer bytes than
`Content-Length`.

**Handshake replay** (`tests/HandshakeReplay.java`): relays one request, recording the handshake, then replays
its HELLO and RESPONSE to the server with no keys. It also runs straight from the source:

```bash
java -cp out/server OriginSocketServer 8081 streamserver/media configs/aes-gcm/servercrypto.config
java tests/HandshakeReplay.java 9000 localhost 8081
java -cp out/proxy  ProxySocketServer  8080 localhost 9000 configs/aes-gcm/proxycrypto.config
curl -s -o /dev/null -H "Range: bytes=0-2047" http://localhost:8080/video/dante.mp4
```

It ends with `RESULT: OK`. The old RESPONSE is rejected with `BAD_RECORD_MAC`. Each replayed HELLO gets a new
CHALLENGE and shows the known limitation of message 2 (PROTOCOL.md §4): in modes that use a keystream, the first
ciphertext bytes repeat. It relays only that one request and then stops.

## RC6

RC6 is not in the JDK, so it uses BouncyCastle (`lib/bcprov-jdk18on-1.86.jar`, the jar from the SSC labs).
The code loads it by name only when a config asks for RC6, so compiling never needs it. Add the jar to the
classpath of **both** programs:

```bash
# macOS / Linux
java -cp "out/server:lib/bcprov-jdk18on-1.86.jar" OriginSocketServer 8081 streamserver/media configs/rc6-cbc-hmac/servercrypto.config
java -cp "out/proxy:lib/bcprov-jdk18on-1.86.jar"  ProxySocketServer  8080 localhost 8081 configs/rc6-cbc-hmac/proxycrypto.config
# Windows: use ; instead of :   e.g.  java -cp "out/server;lib/bcprov-jdk18on-1.86.jar" OriginSocketServer ...
```

Without the jar, a config with RC6 is refused at startup: `RC6 needs BouncyCastle (lib/bcprov-jdk18on-1.86.jar) on the classpath`.

## Docker

One image holds both programs. The config files and the videos are **not** in the image: they are mounted
from the host (`configs/` and `streamserver/media/`), so changing the cryptography never needs a rebuild.

```bash
docker compose up --build                       # server + proxy with configs/aes-gcm
CONFIG=chacha20-poly1305 docker compose up      # another pair from configs/, no rebuild
# PowerShell: $env:CONFIG="chacha20-poly1305"; docker compose up
```

Then open **http://localhost:8080/**. `docker compose down` stops both containers.

**On two machines with Docker:** build the image on both (`docker build -t ssc-3s .`), then:

```bash
# machine A (server)
docker run --rm -p 8081:8081 -v "$PWD/configs:/configs:ro" -v "$PWD/streamserver/media:/media:ro" ssc-3s \
  java -cp /app/server:/app/lib/bcprov-jdk18on-1.86.jar OriginSocketServer 8081 /media /configs/aes-gcm/servercrypto.config
# machine B (proxy): replace SERVER_IP with machine A's address
docker run --rm -p 8080:8080 -v "$PWD/configs:/configs:ro" ssc-3s \
  java -cp /app/proxy:/app/lib/bcprov-jdk18on-1.86.jar ProxySocketServer 8080 SERVER_IP 8081 /configs/aes-gcm/proxycrypto.config
```

## Assignment documents

- [WA1-Work-Assignment.pdf](https://github.com/user-attachments/files/33380477/WA1-Work-Assignment.pdf)
- [WA1-Additional-Info-FAQ.pdf](https://github.com/user-attachments/files/33380484/WA1-Additional-Info-FAQ.pdf)
