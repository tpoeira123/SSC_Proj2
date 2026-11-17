# 3S — Secure Streaming Protocol (SSP) v1.1

Protocol between the **Secure Proxy** (`streamproxy/`) and the **Secure Stream Server** (`streamserver/`).
The code shared by both is in `common/`.

## 1. Overview

```
 PROXY                                                      SERVER
   │── 1 HELLO        in clear: proposal + proxy's DH key ───────▶│  does the proposal match my config?
   │◀─ 2 CHALLENGE    🔒 challenge SRV + server's DH key ─────────│  encrypted with the PSK only
   │── 3 RESPONSE     🔒 R = H(SRV) + video name + range ────────▶│  encrypted with PSK + DH; checks R
   │◀─ 6 STREAM_INFO  🔒 status (200/206/404/416) + size ─────────│
   │◀─ 4 DATA         🔒 one block of the video (up to 1024 B) × N│
   │◀─ 5 END          🔒 "END" + totals ──────────────────────────│
   └─ any error: 255 ALERT and the connection is closed
```

- **One TCP connection = one request.** The browser makes several requests with `Range` (one per seek).
- **PSK** = pre-shared key: the `<SKey>` (and `<MacKey>`) that is identical in both config files.
- **🔒** = encrypted and authenticated. Nothing is decrypted before its tag/MAC has been verified.

## 2. Message format

```
HEADER (9 bytes, always in clear)                         PAYLOAD
VERSION u16 = 1 | RELEASE u16 = 1 | TYPE u8 | LENGTH u32 | ...
```

`TYPE`: 1 HELLO · 2 CHALLENGE · 3 RESPONSE · 4 DATA · 5 END · 6 STREAM_INFO · 255 ALERT.
Integers are big-endian; `str` and `bytes` are preceded by a 2-byte length. Maximum payload: 16384 bytes.

## 3. The messages

| # | Content | Protected with |
|---|---|---|
| 1 HELLO | `SEQX` (random, 62 bits), `PCC` = `ALG/MODE/IV/PADDING`, MAC, key exchange, hash, key sizes, proxy's DH public key | nothing (in clear) |
| 2 CHALLENGE | `SEQX+1`, `SRV` (32 random bytes), `CCC` (= PCC), server's DH public key | `hs s2p` keys (PSK only) |
| 3 RESPONSE | `SEQX+2`, `R = H(SRV)`, file name, start and end of the range | `hs p2s` keys (PSK + DH) |
| 6 STREAM_INFO | status, file size, first and last byte, `video/mp4` | stream keys |
| 4 DATA | 1 to 1024 bytes of the file | stream keys |
| 5 END | `SEQF`, `"END"`, 16 random bytes, number of blocks, number of bytes | stream keys |
| 255 ALERT | 1 byte with the error code | in clear before the stream keys exist, encrypted after |

**Range** (copied from the browser's `Range`; `-1` = not given): `-1,-1` whole file (200) ·
`S,-1` from S to the end · `S,E` from S to E · `-1,N` last N bytes (these three give 206).
Impossible (e.g. starts after the end) → 416. Missing file, or a name with `/`, `\`, `..` → 404.

**Sequence numbers**: everything starts from the proxy's `SEQX`.

| Message | SEQ |
|---|---|
| 1, 2, 3 | `SEQX`, `SEQX+1`, `SEQX+2` (= `SEQZ`) |
| STREAM_INFO | `SEQZ+1` |
| DATA | `SEQZ+1`, `SEQZ+2`, … (one per block) |
| END | the SEQ of the last DATA |

The receiver requires **exactly** the next SEQ: a repeated, reordered or missing message is rejected.
`SEQX` has its top 2 bits set to 0 (the server rejects any other value with `DECODE_ERROR`), so `SEQX + n` never overflows.

## 4. Keys (HKDF)

```
before DH:  PRK = HKDF(PSK)
after DH:   PRK = HKDF(salt = PSK, DH secret)

key = HKDF-Expand(PRK, "3S " + label + hash of the messages so far)

  hs s2p   ← H(msg1)                  protects msg 2
  hs p2s   ← H(msg1 ‖ msg2)           protects msg 3
  app s2p  ← H(msg1 ‖ msg2 ‖ msg3)    server → proxy: types 6, 4, 5 and alerts
  app p2s  ← H(msg1 ‖ msg2 ‖ msg3)    proxy → server: alerts
```

Each "key" is actually: encryption key + MAC key (if not AEAD) + base IV.
The DH is ephemeral: a new key pair for every connection.

**Why it is secure:**
- **No PSK, no keys.** An attacker in the middle cannot decrypt msg 2 or forge msg 3 (anti-MITM).
- **Changing any handshake message changes the hash**, so the two sides derive different keys and the next tag fails.
- **Forward secrecy:** the stream keys depend on the ephemeral DH. Stealing the PSK later does not decrypt recorded streams.
- **Known limitation:** HELLO is in clear and msg 2 keeps the format of the assignment, so a replayed HELLO makes the server encrypt a new msg 2 under the same key and nonce. In AEAD, CTR, OFB and ChaCha20 modes an attacker learns the XOR of the `SRV` and DH public values of those replies, but not the stream: the keys of msg 3 and of the stream depend on the fresh DH secret.
- **R = H(SRV)** proves the proxy decrypted the challenge of *this* session: an old msg 3 is useless.

## 5. How each message is protected

- **AEAD** (`AES/GCM`, `ChaCha20/Poly1305`): encryption + 16-byte tag. MAC = `NULL` in the config.
- **Cipher + HMAC** (`AES` or `RC6` in CBC, CTR, OFB or CFB, and `ChaCha20`): encrypt, then HMAC over everything (*encrypt-then-MAC*). The MAC is verified before decrypting.
- The tag/MAC also covers the **header and the SEQ**.
- **Nonce/IV** of each message = `base IV XOR (TYPE ‖ SEQ)`. Within a connection it never repeats under the same key, because each (type, SEQ) pair is used only once. That is why END can have the same SEQ as the last DATA. In CBC and CFB the IV is also encrypted, so that it is unpredictable (OFB, like CTR, only needs a unique IV).

## 6. Configuration files

`proxycrypto.config` and `servercrypto.config`, in the format of the assignment plus `<KeyExchange>` and `<HashSuite>`.
**Both must have the same values**, including the PSK.

| Field | Values |
|---|---|
| `Algorithm` / `Mode` | AES: GCM, CBC, CTR, OFB, CFB · ChaCha20: Poly1305 or NULL · RC6 (BouncyCastle): CBC, CTR, OFB, CFB |
| `IV` / `IVSize` | `NULL` (derived) or a fixed value · 96 (GCM, ChaCha20) or 128 (CBC, CTR, OFB, CFB) |
| `Padding` | `PKCS5Padding` only with CBC |
| MAC | `NULL` with GCM/Poly1305 · otherwise HMAC-SHA256/384/512 |
| `KeyExchange` | X25519, X448, DH-3072 |
| `HashSuite` | SHA-256, SHA-384, SHA-512 |
| `Keysize` / `MacKeySize` | 128, 192, 256 (ChaCha20: 256) / ≥ 128 |

An invalid or insecure combination (e.g. ECB, CBC without a MAC, a key of the wrong size) stops the program from starting and says why.

The `configs/` folder has 9 tested pairs (a pair = the two files, with their own keys): `aes-gcm`,
`chacha20-poly1305`, `aes-cbc-hmac`, `aes-ctr-hmac`, `aes-ofb-hmac`, `aes-cfb-hmac`, `chacha20-hmac`,
`aes-gcm-fixed-iv` (fixed IV in the config: each message's nonce is still `IV XOR (TYPE ‖ SEQ)`) and
`rc6-cbc-hmac` (RC6 via BouncyCastle, `lib/bcprov-jdk18on-1.86.jar`).
Together they use every supported mode, key exchange, hash and key size (table in the README).

## 7. Alerts (type 255)

| Code | Name | When |
|---|---|---|
| 1 | `UNSUPPORTED_VERSION` | version ≠ 1.1 |
| 2 | `UNEXPECTED_MESSAGE` | wrong message type |
| 3 | `DECODE_ERROR` | malformed message |
| 4 | `INCOMPATIBLE_SUITE` | proposal ≠ server config |
| 5 | `BAD_RECORD_MAC` | wrong tag/MAC (message altered or different PSK) |
| 6 | `BAD_SEQUENCE` | wrong SEQ (replay, reordering, loss) |
| 7 | `CHALLENGE_FAILED` | wrong R |
| 8 | `RECORD_TOO_LARGE` | payload > 16384 bytes |
| 9 | `TRUNCATED_STREAM` | connection closed before END, or wrong totals in END |
| 10 | `INTERNAL_ERROR` | local error |

At most one alert per connection, never in reply to another alert, and the connection is then closed.
An alert in clear can be injected by an attacker, but that only lets them cut the connection (DoS, outside the threat model).

## 8. Proxy statistics

At the end of each request the proxy prints: blocks received and forwarded, video bytes (compared with the
file size), bytes on the network (overhead), throughput in MB/s (from the 1st block to the end) and handshake time.

**Overhead** per 1024 B block = 17 B (header 9 + SEQ 8) + tag/MAC + padding:

| Configuration | Extra per block | Overhead |
|---|---|---|
| AES-GCM, ChaCha20-Poly1305 | 17 + 16 (tag) = 33 B | 3.22% |
| AES-OFB + HMAC-SHA256 | 17 + 32 (MAC) = 49 B | 4.79% |
| AES-CBC, RC6-CBC + HMAC-SHA256 | 17 + 16 (padding) + 32 (MAC) = 65 B | 6.35% |
| AES-CFB, ChaCha20 + HMAC-SHA384 | 17 + 48 (MAC) = 65 B | 6.35% |
| AES-CTR + HMAC-SHA512 | 17 + 64 (MAC) = 81 B | 7.91% |

In CBC, a 1024 B block (a multiple of 16) gets a whole block of PKCS5 padding. The other modes work as
stream ciphers and need no padding. The values measured in the tests match these numbers to the byte.

## 9. Differences from the assignment

| Assignment | Here | Why |
|---|---|---|
| Does not say where the DH goes | Proxy's DH key in msg 1, server's inside msg 2 | The assignment requires DH; inside msg 2 it is authenticated by the PSK |
| Msg 2 encrypted without saying with which key | Keys derived from the PSK | Only the real server can create it |
| — | Type 6 STREAM_INFO | The browser needs the size and the range to play and seek |
| MEDIA | MEDIA + range | Seeking in the video |
| END with "END" + random | + number of blocks and bytes | Detect a stream cut in the middle |
| Only cipher and MAC algorithms in the config | + `<KeyExchange>` and `<HashSuite>` | Nothing hard-coded |
| `sservercrypto.config` / `sscrypto.config` | `servercrypto.config` | The assignment uses both names |
| XML example with badly closed tags | Valid XML | The example is not valid XML |
