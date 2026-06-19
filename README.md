# airplay 2 sender (c++)

**by Akustikrausch (Andreas Wendorf)**

<p>
  <img src="https://img.shields.io/badge/license-Apache--2.0-3da639" alt="license Apache-2.0">
  <img src="https://img.shields.io/badge/C%2B%2B-20-00599c" alt="C++20">
  <img src="https://img.shields.io/badge/protocol-AirPlay%202%20realtime-ff5e00" alt="AirPlay 2 realtime">
  <img src="https://img.shields.io/badge/codec-ALAC%20lossless-8a2be2" alt="ALAC lossless">
  <img src="https://img.shields.io/badge/crypto-ChaCha20--Poly1305%20%C2%B7%20X25519%20%C2%B7%20SRP--6a-blue" alt="crypto">
  <a href="https://github.com/akustikrausch/FXChainPlayer-Releases"><img src="https://img.shields.io/badge/proven%20in-FXChainPlayer-6c7bff" alt="proven in FXChainPlayer"></a>
</p>

a working, verified **AirPlay 2 realtime-audio SENDER** in c++. it pairs with a
modern **Apple TV 4K**, a **HomePod**, or a **macOS** receiver, and streams clean,
lossless **ALAC** to it over the encrypted RAOP/RTSP path apple actually uses
today — bidirectional volume, seamless track changes, the works.

this is the part of the apple-tax that nobody published. you can find a hundred
*receivers*. you can find python. you cannot find a small c++ thing that just
**sends** AirPlay 2 realtime audio to a current apple device and keeps the
session alive. so here it is, with the entire recipe written down.

## why this exists

the open AirPlay landscape is all receiver, wrong language, or stuck in 2014:

- **shairport-sync** — a *receiver*. brilliant, but the other direction.
- **owntone** (forked-daapd) — a whole media server, not a sender library. it
  *can* send, but you don't drop it into your app.
- **pyatv** — python, and a client/control library; not a c++ realtime audio
  pipe.
- **AirConnect / raop_play / the old shairport "client" forks** — AirPlay **1**
  / legacy rtsp. they do not do the AP2 handshake a 2024 apple tv demands
  (encrypted control channel, the event-channel + RECORD ordering, the
  hardcoded-ALAC realtime stream, the 30-second keep-alive).

apple never documented any of it. every byte here was recovered by reading the
above as a *spec* (never copying a line), packet-watching, and a lot of
"why did the socket just close after exactly one millisecond". the fact that
it took this long is the whole argument for the repo existing.

## the recipe (this is the valuable part)

if you only read one section, read this. AP2 realtime to a modern apple tv is
**seven** things in the **right order**, and getting any one wrong gives you a
session that *looks* connected and plays **silence**, or drops after ~30 s, or
refuses at SETUP. in order:

1. **pair, then an encrypted RTSP control channel — immediately.** right after
   pair-verify, every RTSP request/response rides ChaCha20-Poly1305. frame =
   `[2-byte LE len][cipher][16-byte tag]`, chunk ≤ 1024 B, AAD = the length
   prefix, nonce = `[4 zero bytes][8-byte LE counter]`, separate send/recv
   counters (Control-Write / Control-Read keys). skip this and the tv drops the
   socket ~1 ms after pair-verify.

2. **session/stream setup is the RTSP `SETUP rtsp://host/sessionId` METHOD** —
   not `POST /setup` (that's a 404), and it's preceded by a required
   `GET /info`.

3. **open the event channel, send RECORD in the owntone order.** tcp-connect to
   the `eventPort` from the session SETUP, and send **RECORD after the session
   SETUP / before the stream SETUP**. without the event channel open you get
   `RECORD=500` / `FLUSH=455`.

4. **the audio key (`shk`) = the first 32 bytes of the pairing shared secret,
   raw.** no HKDF. used directly as the ChaCha20-Poly1305 key for the audio
   payload **and** sent verbatim in the stream-SETUP plist. (see the
   **transient** note below — this is where macOS bit us.)

5. **ALAC is mandatory on the realtime stream.** the receiver hardcodes ALAC and
   ignores `ct` / `audioFormat`. send *uncompressed* ALAC frames
   (`audioFormat 0x40000`, `ct 2`, type `0x60`): MSB-first `3b stereo-CPE(=1) ·
   4b 0 · 12b 0 · 1b hasSize=0 · 2b 0 · 1b isNotCompressed=1 · 352×{L16,R16} ·
   3b END(=7) · byte-align`.

6. **the keep-alive IS the encrypted event channel.** after RECORD the tv tears
   the whole session down at ~25-30 s unless you decrypt the receiver's pushed
   `POST /command` (updateInfo) events and answer `200 OK`. the events keys are
   `HKDF "Events-Salt" / "Events-Write|Read-Encryption-Key"` over the pair-verify
   secret, **swapped** (reverse connection → eventIn decrypts with the WRITE
   key, eventOut encrypts with the READ key). `POST /feedback` must be
   `RTSP/1.0` (not HTTP/1.1) — but feedback alone is *not* the keep-alive, the
   event channel is.

7. **the 200-OK must be minimal.** `RTSP/1.0 200 OK\r\nServer: …\r\n[CSeq]\r\n\r\n`
   — and nothing else. adding `Audio-Latency: 0` or `Content-Length: 0` corrupts
   the receiver's realtime timeline → the session stays **connected** and renders
   **silence**. this was the final "stable but silent" bug: timing, sync and
   ALAC were all correct, the two extra response headers were the whole fault.

### the two pairing paths (and the macOS gotcha)

the audio key in step 4 is the *first 32 bytes of the pairing shared secret*.
that secret comes out at **different lengths** depending on how you paired:

- **pair-verify (Apple TV, on-screen PIN, `sf=0x644`):** X25519 ECDH = **32
  bytes**. use the whole thing.
- **HAP transient (MacBook / HomePod, `sf=0x4`):** pairing stops at pair-setup
  **M4** — no pair-verify — and the secret is the SRP session key
  `K = SHA-512(S) = 64 bytes`.

feed the full 64-byte `K` into a ChaCha key and it throws `chacha key size`
**every audio packet** → zero audio sent → the receiver drops the otherwise-
healthy session after its ~30 s no-audio timeout (the cover art + control
channel still work, because *those* keys are HKDF over the full K, which is
length-independent). **clamp the audio key to the first 32 bytes** — owntone's
`airplay.c` (`AIRPLAY_AUDIO_KEY_LEN = 32`) says it outright: *"for transient
pairing the key_len will be 64 bytes, but only 32 are used for audio payload
encryption."* the pair-verify secret is already 32 → the clamp is a no-op there.
that one line is the difference between "macbook shows the cover and is silent"
and "macbook plays".

## what's in the box

```
src/
  airplay_crypto.h / .cpp   the qt-free crypto + wire-format core
  raop_sender.h   / .cpp    the AP2 sender state machine (the recipe, in code)
  ring_buffer.h             the lock-free spsc tap the audio thread feeds
third_party/ed25519/        the one primitive mbed tls lacks (zlib, vendored)
```

**`airplay_crypto`** is the genuinely reusable, **Qt-free** core
(`std::vector<uint8_t>` + `std::string` only): SRP-6a-3072 / SHA-512, X25519
ECDH, Ed25519 sign/verify, ChaCha20-Poly1305 AEAD, HKDF-SHA512, HomeKit TLV8,
and a minimal `bplist00` encoder/decoder — exactly the pieces AP2 pairing +
the encrypted channels need, and nothing else. backed by **Mbed TLS 3.6**
(Apache-2.0) + orlp's **ed25519** (zlib). drop it in.

**`raop_sender`** is the state machine that *is* the recipe above — pairing,
the encrypted control channel, the event channel, the ALAC realtime encoder,
the keep-alive.

## status (read me)

this is **lifted, working, and verified** out of **FXChainPlayer**, where it
casts to a real Apple TV 4K (`AppleTV14,1`) and a MacBook every day. it is
**not yet a turn-key standalone library**: `raop_sender` currently does its
networking with **Qt** (`QTcpSocket` / `QUdpSocket` / `QTimer`) and pulls a
couple of host headers. the **roadmap** (`ROADMAP.md`) is to put the sockets
behind a ~3-method interface so the whole thing builds Qt-free, plus a
`airplay-send <host> <file.wav>` CLI demo. the **crypto core already builds on
its own** — that's the part you can use today; the sender is the reference you
follow.

if you want the polished player it lives in, here:

→ **https://github.com/akustikrausch/FXChainPlayer-Releases**

## license

**Apache-2.0** for everything in `src/`. © 2026 Andreas Wendorf (Akustikrausch).

apache-2.0 on purpose: this is *reverse-engineered apple-protocol* code, so the
license carries an **explicit patent grant** — embed it in a product without the
"is this safe to ship" patent worry that keeps MIT-licensed protocol code out of
corporate codebases. fully permissive, no copyleft; keep the `NOTICE`.

clean-room: the apple protocol was reconstructed from public reverse-engineering
work (owntone, pyatv, shairport-sync, emanuelecozzi's AP2 notes, the unofficial
airplay spec) read **as documentation only** — not a line of their code is here.
vendored deps keep their own licenses: **Mbed TLS** Apache-2.0, **ed25519** zlib.

---

*greetz to everyone who ever watched a socket close after one millisecond and
refused to let it win.*
