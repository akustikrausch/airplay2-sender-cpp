# AirPlay 2 Sender (C++)

**by Akustikrausch (Andreas Wendorf)**

<p>
  <a href="https://github.com/akustikrausch/airplay2-sender-cpp/actions/workflows/ci.yml"><img src="https://github.com/akustikrausch/airplay2-sender-cpp/actions/workflows/ci.yml/badge.svg" alt="ci"></a>
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
today. bidirectional volume, seamless track changes, the works.

this is the part of the apple-tax that nobody published. you can find a hundred
*receivers*. you can find python. you cannot find a small c++ thing that just
**sends** AirPlay 2 realtime audio to a current apple device and keeps the
session alive. so here it is, with the entire recipe written down.

> 🎧 **this code ships in a real product: [FXChainPlayer](https://github.com/akustikrausch/FXChainPlayer-Releases).**
> a native windows audio player that casts straight to your apple tv / homepod /
> macbook over AirPlay 2. that's where this sender runs every day, against real
> hardware. go grab the player to hear it, or read on for the protocol.

## why this exists

the open AirPlay landscape is all receiver, wrong language, or stuck in 2014:

- **shairport-sync** is a *receiver*. brilliant, but the other direction.
- **owntone** (forked-daapd) is a whole media server, not a sender library. it
  *can* send, but you don't drop it into your app.
- **pyatv** is python, and a client/control library, not a c++ realtime audio
  pipe.
- **AirConnect / raop_play / the old shairport "client" forks** do AirPlay **1**
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

1. **pair, then an encrypted RTSP control channel, immediately.** right after
   pair-verify, every RTSP request/response rides ChaCha20-Poly1305. frame =
   `[2-byte LE len][cipher][16-byte tag]`, chunk ≤ 1024 B, AAD = the length
   prefix, nonce = `[4 zero bytes][8-byte LE counter]`, separate send/recv
   counters (Control-Write / Control-Read keys). skip this and the tv drops the
   socket ~1 ms after pair-verify.

2. **session/stream setup is the RTSP `SETUP rtsp://host/sessionId` METHOD**,
   not `POST /setup` (that's a 404), and it's preceded by a required
   `GET /info`.

3. **open the event channel, send RECORD in the owntone order.** tcp-connect to
   the `eventPort` from the session SETUP, and send **RECORD after the session
   SETUP / before the stream SETUP**. without the event channel open you get
   `RECORD=500` / `FLUSH=455`.

4. **the audio key (`shk`) = the first 32 bytes of the pairing shared secret,
   raw.** no HKDF. used directly as the ChaCha20-Poly1305 key for the audio
   payload **and** sent verbatim in the stream-SETUP plist. (see the
   **transient** note below; this is where macOS bit us.)

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
   `RTSP/1.0` (not HTTP/1.1), but feedback alone is *not* the keep-alive, the
   event channel is.

7. **the 200-OK must be minimal.** `RTSP/1.0 200 OK\r\nServer: …\r\n[CSeq]\r\n\r\n`,
   and nothing else. adding `Audio-Latency: 0` or `Content-Length: 0` corrupts
   the receiver's realtime timeline → the session stays **connected** and renders
   **silence**. this was the final "stable but silent" bug: timing, sync and
   ALAC were all correct, the two extra response headers were the whole fault.

### the two pairing paths (and the macOS gotcha)

the audio key in step 4 is the *first 32 bytes of the pairing shared secret*.
that secret comes out at **different lengths** depending on how you paired:

- **pair-verify (Apple TV, on-screen PIN, `sf=0x644`):** X25519 ECDH = **32
  bytes**. use the whole thing.
- **HAP transient (MacBook / HomePod, `sf=0x4`):** pairing stops at pair-setup
  **M4** (no pair-verify), and the secret is the SRP session key
  `K = SHA-512(S) = 64 bytes`.

feed the full 64-byte `K` into a ChaCha key and it throws `chacha key size`
**every audio packet** → zero audio sent → the receiver drops the otherwise
healthy session after its ~30 s no-audio timeout (the cover art + control
channel still work, because *those* keys are HKDF over the full K, which is
length-independent). **clamp the audio key to the first 32 bytes.** owntone's
`airplay.c` (`AIRPLAY_AUDIO_KEY_LEN = 32`) says it outright: *"for transient
pairing the key_len will be 64 bytes, but only 32 are used for audio payload
encryption."* the pair-verify secret is already 32, so the clamp is a no-op there.
that one line is the difference between "macbook shows the cover and is silent"
and "macbook plays".

## what's in the box

```
src/
  airplay_crypto.h / .cpp   the qt-free crypto + wire-format core
  raop_sender.h   / .cpp    the AP2 sender state machine (the recipe, in code), sans-i/o
  raop_io.h                 the six-method seam the sender sends through
  raop_loop.h     / .cpp    the bundled poll()/WSAPoll() host: sockets + the run loop
  raop_qt_host.h  / .cpp    optional: the same host on Qt sockets (off by default)
  raop_auth.h               how a receiver wants to be authenticated (the Auth enum)
  raop_creds.h              the stored-pairing credentials blob (json, no qt)
  raop_log.h                the log sink + a tiny "{}" formatter
  ring_buffer.h             the lock-free spsc tap the audio thread feeds
example/airplay_send.cpp    the cli demo: pair, set up, stream a wav
test/core_tests.cpp         the protocol core against an in-process fake receiver
test/loop_tests.cpp         the poll host against a real loopback receiver
third_party/ed25519/        the one primitive mbed tls lacks (zlib, vendored)
```

**`airplay_crypto`** is the genuinely reusable, **Qt-free** core
(`std::vector<uint8_t>` + `std::string` only): SRP-6a-3072 / SHA-512, X25519
ECDH, Ed25519 sign/verify, ChaCha20-Poly1305 AEAD, HKDF-SHA512, HomeKit TLV8,
and a minimal `bplist00` encoder/decoder, exactly the pieces AP2 pairing +
the encrypted channels need, and nothing else. backed by **Mbed TLS 3.6**
(Apache-2.0) + orlp's **ed25519** (zlib). drop it in.

**`raop_sender`** is the state machine that *is* the recipe above: pairing,
the encrypted control channel, the event channel, the ALAC realtime encoder,
the keep-alive. it is **sans-i/o**: it owns no socket, no timer and no thread.
it sends through `RaopIo` (six methods: tcp connect / send / close, udp bind /
send / close) and the host pushes back in what happened (`onTcpData`,
`onUdpDatagram`, `tick`). that is what makes it a drop-in: `RaopLoop` is the
bundled portable host, `RaopQtHost` the optional one for an app that already
runs Qt, and a test can drive the whole handshake with a fake host and no
network at all.

## build + run

you need cmake 3.16+ and a c++20 compiler: gcc 10+, clang 12+, apple clang 13+
(xcode 13), msvc 2019 16.10+ / 2022. mbed tls is fetched at configure time
(network needed once); ed25519 is vendored. nothing else.

```
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel
ctest --test-dir build --output-on-failure
```

that builds `airplay_crypto`, `raop_sender` (core + host), the `airplay_send`
demo and the two test binaries. ci runs exactly this on linux (gcc, clang,
asan+ubsan), macos and windows (msvc).

### the demo

```
./build/airplay_send <receiver-ip> [file.wav] [--atv | --mac | --ap1] [--name TEXT] [--volume 0..100] [--strict]
```

- `--atv` (default): apple tv, hap pairing with the on-screen pin. the pin is
  asked once; the long-term credentials are saved next to the binary
  (`airplay_creds_<ip>.json`) and later runs skip it.
- `--mac` / `--homepod`: hap transient pairing, no pin.
- `--ap1`: airplay 1, plain rtsp (shairport-sync, apple tv 3, raop speakers).
- no file: a 440 Hz test tone. a wav needs 16-bit pcm, mono or stereo, any rate.
- ctrl-c sends TEARDOWN and exits.

the receiver's ip comes from mdns (`dns-sd -B _raop._tcp` on a mac,
`avahi-browse _raop._tcp` on linux, or the receiver's network settings); a
bundled browser is the one open roadmap item.

### the windows / vm gotcha (firewall + udp)

the receiver does not only answer on the tcp control channel: it sends
*unsolicited inbound udp* to the sender's timing and control ports (the
ntp-style clock sync that the ap2 session SETUP waits for, later the
retransmit requests). windows firewall drops unsolicited inbound udp by
default, so the handshake stalls at the session SETUP and times out. allow
inbound udp for the program (a per-program rule is enough). a nat'd vm fails
the same way; use bridged networking. `airplay_send` prints this hint on a
handshake timeout. (diagnosed on a windows vm by @rursache in #1, thanks.)

### using the library

```cpp
RaopLoop   loop;                       // or RaopQtHost inside a Qt app
RaopSender sender(loop, events, log);  // events: launched / closed / pinRequired / credentialsObtained
sender.attachRing(&ring);              // your audio thread feeds the ring (16-bit stereo, any rate)
sender.setInputFormat(48000);
sender.setIdentity({"my player", "AA:BB:CC:DD:EE:FF", "iPhone14,3"});
sender.setAuth(RaopDeviceInfo::Auth::HapPin, /*airplay2=*/true, deviceId, storedCredsJson, "");
sender.start(ip, 7000, "Living Room");
loop.run(sender);                      // until loop.requestStop(); sender.stop() sends TEARDOWN
```

## status (read me)

this is **lifted, working, and verified** out of **FXChainPlayer**, where it
casts to a real Apple TV 4K (`AppleTV14,1`) and a MacBook every day. roadmap
**m1..m3 have landed**: the sender is a **standalone, Qt-free library**. the
state machine is sans-i/o, the bundled `RaopLoop` drives it on linux, macos and
windows, `airplay_send` is the runnable proof, and the test suite walks the
complete ap1 and ap2 handshakes (pair-setup, pair-verify, the encrypted control
channel, the event channel, encrypted alac audio) against an in-process fake
receiver, byte for byte.

honest caveat: the wire bytes are the verified Qt build's and the tests pin
them, but the Qt-free build itself has not had its fresh listen against the
apple tv / macbook yet. that is the first item in `ROADMAP.md`. still open
after that: a bundled mdns browser (you pass the receiver's ip today) and
fail-closed receiver auth by default (available as an option, see security).

if you want the polished player it lives in, here:

→ **https://github.com/akustikrausch/FXChainPlayer-Releases**

## security (scope, read me)

this is interoperability research, not an audited production security stack. one
thing worth owning up front: the **sender does not yet cryptographically
authenticate the receiver's identity**. the pair-verify signature and SRP proof
checks currently *log-and-continue* rather than fail-closed, so a same-LAN
man-in-the-middle could in principle accept your session and you'd stream to it
(you'd leak the audio + the transient session key, not take attacker data into a
trust boundary, it's a *sender*). the untrusted-input parsers (bplist / TLV8 /
RTSP / the encrypted event frames) ARE bounds-checked against OOB + alloc-DoS,
and the AEAD usage is authenticate-before-use with per-channel keys + counters.

bottom line: **use it on a network you trust.** since m1 the checks can fail
closed: `RaopSender::setStrictReceiverAuth(true)` (`airplay_send --strict`)
aborts the session on a wrong or missing proof / signature. it is opt-in until
it has been confirmed against real receivers; making it the default is on the
roadmap. report anything via `SECURITY.md`.

## license

**Apache-2.0** for everything in `src/`. © 2026 Andreas Wendorf (Akustikrausch).

apache-2.0 on purpose: this is *reverse-engineered apple-protocol* code, so the
license carries an **explicit patent grant**, so you can embed it in a product
without the "is this safe to ship" patent worry that keeps MIT-licensed protocol
code out of corporate codebases. fully permissive, no copyleft; keep the `NOTICE`.

provenance, split honestly:
- the **crypto + wire-format core** (`airplay_crypto.*`) is **clean-room**,
  reconstructed by reading owntone / pyatv / shairport-sync / pair_ap /
  emanuelecozzi's AP2 notes / the unofficial spec **as documentation only**. no
  upstream code is copied into it; only the on-the-wire byte formats.
- the **RAOP / AirPlay transport** in `raop_sender.cpp` is in part a **C++ port
  of pyatv** (MIT, © 2020 Pierre Ståhl), its RTSP/RTP/sync/timing model + the
  HAP pairing sequence follow pyatv's modules. no python is bundled; pyatv's MIT
  notice rides along in [`licenses/THIRD-PARTY-NOTICES.txt`](licenses/THIRD-PARTY-NOTICES.txt).

vendored / build deps keep their own licenses: **Mbed TLS** Apache-2.0,
**ed25519** zlib, same file has the details.

## disclaimer

not affiliated with, authorized by, or endorsed by **Apple Inc.** *AirPlay*,
*Apple TV*, *HomePod*, *HomeKit* and *macOS* are trademarks of Apple Inc., used
here only to describe what this code talks to. nothing here ships an apple key,
certificate, or any extracted firmware; it's a clean-room client of a network
protocol, for interoperability with **your own** devices. use it on hardware you
own and are allowed to use.

this is interoperability work in the legal sense: it relies on the
decompilation / interoperability right under **article 6 of eu directive
2009/24/ec** (the *software directive*), reimplements the protocol clean-room,
and ships none of apple's code, keys, or certificates.


