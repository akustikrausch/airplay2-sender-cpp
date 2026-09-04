# roadmap

the crypto core has stood on its own from day one. the sender now does too:
`git clone && cmake && run` is real, and there is no Qt anywhere in the
standalone build.

## done

- the whole AP2 realtime recipe, verified live against a real **Apple TV 4K**, a
  **HomePod**, and a **macOS** receiver (the full story is in the README).
- `airplay_crypto`: the Qt-free crypto + wire-format core.
- the transient/macOS **32-byte audio-key clamp**, the last-mile fix that turned
  "macbook shows the cover and stays silent" into "macbook plays".
- **m1, the Qt-free sender.** `raop_sender` is a sans-i/o state machine: it
  sends through the six-method `RaopIo` seam (`src/raop_io.h`) and the host
  pushes bytes, datagrams and ticks back in. `RaopLoop` is the bundled
  poll()/WSAPoll() host (linux, macos, windows); `RaopQtHost` the optional one
  for an app that already runs Qt.
- **m2, the host glue.** the `RaopDeviceInfo::Auth` enum lives in
  `raop_auth.h`, the logger is a `std::function` sink (`raop_log.h`), the
  credentials blob is plain json (`raop_creds.h`, byte-compatible with what the
  Qt build stored).
- **m3, the demo.** `airplay_send <ip> [file.wav]`: pair, set up, stream, ctrl-c.
- a test suite that walks both handshakes byte for byte against an in-process
  fake receiver (an SRP server, pair-setup M1..M6, pair-verify, the encrypted
  control + event channels, encrypted ALAC audio, the mac / apple tv fallbacks),
  plus loopback socket tests. ci on linux (gcc, clang, asan+ubsan), macos and
  windows (msvc).
- the sender identity (name, deviceID/mac, model) is configurable, and the
  receiver's proof / signature can fail closed (`setStrictReceiverAuth`).

## next

1. **a real-hardware pass of the Qt-free build**: `airplay_send` against the
   Apple TV 4K, the HomePod and the MacBook, and FXChainPlayer switched over to
   `RaopQtHost`. the wire bytes are the verified ones and the tests pin them,
   but a fresh listen is the proof.
2. **a bundled mDNS browser** (`_raop._tcp` / `_airplay._tcp` -> host, port,
   the `sf` flags -> `RaopDeviceInfo::Auth`), so a caller without its own
   discovery can find receivers. until then you pass the ip.
3. **fail-closed receiver auth by default**, once strict mode has been run
   against real receivers.

## later / maybe

- buffered stream (type 103, TCP) alongside realtime (type 96, UDP).
- AAC / Opus on receivers that advertise it (realtime is hardcoded-ALAC).
- multi-room / grouped output.
- a windowed-sinc resampler (the cast path lerps today).

## want to help?

open an issue: receiver models, `sf` flags, handshake logs and "connects but
silent" reports are what move this project. code lands here single-author; see
`CONTRIBUTING.md` for why, and for how a report gets credited.
