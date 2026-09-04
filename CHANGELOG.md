# changelog

## unreleased
- **m1..m3 landed: the sender is standalone and Qt-free.** `raop_sender` is now
  a sans-i/o state machine (no socket, timer or thread of its own) behind the
  six-method `RaopIo` seam (`raop_io.h`); `RaopLoop` (`raop_loop.*`) is the
  bundled poll()/WSAPoll() host for linux, macos and windows, `RaopQtHost`
  (`raop_qt_host.*`, off by default) the adapter for a Qt app. the Qt signals
  became `RaopEvents` callbacks. nothing on the wire changed.
- `example/airplay_send`: the cli demo (pair with pin / transient / airplay 1,
  stream a wav or a tone, stored credentials, ctrl-c teardown).
- host glue folded in: `raop_auth.h` (the Auth enum), `raop_log.h` (a
  std::function sink + a small "{}" formatter, no `<format>` needed),
  `raop_creds.h` (the credentials json, byte-identical to the Qt build's).
- `RaopSender::setIdentity()`: the name the receiver shows, the deviceID/mac
  and the model are configurable (CR/LF stripped); the default name is
  "airplay2-sender-cpp" instead of a product name.
- `RaopSender::setStrictReceiverAuth()` / `airplay_send --strict`: opt-in
  fail-closed check of the receiver's SRP proof and pair-verify signature.
- a receiver-initiated close now releases every session socket, and `start()`
  after it works without leaking. hostnames resolve once, in the host; the
  resolved peer ip is used for the udp sends and the sdp.
- tests: `raop_core_tests` (in-process fake receiver: AP1 handshake + audio /
  sync / timing / retransmit, AP2 transient, AP2 pin pairing + credentials +
  pair-verify reconnect, encrypted control + event channels, encrypted ALAC,
  strict auth, digest auth, the mac / apple tv fallbacks, failure paths) and
  `raop_loop_tests` (real loopback sockets). ci: linux gcc / clang / sanitizers,
  macos, windows msvc.
- docs: build + run, the windows firewall / udp note (diagnosed by @rursache
  in #1), the contribution policy.
- build: mbed tls pinned by commit, `MBEDTLS_FATAL_WARNINGS` off so a bare
  `cmake --build` works on newer compilers; `.gitattributes` forces lf.
- provenance made precise: the crypto/wire-format core is clean-room; the
  RAOP/AP2 transport in `raop_sender.cpp` is credited as a C++ port of pyatv
  (MIT). pyatv's MIT notice now ships in `licenses/THIRD-PARTY-NOTICES.txt`.
- added `## security` scope note (sender does not yet authenticate the receiver;
  trusted-LAN use), plus `SECURITY.md`, `CONTRIBUTING.md` (with the clean-room
  rule), an issue template, and a CI build of the crypto core.
- hardening: bplist UTF-16 length DoS-bound; pair-verify empty-shared-secret
  guard. ed25519 build now matches its SOURCE.md (drops seed.c / `ED25519_NO_SEED`).
- initial extraction from FXChainPlayer: the verified AirPlay 2 realtime sender
  + the Qt-free crypto/wire-format core.
- README carries the complete seven-step AP2 realtime recipe + the
  pair-verify-vs-transient audio-key story (the macOS 32-byte clamp).
- Apache-2.0 (explicit patent grant for the reverse-engineered protocol); vendored ed25519 (zlib); Mbed TLS (Apache-2.0) at build time.
- trademark / non-affiliation disclaimer added to README + NOTICE (Apple Inc.
  marks used nominatively; clean-room interoperability client, ships no apple
  keys/certs/firmware).
