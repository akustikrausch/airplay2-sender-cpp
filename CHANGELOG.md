# changelog

## unreleased
- ROADMAP m1 (Qt-free sender): `raop_sender` no longer depends on Qt. all
  networking + timers go through a small `ITransport` seam (`src/itransport.h`);
  the default `PollTransport` is a portable poll()/select() loop (zero Qt), and
  an optional, off-by-default Qt adapter (`QtTransport`, `-DAIRPLAY_BUILD_QT_ADAPTER=ON`)
  keeps the existing Qt integration working. the old Qt signals are now
  `std::function` callbacks and the logger is a `std::function` sink; the
  `RaopDeviceInfo::Auth` enum (`raop_device_auth.h`) and the credentials JSON
  (`creds_json.h`) are inlined so the build no longer needs `mdns_discovery.h`
  or Qt JSON. behavior on the wire is unchanged. CI now builds the sender and
  runs a loopback handshake + transport test (`test/m1_verify.cpp`).
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
