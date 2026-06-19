# roadmap

what's done, and what stands between "lifted out of a working player" and
"drop-in standalone library".

## done
- the whole AP2 realtime recipe, verified against a real Apple TV 4K + HomePod
  + a macOS receiver (see README).
- `airplay_crypto`, the Qt-free crypto + wire-format core. builds on its own.
- the transient/macOS 32-byte audio-key clamp (the last-mile fix).

## next: make the sender Qt-free
`raop_sender` does its networking with Qt today (`QTcpSocket` / `QUdpSocket` /
`QTimer`). the plan is a ~3-method transport interface:

```cpp
struct ITransport {
    virtual int   tcpConnect(host, port) = 0;          // -> handle
    virtual int   send(handle, span<const uint8_t>) = 0;
    virtual int   recv(handle, span<uint8_t>) = 0;      // non-blocking-ish
    virtual void  close(handle) = 0;
    virtual void  every(ms, fn) = 0;                    // the ~16 ms pacer + keep-alive
};
```

with that, the sender is plain C++ + `airplay_crypto`; the Qt build becomes one
small adapter. a poll/`select` adapter ships as the default.

## next: drop the host glue
- `mdns_discovery.h` is only needed for the `RaopDeviceInfo::Auth` enum + the
  bonjour discovery of receivers. fold the enum in; ship a tiny mDNS browser
  (or let the caller pass a resolved host + the `sf` flags).
- `common/logger.h` → a one-line `std::function<void(level, msg)>` sink.
- `common/ring_buffer.h` is already self-contained (it's in `src/`).

## next: the demo
`airplay-send <host> <file.wav>`: pair, set up, stream a wav, ctrl-c to stop.
the thing you actually `git clone && cmake && run` to prove it on your couch.

## maybe later
- buffered stream (type 103, TCP) in addition to realtime (type 96, UDP).
- AAC/Opus on receivers that advertise it (realtime is hardcoded-ALAC).
- multi-room / grouped output.
