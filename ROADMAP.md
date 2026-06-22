# roadmap

the crypto core already stands on its own. the goal here is to walk the rest of
the sender the last mile: from "lifted out of a working player" to a **drop-in,
Qt-free standalone library** you can `git clone && cmake && run`.

## done

- the whole AP2 realtime recipe, verified live against a real **Apple TV 4K**, a
  **HomePod**, and a **macOS** receiver (the full story is in the README).
- `airplay_crypto`: the Qt-free crypto + wire-format core. compiles and links on
  its own today, no Qt, no app around it.
- the transient/macOS **32-byte audio-key clamp**, the last-mile fix that turned
  "macbook shows the cover and stays silent" into "macbook plays".
- **m1, the Qt-free sender** (see below): `raop_sender` now drives networking +
  timers through the `ITransport` seam, with a default poll/select adapter and
  an optional Qt one. no Qt in the standalone build.

## the path to standalone

three milestones, in order. **m1 is the keystone** (it unblocks the demo); m2 is
cleanup; m3 is the payoff.

### m1: make the sender Qt-free **(landed)**

`raop_sender` used to do its networking with Qt (`QTcpSocket` / `QUdpSocket` /
`QTimer`). it now sits behind a small transport interface and the dependency
drops straight out:

```cpp
struct ITransport {
    virtual int  tcpConnect(host, port)         = 0;  // -> handle
    virtual int  send(handle, span<const u8>)   = 0;
    virtual int  recv(handle, span<u8>)         = 0;  // non-blocking-ish
    virtual void close(handle)                  = 0;
    virtual void every(ms, fn)                  = 0;  // the ~16 ms pacer + keep-alive
};
```

with that, the sender is plain C++ + `airplay_crypto`, and the Qt build collapses
to one small adapter. the real interface (`src/itransport.h`) is a little richer
than this sketch (UDP needs sendto/recvfrom with the peer address for the timing
+ retransmit replies, plus local-port readback and one-shot timers). the portable
`PollTransport` poll/`select` adapter ships as the default; `QtTransport` is the
optional Qt one.

### m2: drop the host glue

- **done.** the `RaopDeviceInfo::Auth` enum is folded into `raop_device_auth.h`,
  so `mdns_discovery.h` is gone. the caller passes an already-resolved host + the
  matching `Auth` value to `setAuth()`.
- **done.** `common/logger.h` is now a one-line `std::function<void(level, msg)>`
  sink (`logging.h`).
- `common/ring_buffer.h` is already self-contained (it lives in `src/`).
- still open: a tiny bundled mDNS browser, so a caller without its own discovery
  can find receivers + their `sf` flags.

### m3: the demo

`airplay-send <host> <file.wav>`: pair, set up, stream a wav, ctrl-c to stop. the
thing you actually clone and run to prove it on your own couch in 30 seconds.

## later / maybe

- buffered stream (type 103, TCP) alongside realtime (type 96, UDP).
- AAC / Opus on receivers that advertise it (realtime is hardcoded-ALAC).
- multi-room / grouped output.

## want to help?

m1 landed, so the highest-leverage PRs now are **m3 (the `airplay-send` CLI demo,
on top of `PollTransport`)** and the **mDNS browser** that finishes m2. an extra
`ITransport` adapter (asio / libuv) is also welcome. open an issue and let's talk.
