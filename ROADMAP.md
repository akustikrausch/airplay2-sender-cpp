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

## the path to standalone

three milestones, in order. **m1 is the keystone** (it unblocks the demo); m2 is
cleanup; m3 is the payoff.

### m1: make the sender Qt-free

`raop_sender` does its networking with Qt today (`QTcpSocket` / `QUdpSocket` /
`QTimer`). put it behind a small transport interface and the dependency drops
straight out:

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
to one small adapter. a portable poll/`select` adapter ships as the default.

### m2: drop the host glue

- `mdns_discovery.h` is only there for the `RaopDeviceInfo::Auth` enum + bonjour
  discovery of receivers. fold the enum in; ship a tiny mDNS browser (or let the
  caller pass an already-resolved host + the `sf` flags).
- `common/logger.h` becomes a one-line `std::function<void(level, msg)>` sink.
- `common/ring_buffer.h` is already self-contained (it lives in `src/`).

### m3: the demo

`airplay-send <host> <file.wav>`: pair, set up, stream a wav, ctrl-c to stop. the
thing you actually clone and run to prove it on your own couch in 30 seconds.

## later / maybe

- buffered stream (type 103, TCP) alongside realtime (type 96, UDP).
- AAC / Opus on receivers that advertise it (realtime is hardcoded-ALAC).
- multi-room / grouped output.

## want to help?

**m1 is the one that matters.** the transport interface is tiny, self-contained,
and unblocks everything downstream. got a clean poll/`select` (or asio / libuv)
adapter, or an mDNS browser for m2? those are the highest-leverage PRs you can
send. open an issue and let's talk.
