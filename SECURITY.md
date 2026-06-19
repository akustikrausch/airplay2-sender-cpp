# security policy

## scope (read this first)

this is **interoperability research**, a clean-room/ported client of a
reverse-engineered network protocol. it is **not** an audited production
security stack. use it on networks you trust.

### known, scoped limitation: the sender does not authenticate the receiver

right now the pair-verify Ed25519 signature check and the SRP M5 proof check
**log-and-continue** instead of failing closed (`src/raop_sender.cpp`). a
same-LAN man-in-the-middle could accept your session and you would stream to it.
because this is a *sender*, the blast radius is **outbound**: you leak your audio
and the transient session key, you do not take attacker-controlled data across
a trust boundary. making these checks fail-closed is a tracked TODO and a good
first PR (see `ROADMAP.md`).

what IS defended: the untrusted-input parsers (bplist00 / TLV8 / RTSP / the
encrypted event-channel frames) are bounds-checked against out-of-bounds reads,
integer overflow, and unbounded-allocation DoS; AEAD is authenticate-before-use
with a distinct key + monotonic counter per channel.

## reporting a vulnerability

found something? please **do not** open a public issue for an exploitable bug.
email the maintainer at **akustikrausch@gmail.com** with details and, if you
can, a reproduction. you'll get an acknowledgement; fixes land on `main` and are
credited in `CHANGELOG.md` unless you'd rather stay anonymous.

for non-exploitable hardening ideas, a normal issue or PR is perfect.
