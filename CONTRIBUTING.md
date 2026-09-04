# contributing

## contribution policy (read this first)

this project is written and maintained by one person on purpose, and it does
**not merge outside code**, the same stance sqlite takes. the reason is the
license story: this is a clean-room / ported reimplementation of a
reverse-engineered protocol, and that story is easiest to keep straight when
every line in `src/` has one known origin. a pull request will be closed with a
thank-you; where it carries a finding, the finding gets implemented here and
credited in `CHANGELOG.md`.

what IS wanted, and what actually moves the project:

- **bug reports and protocol findings** as issues: receiver model + os, the
  `sf=` feature flag from its mdns txt record, the symptom ("refused at SETUP",
  "connects but silent", "drops at ~30 s"), and the handshake log. that is
  usually the whole answer.
- **wire observations** from receivers the maintainer does not own (homepod
  mini, older apple tvs, third-party airplay 2 speakers).
- **hardware reports** for the qt-free build: `airplay_send` against your
  receiver, success or failure, with the log.

if you want to build on the code, fork it. it is Apache-2.0 and the whole point
of the license choice is that you can ship it.

## the rule for the code itself: stay clean-room

this project reconstructs a reverse-engineered protocol. its license story only
holds if we are careful about where code comes from:

- the **crypto/wire-format core** (`src/airplay_crypto.*`) is **clean-room**,
  written from public reverse-engineering work read *as documentation only*.
  no code from owntone, shairport-sync, pyatv, pair_ap, or any other
  implementation goes in. byte formats and constants (the facts on the wire)
  are fine; their *source code* is not.
- the **RAOP transport** (`src/raop_sender.cpp`) is openly credited as a C++
  **port of pyatv** (MIT) in `licenses/THIRD-PARTY-NOTICES.txt`. logic derived
  from another project brings the matching license + attribution with it.
  **never** from a GPL/AGPL source (owntone's daapd lineage, RAOP-Player,
  etc.), that would poison the Apache-2.0 license for everyone.

when in doubt, describe the protocol behaviour in your own words (an issue is
the right place) and it gets implemented from that.

## practical bits

- build + test: `cmake -B build && cmake --build build && ctest --test-dir build`.
- the protocol tests need no network; the loop tests bind loopback sockets.
- keep the prose voice as-is (lowercase, plain). no em-dashes in comments/docs.
- commits carry no AI-attribution / `Co-Authored-By` trailers.

## security

see `SECURITY.md`.
