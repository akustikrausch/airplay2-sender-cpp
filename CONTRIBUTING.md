# contributing

prs and issues welcome. this is a small, focused project, the fastest way in is
to read the README recipe + `ROADMAP.md`, then pick the thing that unblocks the
most: **m1, the Qt-free transport interface.**

## the one rule that actually matters: stay clean-room

this project reconstructs a reverse-engineered protocol. its license story only
holds if we are careful about where code comes from:

- the **crypto/wire-format core** (`src/airplay_crypto.*`) is **clean-room**,
  written from public reverse-engineering work read *as documentation only*.
  **do not paste code into it** from owntone, shairport-sync, pyatv, pair_ap, or
  any other implementation. byte formats and constants (the facts on the wire)
  are fine; their *source code* is not.
- the **RAOP transport** (`src/raop_sender.cpp`) is openly credited as a C++
  **port of pyatv** (MIT) in `licenses/THIRD-PARTY-NOTICES.txt`. if you extend
  it with logic derived from another project, say so in the PR and bring the
  matching license + attribution with it. **never** copy from a GPL/AGPL source
  (owntone's daapd lineage, RAOP-Player, etc.), that would poison the
  Apache-2.0 license for everyone.

when in doubt, describe the protocol behaviour in your own words and implement
from that. if you're unsure whether something is OK to bring in, open an issue
first and ask.

## practical bits

- build the crypto core: `cmake -B build && cmake --build build --target airplay_crypto`.
- keep the prose voice as-is (lowercase, plain). no em-dashes in comments/docs.
- authorship: commits are by their author; no AI-attribution / `Co-Authored-By`
  trailers, please.
- a good bug report (see the issue template) names the **receiver model**, the
  **`sf=` feature flag**, and the **symptom** ("connects but silent", "drops at
  ~30 s", "refused at SETUP"), that's usually enough to locate it in the recipe.

## security

see `SECURITY.md`. the headline open item (fail-closed receiver authentication)
is a genuinely good, well-scoped first contribution.
