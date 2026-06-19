---
name: Bug report
about: A receiver that won't pair / connects but plays silence / drops mid-stream
title: ''
labels: bug
assignees: ''
---

**receiver**
- model + OS: <!-- e.g. Apple TV 4K (tvOS 18.2) / HomePod mini / MacBook (macOS 15) / shairport-sync -->
- the `sf=` feature flag it advertises (from its mDNS TXT, if you have it): <!-- e.g. sf=0x644 / sf=0x4 -->

**symptom** (pick the closest)
- [ ] refused / errored during pairing or SETUP
- [ ] pairs + connects, but plays **silence**
- [ ] plays, then **drops after ~30 s**
- [ ] audio plays but is glitchy / drifts
- [ ] other:

**what happened**
<!-- one or two sentences. -->

**logs**
<!-- the handshake log if you have one: which RTSP method got which status code,
and where it stalled. that's usually the whole answer. -->

**which step of the README recipe** (if you know): <!-- 1-7, or "no idea" -->
