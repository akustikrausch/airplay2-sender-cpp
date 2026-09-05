# airplay_send

the cli demo (roadmap m3): pair, set up, stream a wav or a tone, ctrl-c to
stop. built by default (`-DAIRPLAY_BUILD_EXAMPLE=ON`) as `airplay_send`.

    airplay_send <receiver-ip> [file.wav] [--atv | --mac | --ap1]
                 [--port N] [--name TEXT] [--volume 0..100]
                 [--creds FILE] [--strict] [--quiet]

- `--atv` (default): apple tv, on-screen pin. asked once; the credentials are
  saved to `airplay_creds_<ip>.json` (`--creds` picks another file).
- `--mac` / `--homepod`: transient pairing (pin 3939, no ui).
- `--ap1`: airplay 1, plain rtsp (shairport-sync, apple tv 3, raop speakers).
- the wav must be 16-bit pcm, mono or stereo, any sample rate (the sender
  resamples to 44.1 kHz): `ffmpeg -i in.mp3 -ac 2 -ar 44100 -c:a pcm_s16le out.wav`.
- `--strict`: fail closed on a bad receiver proof / signature.
- exit code 0 after a clean stop (ctrl-c), 1 when the session failed or the
  receiver ended it, 2 on a usage error.

what it shows: `RaopLoop` + `RaopSender` + a producer thread feeding the ring,
exactly the split a real player uses. read `airplay_send.cpp` as the
integration example; the README's "using the library" is the short form.
