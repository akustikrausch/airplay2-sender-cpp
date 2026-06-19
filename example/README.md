# example (roadmap)

the `airplay-send <host> <file.wav>` CLI demo lands once the Qt-free transport
interface (see `../ROADMAP.md`) is in place.

until then, the working sender is `../src/raop_sender.{h,cpp}` as it runs inside
FXChainPlayer, and the **README recipe** is the map. the crypto core
(`../src/airplay_crypto.*`) you can use today — build it with the top-level
`CMakeLists.txt` and link `airplay_crypto`.
