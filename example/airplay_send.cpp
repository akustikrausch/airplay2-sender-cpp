// SPDX-License-Identifier: Apache-2.0
//
// airplay_send -- stream a WAV (or a built-in test tone) to an AirPlay
// receiver through RaopSender + the Qt-free PollTransport. this is the
// ROADMAP m3 demo: the thing you clone, build, and run to prove the sender on
// real hardware (Apple TV / HomePod / a Mac AirPlay receiver).
//
//   airplay_send <host-ip> [file.wav] [--atv|--mac|--ap1] [--port N]
//                [--name NAME] [--vol 0-100] [--creds FILE]
//
// no file -> a 440 Hz tone. --atv = HAP on-screen PIN (Apple TV); --mac =
// HAP transient (Mac / HomePod, PIN 3939); --ap1 = legacy unencrypted RAOP
// (shairport-sync etc). a producer thread feeds PCM into the lock-free ring
// the sender drains, exactly the cross-thread split the library is built for.

#include "raop_sender.h"
#include "poll_transport.h"
#include "ring_buffer.h"

#include <atomic>
#include <chrono>
#include <cmath>
#include <csignal>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iostream>
#include <iterator>
#include <span>
#include <string>
#include <thread>
#include <vector>

using namespace fxchain;

namespace {

std::atomic<bool> g_sigint{false};
void onSigint(int) { g_sigint = true; }

std::string readFile(const std::string& p) {
    std::ifstream f(p, std::ios::binary);
    return f ? std::string((std::istreambuf_iterator<char>(f)),
                           std::istreambuf_iterator<char>())
             : std::string();
}
void writeFile(const std::string& p, const std::string& s) {
    std::ofstream f(p, std::ios::trunc | std::ios::binary);
    f << s;
}

// load a 16-bit PCM WAV into interleaved-stereo samples at its native rate.
bool loadWav(const std::string& path, std::vector<int16_t>& out,
             uint32_t& rate, std::string& err) {
    const std::string buf = readFile(path);
    if (buf.size() < 44 || buf.compare(0, 4, "RIFF") || buf.compare(8, 4, "WAVE")) {
        err = "not a RIFF/WAVE file"; return false;
    }
    uint16_t fmt = 0, ch = 0, bits = 0;
    uint32_t sr = 0;
    size_t dataOff = 0, dataLen = 0, p = 12;
    auto rd16 = [&](size_t o) { uint16_t v; std::memcpy(&v, buf.data() + o, 2); return v; };
    auto rd32 = [&](size_t o) { uint32_t v; std::memcpy(&v, buf.data() + o, 4); return v; };
    while (p + 8 <= buf.size()) {
        const size_t body = p + 8;
        const uint32_t sz = rd32(p + 4);
        if (!buf.compare(p, 4, "fmt ") && body + 16 <= buf.size()) {
            fmt = rd16(body); ch = rd16(body + 2); sr = rd32(body + 4); bits = rd16(body + 14);
        } else if (!buf.compare(p, 4, "data")) {
            dataOff = body; dataLen = std::min(size_t(sz), buf.size() - body);
        }
        p = body + sz + (sz & 1);   // chunks are word-aligned
    }
    if (fmt != 1 || bits != 16 || ch < 1 || ch > 2 || sr == 0 || dataOff == 0) {
        err = "need a 16-bit PCM mono/stereo WAV. convert with:\n"
              "  afconvert -f WAVE -d LEI16@44100 -c 2 in.mp3 out.wav   (macOS)\n"
              "  ffmpeg -i in.mp3 -ac 2 -ar 44100 -c:a pcm_s16le out.wav";
        return false;
    }
    const auto* s = reinterpret_cast<const int16_t*>(buf.data() + dataOff);
    const size_t n = dataLen / 2;
    out.clear();
    if (ch == 2) {
        out.assign(s, s + n);
    } else {
        out.reserve(n * 2);
        for (size_t i = 0; i < n; ++i) { out.push_back(s[i]); out.push_back(s[i]); }
    }
    rate = sr;
    return true;
}

void makeTone(std::vector<int16_t>& out, uint32_t& rate) {
    rate = 44100;
    const int secs = 10;
    out.resize(size_t(rate) * secs * 2);
    const double twoPiF = 2.0 * 3.14159265358979323846 * 440.0;
    for (uint32_t i = 0; i < rate * secs; ++i) {
        const auto v = int16_t(8000.0 * std::sin(twoPiF * i / rate));
        out[i * 2] = v;
        out[i * 2 + 1] = v;
    }
}

} // namespace

int main(int argc, char** argv) {
    std::string host, wav, name = "airplay-send", credsPath;
    uint16_t port = 7000;
    double vol = 50.0;
    auto mode = RaopDeviceInfo::Auth::HapPin;   // default: Apple TV
    bool ap2 = true;

    for (int i = 1; i < argc; ++i) {
        const std::string a = argv[i];
        if      (a == "--atv")     { mode = RaopDeviceInfo::Auth::HapPin;       ap2 = true; }
        else if (a == "--mac" || a == "--homepod") { mode = RaopDeviceInfo::Auth::HapTransient; ap2 = true; }
        else if (a == "--ap1")     { mode = RaopDeviceInfo::Auth::None;         ap2 = false; }
        else if (a == "--port"  && i + 1 < argc) port = uint16_t(std::atoi(argv[++i]));
        else if (a == "--name"  && i + 1 < argc) name = argv[++i];
        else if (a == "--vol"   && i + 1 < argc) vol  = std::atof(argv[++i]);
        else if (a == "--creds" && i + 1 < argc) credsPath = argv[++i];
        else if (!a.empty() && a[0] != '-' && host.empty()) host = a;
        else if (!a.empty() && a[0] != '-') wav = a;
    }
    if (host.empty()) {
        std::fprintf(stderr,
            "usage: airplay_send <host-ip> [file.wav] [--atv|--mac|--ap1]\n"
            "                    [--port N] [--name NAME] [--vol 0-100] [--creds FILE]\n"
            "  no file -> a 440 Hz test tone. default --atv (HAP PIN), port 7000.\n");
        return 2;
    }
    if (credsPath.empty()) credsPath = "airplay_creds_" + host + ".json";

    std::vector<int16_t> samples;
    uint32_t rate = 44100;
    if (!wav.empty()) {
        std::string err;
        if (!loadWav(wav, samples, rate, err)) { std::fprintf(stderr, "wav: %s\n", err.c_str()); return 2; }
    } else {
        makeTone(samples, rate);
    }
    std::printf("audio: %zu frames @ %u Hz stereo (%.1f s)%s\n",
                samples.size() / 2, rate, double(samples.size() / 2) / rate,
                wav.empty() ? "  [test tone]" : "");

    std::signal(SIGINT, onSigint);

    PollTransport transport;
    RingBuffer<int16_t> ring(1u << 19);   // ~6 s of stereo @ 44100
    std::atomic<bool> done{false};

    RaopSender* sp = nullptr;
    RaopSender sender(transport,
        [](LogLevel lv, std::string m) {
            std::fprintf(stderr, "[%s] %s\n", lv == LogLevel::Warn ? "warn" : "info", m.c_str());
        },
        [&](bool ok, std::string err) {
            if (ok) std::printf(">> streaming (ctrl-c to stop)\n");
            else {
                std::fprintf(stderr, ">> launch failed: %s\n", err.c_str());
                // a SETUP/timing stall is usually the receiver unable to reach our UDP ports
                std::fprintf(stderr,
                    ">> hint: the receiver must reach this sender's UDP ports. on Windows allow\n"
                    ">>       inbound UDP through the firewall; in a VM use bridged, not NAT.\n");
                done = true; transport.stopLoop();
            }
        },
        [&]() { std::printf(">> session closed\n"); done = true; transport.stopLoop(); },
        [&](std::string dev) {
            std::printf(">> %s is showing a PIN. type the 4 digits then Enter: ", dev.c_str());
            std::fflush(stdout);
            std::string line; std::getline(std::cin, line);
            std::string pin; for (char c : line) if (c >= '0' && c <= '9') pin += c;
            if (sp) sp->submitPin(pin);
        },
        [&](std::string /*dev*/, std::string json) {
            writeFile(credsPath, json);
            std::printf(">> credentials saved to %s (next run skips the PIN)\n", credsPath.c_str());
        });
    sp = &sender;

    sender.setInputFormat(rate);
    sender.attachRing(&ring);
    sender.setVolume(vol);
    sender.setNowPlaying("airplay-send", "airplay2-sender-cpp", "m1 demo");
    sender.setAuth(mode, ap2, host, readFile(credsPath), "");

    // ctrl-c watchdog: tears the session down cleanly (TEARDOWN) from the loop.
    TimerHandle sig = transport.createTimer(100, true, [&] {
        if (g_sigint) { std::printf("\n>> stopping\n"); sender.stop(); transport.stopLoop(); }
    });
    transport.startTimer(sig);

    // producer thread: keep the ring topped up, looping the audio.
    std::thread producer([&] {
        size_t pos = 0;
        std::vector<int16_t> chunk(4096);
        while (!done) {
            if (ring.availableWrite() >= chunk.size()) {
                for (auto& x : chunk) { x = samples[pos]; if (++pos >= samples.size()) pos = 0; }
                ring.tryPush(std::span<const int16_t>(chunk.data(), chunk.size()));
            } else {
                std::this_thread::sleep_for(std::chrono::milliseconds(2));
            }
        }
    });

    std::printf("connecting to %s:%u (%s)...\n", host.c_str(), port,
                mode == RaopDeviceInfo::Auth::HapPin ? "Apple TV / HAP PIN"
              : mode == RaopDeviceInfo::Auth::HapTransient ? "Mac/HomePod / transient"
              : "AirPlay 1 / unencrypted");
    sender.start(host, port, name);
    transport.runLoop();

    done = true;
    producer.join();
    transport.destroyTimer(sig);
    return 0;
}
