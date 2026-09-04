// SPDX-License-Identifier: Apache-2.0
//
// airplay_send -- stream a wav file (or a test tone) to an AirPlay receiver.
// the ROADMAP m3 demo: what you clone, build and run to prove the sender on
// your own hardware (Apple TV, HomePod, a Mac, or an AirPlay-1 receiver such
// as shairport-sync).
//
//   airplay_send <receiver-ip> [file.wav] [--atv | --mac | --ap1]
//                [--port N] [--name TEXT] [--volume 0..100]
//                [--creds FILE] [--strict] [--quiet]
//
//   --atv   apple tv: hap pairing with the on-screen pin (default). the
//           long-term credentials are saved next to the binary, so the pin
//           is only asked once per receiver.
//   --mac   mac / homepod: hap transient pairing, fixed pin 3939, no ui.
//   --ap1   airplay 1: plain rtsp, no pairing (shairport-sync, apple tv 3).
//   --strict fail closed when the receiver's proof / signature is wrong.
//
// the audio goes through the same lock-free ring a real player feeds from
// its audio thread: a producer thread keeps it topped up, the sender pulls
// 352-frame packets out of it on the loop thread. no file = a 440 Hz tone.

#include "raop_loop.h"
#include "raop_sender.h"
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

std::atomic<bool> g_interrupted{false};
void onSignal(int) { g_interrupted.store(true); }

std::string readFile(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    if (!f) return {};
    return std::string((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
}

bool writeFile(const std::string& path, const std::string& data) {
    std::ofstream f(path, std::ios::binary | std::ios::trunc);
    if (!f) return false;
    f << data;
    return bool(f);
}

// a 16-bit pcm wav (mono or stereo, any rate) -> interleaved stereo s16.
bool loadWav(const std::string& path, std::vector<int16_t>& out, uint32_t& rate, std::string& err) {
    const std::string buf = readFile(path);
    if (buf.size() < 12 || buf.compare(0, 4, "RIFF") != 0 || buf.compare(8, 4, "WAVE") != 0) {
        err = "not a RIFF/WAVE file";
        return false;
    }
    auto rd16 = [&](size_t o) { uint16_t v; std::memcpy(&v, buf.data() + o, 2); return v; };
    auto rd32 = [&](size_t o) { uint32_t v; std::memcpy(&v, buf.data() + o, 4); return v; };
    uint16_t format = 0, channels = 0, bits = 0;
    uint32_t sampleRate = 0;
    size_t dataOff = 0, dataLen = 0;
    for (size_t p = 12; p + 8 <= buf.size();) {
        const size_t body = p + 8;
        const uint32_t size = rd32(p + 4);
        if (buf.compare(p, 4, "fmt ") == 0 && body + 16 <= buf.size()) {
            format = rd16(body); channels = rd16(body + 2);
            sampleRate = rd32(body + 4); bits = rd16(body + 14);
        } else if (buf.compare(p, 4, "data") == 0) {
            dataOff = body;
            dataLen = std::min<size_t>(size, buf.size() - body);
        }
        p = body + size + (size & 1);   // chunks are word-aligned
    }
    if (format != 1 || bits != 16 || channels < 1 || channels > 2 || sampleRate == 0 || dataOff == 0) {
        err = "need 16-bit pcm, mono or stereo. convert with\n"
              "  ffmpeg -i in.mp3 -ac 2 -ar 44100 -c:a pcm_s16le out.wav";
        return false;
    }
    const size_t n = dataLen / 2;
    out.clear();
    out.reserve(channels == 2 ? n : n * 2);
    for (size_t i = 0; i < n; ++i) {
        int16_t s;
        std::memcpy(&s, buf.data() + dataOff + i * 2, 2);
        out.push_back(s);
        if (channels == 1) out.push_back(s);
    }
    rate = sampleRate;
    return true;
}

void makeTone(std::vector<int16_t>& out, uint32_t& rate) {
    rate = 44100;
    const uint32_t seconds = 10;
    out.resize(size_t(rate) * seconds * 2);
    const double w = 2.0 * 3.14159265358979323846 * 440.0 / rate;
    for (uint32_t i = 0; i < rate * seconds; ++i) {
        const auto v = int16_t(8000.0 * std::sin(w * i));
        out[i * 2] = v;
        out[i * 2 + 1] = v;
    }
}

void usage() {
    std::fprintf(stderr,
        "usage: airplay_send <receiver-ip> [file.wav] [--atv | --mac | --ap1]\n"
        "                    [--port N] [--name TEXT] [--volume 0..100]\n"
        "                    [--creds FILE] [--strict] [--quiet]\n"
        "  no file -> a 440 Hz test tone. default: --atv (apple tv, on-screen pin), port 7000.\n");
}

} // namespace

int main(int argc, char** argv) {
    std::string host, wav, name = "airplay-send", credsPath;
    uint16_t port = 7000;
    double volume = 50.0;
    bool strict = false, quiet = false;
    auto auth = RaopDeviceInfo::Auth::HapPin;
    bool airplay2 = true;

    for (int i = 1; i < argc; ++i) {
        const std::string a = argv[i];
        auto next = [&](const char* what) -> const char* {
            if (i + 1 >= argc) { std::fprintf(stderr, "%s needs a value\n", what); std::exit(2); }
            return argv[++i];
        };
        if      (a == "--atv")    { auth = RaopDeviceInfo::Auth::HapPin;       airplay2 = true; }
        else if (a == "--mac" || a == "--homepod") { auth = RaopDeviceInfo::Auth::HapTransient; airplay2 = true; }
        else if (a == "--ap1")    { auth = RaopDeviceInfo::Auth::None;         airplay2 = false; }
        else if (a == "--port")   port = uint16_t(std::atoi(next("--port")));
        else if (a == "--name")   name = next("--name");
        else if (a == "--volume") volume = std::atof(next("--volume"));
        else if (a == "--creds")  credsPath = next("--creds");
        else if (a == "--strict") strict = true;
        else if (a == "--quiet")  quiet = true;
        else if (a == "--help" || a == "-h") { usage(); return 0; }
        else if (!a.empty() && a[0] == '-') { std::fprintf(stderr, "unknown option %s\n", a.c_str()); usage(); return 2; }
        else if (host.empty()) host = a;
        else if (wav.empty())  wav = a;
        else { usage(); return 2; }
    }
    if (host.empty()) { usage(); return 2; }
    if (credsPath.empty()) credsPath = "airplay_creds_" + host + ".json";

    std::vector<int16_t> samples;
    uint32_t rate = 44100;
    if (!wav.empty()) {
        std::string err;
        if (!loadWav(wav, samples, rate, err)) {
            std::fprintf(stderr, "%s: %s\n", wav.c_str(), err.c_str());
            return 2;
        }
    } else {
        makeTone(samples, rate);
    }
    std::printf("audio: %zu frames @ %u Hz stereo (%.1f s)%s\n",
                samples.size() / 2, rate, double(samples.size() / 2) / rate,
                wav.empty() ? ", test tone" : "");

    std::signal(SIGINT, onSignal);
#ifdef SIGTERM
    std::signal(SIGTERM, onSignal);
#endif

    RaopLoop loop;
    RingBuffer<int16_t> ring(1u << 19);   // ~6 s of stereo at 44.1 kHz
    std::atomic<bool> done{false};
    int exitCode = 0;

    RaopSender* senderPtr = nullptr;
    RaopEvents events;
    events.launched = [&](bool ok, const std::string& err) {
        if (ok) { std::printf(">> streaming, ctrl-c to stop\n"); return; }
        std::fprintf(stderr, ">> launch failed: %s\n", err.c_str());
        if (err.find("Timed out") != std::string::npos)   // a SETUP stall = our udp ports are unreachable
            std::fprintf(stderr,
                ">> hint: the receiver must reach this machine's udp ports (timing + control).\n"
                ">>       on windows allow inbound udp for airplay_send in the firewall; in a vm\n"
                ">>       use bridged networking, not nat.\n");
        exitCode = 1;
        done = true;
    };
    events.closed = [&] {
        if (!done) std::printf(">> session closed by the receiver\n");
        done = true;
    };
    events.pinRequired = [&](const std::string& device) {
        std::printf(">> %s is showing a pin. type the 4 digits and press enter: ", device.c_str());
        std::fflush(stdout);
        std::string line, pin;
        std::getline(std::cin, line);
        for (const char c : line) if (c >= '0' && c <= '9') pin += c;
        if (senderPtr) senderPtr->submitPin(pin);
    };
    events.credentialsObtained = [&](const std::string&, const std::string& json) {
        if (writeFile(credsPath, json))
            std::printf(">> credentials saved to %s (the next run skips the pin)\n", credsPath.c_str());
        else
            std::fprintf(stderr, ">> could not write %s\n", credsPath.c_str());
    };
    RaopLogSink log;
    if (!quiet) {
        log = [](RaopLogLevel level, const std::string& line) {
            std::fprintf(stderr, "[%s] %s\n", level == RaopLogLevel::Warn ? "warn" : "info", line.c_str());
        };
    }

    RaopSender sender(loop, std::move(events), std::move(log));
    senderPtr = &sender;
    sender.setInputFormat(rate);
    sender.attachRing(&ring);
    sender.setVolume(volume);
    sender.setStrictReceiverAuth(strict);
    RaopIdentity identity;
    identity.name = "airplay-send";
    sender.setIdentity(identity);
    sender.setNowPlaying("airplay-send", "airplay2-sender-cpp", wav.empty() ? "test tone" : wav);
    sender.setAuth(auth, airplay2, host, readFile(credsPath), std::string());

    // producer: keep the ring topped up, looping the audio, like a player's
    // audio callback would.
    std::thread producer([&] {
        size_t pos = 0;
        std::vector<int16_t> chunk(4096);
        while (!done.load()) {
            if (ring.availableWrite() >= chunk.size()) {
                for (auto& x : chunk) { x = samples[pos]; if (++pos >= samples.size()) pos = 0; }
                ring.tryPush(std::span<const int16_t>(chunk.data(), chunk.size()));
            } else {
                std::this_thread::sleep_for(std::chrono::milliseconds(2));
            }
        }
    });

    std::printf("connecting to %s:%u (%s, %s)...\n", host.c_str(), port, name.c_str(),
                auth == RaopDeviceInfo::Auth::HapPin       ? "apple tv, hap pin"
              : auth == RaopDeviceInfo::Auth::HapTransient ? "mac/homepod, transient"
              :                                             "airplay 1");
    sender.start(host, port, name);

    while (!done.load() && !g_interrupted.load()) loop.pump(sender);

    if (g_interrupted.load()) std::printf("\n>> stopping\n");
    sender.stop();   // TEARDOWN, flushed before the socket closes
    done = true;
    producer.join();
    return exitCode;
}
