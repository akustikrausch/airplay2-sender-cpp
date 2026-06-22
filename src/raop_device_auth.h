// SPDX-License-Identifier: Apache-2.0
#pragma once
//
// raop_device_auth.h -- the receiver auth method enum (ROADMAP m2).
// ----------------------------------------------------------------------------
// raop_sender used to pull this one enum from the host's mdns_discovery.h
// (which also did bonjour discovery). it is inlined here so the sender builds
// standalone; a caller that has discovery passes the resolved host + the
// matching Auth value to setAuth(). the enumerators are exactly the ones the
// sender's auth chain switches on -- do not drop any (LegacyPin is handled
// with an explicit "not supported yet" path, so it must exist).

#include <cstdint>

namespace fxchain {

struct RaopDeviceInfo {
    enum class Auth : uint8_t {
        None,         // open receiver, plain RTSP, no auth
        Password,     // RTSP digest auth (pw=true), reactive on a 401
        AuthSetup,    // MFiSAP one-shot POST (AirPort Express gen 2), reply ignored
        LegacyPin,    // pre-HomeKit "Fruit" SRP-2048 PIN (not implemented yet)
        HapTransient, // HAP transient pairing, fixed PIN "3939" (HomePod / macOS)
        HapPin,       // HAP on-screen 4-digit PIN (Apple TV 4+)
    };
};

} // namespace fxchain
