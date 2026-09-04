// SPDX-License-Identifier: Apache-2.0
#pragma once
//
// raop_auth.h -- how a receiver wants to be authenticated (ROADMAP m2).
// ----------------------------------------------------------------------------
// this enum used to come from the host's mdns browser header; it was the one
// thing the sender needed from discovery. a caller with its own discovery
// maps the receiver's mdns txt record onto it (roughly: `pw=true` ->
// Password, `am=AirPort*` -> AuthSetup, an `sf`/`features` flag set with the
// HomeKit bits -> HapPin for an apple tv, HapTransient for a homepod / mac)
// and passes the resolved host to RaopSender::start().

#include <cstdint>

namespace fxchain {

struct RaopDeviceInfo {
    enum class Auth : uint8_t {
        None,          // open receiver: plain rtsp, no auth at all
        Password,      // rtsp digest auth (pw=true), reactive on a 401
        AuthSetup,     // MFiSAP one-shot POST (airport express gen 2), reply ignored
        LegacyPin,     // pre-homekit "fruit" srp-2048 pin (not implemented, fails fast)
        HapTransient,  // hap transient pairing, fixed pin 3939 (homepod / macos)
        HapPin,        // hap on-screen 4-digit pin (apple tv 4+); stored creds skip it
    };
};

} // namespace fxchain
