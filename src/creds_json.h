// SPDX-License-Identifier: Apache-2.0
#pragma once
//
// creds_json.h -- the stored-pairing credentials blob, Qt-free.
// ----------------------------------------------------------------------------
// a first HAP pairing yields long-term credentials the host persists so later
// connects skip the on-screen PIN. the wire shape is unchanged from the Qt
// (QJsonDocument) version so blobs stored by an older build still load:
//
//   {"ltsk":"<hex>","ltpk":"<hex>","atvId":"<hex>","clientId":"<uuid string>"}
//
// ltsk/ltpk/atvId are lowercase-hex byte strings; clientId is the pairing
// UUID stored RAW (not hex). the writer emits the same compact, same-order
// JSON QJsonObject::insert produced. the reader scans by key so a
// pretty-printed or reordered blob still loads.

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace fxchain {

inline std::string credsToHex(const std::vector<uint8_t>& b) {
    static constexpr char h[] = "0123456789abcdef";
    std::string out;
    out.reserve(b.size() * 2);
    for (uint8_t byte : b) { out += h[byte >> 4]; out += h[byte & 0xF]; }
    return out;
}

// decode lower- or upper-case hex; empty on odd length or a non-hex char.
inline std::vector<uint8_t> credsFromHex(const std::string& s) {
    if (s.size() % 2 != 0) return {};
    auto nib = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    std::vector<uint8_t> out;
    out.reserve(s.size() / 2);
    for (size_t i = 0; i < s.size(); i += 2) {
        const int hi = nib(s[i]), lo = nib(s[i + 1]);
        if (hi < 0 || lo < 0) return {};
        out.push_back(uint8_t((hi << 4) | lo));
    }
    return out;
}

struct CredsFields {
    std::vector<uint8_t> ltsk;      // our 32-byte Ed25519 seed (secret)
    std::vector<uint8_t> ltpk;      // accessory's 32-byte Ed25519 public key
    std::vector<uint8_t> atvId;     // accessory identifier bytes
    std::string          clientId;  // our pairing UUID string (raw, not hex)
};

inline std::string credsToJson(const CredsFields& c) {
    return std::string("{")
        + "\"ltsk\":\""     + credsToHex(c.ltsk)  + "\","
        + "\"ltpk\":\""     + credsToHex(c.ltpk)  + "\","
        + "\"atvId\":\""    + credsToHex(c.atvId) + "\","
        + "\"clientId\":\"" + c.clientId          + "\"}";
}

// pull the four string fields by key. nullopt if any is missing or the two
// required key fields decode empty (matches the old size==32 && !empty guard
// at the call site, which still re-checks lengths).
inline std::optional<CredsFields> credsFromJson(const std::string& json) {
    auto readStr = [&](const std::string& key) -> std::optional<std::string> {
        const std::string needle = "\"" + key + "\":\"";
        const auto pos = json.find(needle);
        if (pos == std::string::npos) return std::nullopt;
        const auto start = pos + needle.size();
        const auto end = json.find('"', start);
        if (end == std::string::npos) return std::nullopt;
        return json.substr(start, end - start);
    };

    const auto ltskHex  = readStr("ltsk");
    const auto ltpkHex  = readStr("ltpk");
    const auto atvIdHex = readStr("atvId");
    const auto cid      = readStr("clientId");
    if (!ltskHex || !ltpkHex || !atvIdHex || !cid) return std::nullopt;

    CredsFields out;
    out.ltsk     = credsFromHex(*ltskHex);
    out.ltpk     = credsFromHex(*ltpkHex);
    out.atvId    = credsFromHex(*atvIdHex);
    out.clientId = *cid;
    return out;
}

} // namespace fxchain
