// SPDX-License-Identifier: Apache-2.0
#pragma once
//
// raop_creds.h -- the stored-pairing credentials blob, without Qt json.
// ----------------------------------------------------------------------------
// a first HAP pairing yields long-term keys the host persists so later
// connects skip the on-screen pin. the text format is exactly what the Qt
// build wrote with QJsonDocument::Compact (keys sorted, no whitespace):
//
//   {"atvId":"<hex>","clientId":"<uuid>","ltpk":"<hex>","ltsk":"<hex>"}
//
// so blobs a host stored earlier keep loading, and blobs written here load in
// the old build. the reader is order- and whitespace-tolerant and skips keys
// it does not know.

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace fxchain {

struct RaopCreds {
    std::vector<uint8_t> ltsk;      // our 32-byte ed25519 seed (secret)
    std::vector<uint8_t> ltpk;      // the receiver's 32-byte ed25519 public key
    std::vector<uint8_t> atvId;     // the receiver's pairing identifier bytes
    std::string          clientId;  // our pairing uuid, stored as text
};

inline std::string raopHexEncode(const std::vector<uint8_t>& b) {
    static constexpr char kHex[] = "0123456789abcdef";
    std::string out;
    out.reserve(b.size() * 2);
    for (const uint8_t x : b) { out += kHex[x >> 4]; out += kHex[x & 0x0F]; }
    return out;
}

// nullopt on an odd length or a non-hex character; both cases accepted.
inline std::optional<std::vector<uint8_t>> raopHexDecode(const std::string& hex) {
    if (hex.size() % 2 != 0) return std::nullopt;
    auto nib = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    std::vector<uint8_t> out;
    out.reserve(hex.size() / 2);
    for (size_t i = 0; i < hex.size(); i += 2) {
        const int hi = nib(hex[i]), lo = nib(hex[i + 1]);
        if (hi < 0 || lo < 0) return std::nullopt;
        out.push_back(uint8_t((hi << 4) | lo));
    }
    return out;
}

namespace raop_detail {

// the json string escapes the four fields could ever need (the writer never
// produces any, but a hand-edited blob might).
inline void jsonEscapeInto(std::string& out, const std::string& s) {
    for (const char c : s) {
        switch (c) {
        case '"':  out += "\\\""; break;
        case '\\': out += "\\\\"; break;
        case '\n': out += "\\n";  break;
        case '\r': out += "\\r";  break;
        case '\t': out += "\\t";  break;
        default:
            if (static_cast<unsigned char>(c) < 0x20) {
                static constexpr char kHex[] = "0123456789abcdef";
                out += "\\u00";
                out += kHex[(c >> 4) & 0x0F];
                out += kHex[c & 0x0F];
            } else {
                out += c;
            }
        }
    }
}

struct JsonCursor {
    const std::string& s;
    size_t i = 0;
    void ws() { while (i < s.size() && (s[i] == ' ' || s[i] == '\t' || s[i] == '\n' || s[i] == '\r')) ++i; }
    bool eat(char c) { ws(); if (i < s.size() && s[i] == c) { ++i; return true; } return false; }
    // parse a json string at the cursor (opening quote expected) into out.
    bool str(std::string& out) {
        ws();
        if (i >= s.size() || s[i] != '"') return false;
        ++i;
        while (i < s.size()) {
            const char c = s[i++];
            if (c == '"') return true;
            if (c != '\\') { out += c; continue; }
            if (i >= s.size()) return false;
            const char e = s[i++];
            switch (e) {
            case '"': out += '"'; break;   case '\\': out += '\\'; break;
            case '/': out += '/'; break;   case 'b': out += '\b'; break;
            case 'f': out += '\f'; break;  case 'n': out += '\n'; break;
            case 'r': out += '\r'; break;  case 't': out += '\t'; break;
            case 'u': {
                if (i + 4 > s.size()) return false;
                unsigned cp = 0;
                for (int k = 0; k < 4; ++k) {
                    const char h = s[i++];
                    cp <<= 4;
                    if (h >= '0' && h <= '9') cp |= unsigned(h - '0');
                    else if (h >= 'a' && h <= 'f') cp |= unsigned(h - 'a' + 10);
                    else if (h >= 'A' && h <= 'F') cp |= unsigned(h - 'A' + 10);
                    else return false;
                }
                if (cp < 0x80) out += char(cp);
                else if (cp < 0x800) { out += char(0xC0 | (cp >> 6)); out += char(0x80 | (cp & 0x3F)); }
                else { out += char(0xE0 | (cp >> 12)); out += char(0x80 | ((cp >> 6) & 0x3F)); out += char(0x80 | (cp & 0x3F)); }
                break;
            }
            default: return false;
            }
        }
        return false;
    }
    // skip one json value of any type (used for keys we don't know).
    bool skipValue() {
        ws();
        if (i >= s.size()) return false;
        if (s[i] == '"') { std::string sink; return str(sink); }
        if (s[i] == '{' || s[i] == '[') {
            int depth = 0;
            bool inStr = false;
            while (i < s.size()) {
                const char c = s[i++];
                if (inStr) { if (c == '\\') ++i; else if (c == '"') inStr = false; continue; }
                if (c == '"') inStr = true;
                else if (c == '{' || c == '[') ++depth;
                else if (c == '}' || c == ']') { if (--depth == 0) return true; }
            }
            return false;
        }
        while (i < s.size() && s[i] != ',' && s[i] != '}' && s[i] != ']') ++i;   // number / literal
        return true;
    }
};

} // namespace raop_detail

inline std::string raopCredsToJson(const RaopCreds& c) {
    std::string out = "{\"atvId\":\"" + raopHexEncode(c.atvId) + "\",\"clientId\":\"";
    raop_detail::jsonEscapeInto(out, c.clientId);
    out += "\",\"ltpk\":\"" + raopHexEncode(c.ltpk) + "\",\"ltsk\":\"" + raopHexEncode(c.ltsk) + "\"}";
    return out;
}

// nullopt unless the text is a json object carrying all four string fields
// with well-formed hex. the caller still checks the key lengths.
inline std::optional<RaopCreds> raopCredsFromJson(const std::string& json) {
    raop_detail::JsonCursor cur{json};
    if (!cur.eat('{')) return std::nullopt;
    std::optional<std::string> ltsk, ltpk, atvId, clientId;
    if (!cur.eat('}')) {
        for (;;) {
            std::string key;
            if (!cur.str(key) || !cur.eat(':')) return std::nullopt;
            if (key == "ltsk" || key == "ltpk" || key == "atvId" || key == "clientId") {
                std::string val;
                if (!cur.str(val)) return std::nullopt;
                if (key == "ltsk") ltsk = val;
                else if (key == "ltpk") ltpk = val;
                else if (key == "atvId") atvId = val;
                else clientId = val;
            } else if (!cur.skipValue()) {
                return std::nullopt;
            }
            if (cur.eat(',')) continue;
            if (cur.eat('}')) break;
            return std::nullopt;
        }
    }
    if (!ltsk || !ltpk || !atvId || !clientId) return std::nullopt;
    const auto sk = raopHexDecode(*ltsk), pk = raopHexDecode(*ltpk), id = raopHexDecode(*atvId);
    if (!sk || !pk || !id) return std::nullopt;
    RaopCreds out;
    out.ltsk = *sk; out.ltpk = *pk; out.atvId = *id; out.clientId = *clientId;
    return out;
}

} // namespace fxchain
