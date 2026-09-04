// SPDX-License-Identifier: Apache-2.0
#pragma once
//
// raop_log.h -- the log sink (ROADMAP m2) and a small "{}" formatter.
// ----------------------------------------------------------------------------
// the sender used to log through a host header. now the host hands it ONE
// std::function and receives finished lines; an empty sink silences it. the
// formatter is deliberately tiny (positional "{}" only, "{{" and "}}" escape a
// brace) so the library needs neither <format> (gcc 13+ only) nor a
// third-party library. it is what the sender's own log lines use; hosts are
// free to ignore it.

#include <functional>
#include <sstream>
#include <string>
#include <string_view>
#include <type_traits>

namespace fxchain {

enum class RaopLogLevel { Info, Warn };
using RaopLogSink = std::function<void(RaopLogLevel, const std::string&)>;

namespace raop_detail {

inline void appendArg(std::string& out, const std::string& v) { out += v; }
inline void appendArg(std::string& out, std::string_view v)   { out.append(v.data(), v.size()); }
inline void appendArg(std::string& out, const char* v)        { out += v ? v : "(null)"; }
inline void appendArg(std::string& out, bool v)               { out += v ? "true" : "false"; }
inline void appendArg(std::string& out, char v)               { out += v; }
template <class T>
inline void appendArg(std::string& out, const T& v) {
    std::ostringstream os;
    if constexpr (std::is_integral_v<T>) os << +v;   // promote: uint8_t prints as a number
    else                                 os << v;
    out += os.str();
}

inline void formatInto(std::string& out, std::string_view fmt) {
    for (size_t i = 0; i < fmt.size(); ++i) {
        const char c = fmt[i];
        if ((c == '{' || c == '}') && i + 1 < fmt.size() && fmt[i + 1] == c) { out += c; ++i; }
        else out += c;
    }
}
template <class T, class... Rest>
inline void formatInto(std::string& out, std::string_view fmt,
                       const T& first, const Rest&... rest) {
    for (size_t i = 0; i < fmt.size(); ++i) {
        const char c = fmt[i];
        if (c == '{') {
            if (i + 1 < fmt.size() && fmt[i + 1] == '{') { out += '{'; ++i; continue; }
            const size_t close = fmt.find('}', i);
            if (close == std::string_view::npos) { out.append(fmt.substr(i)); return; }
            appendArg(out, first);
            formatInto(out, fmt.substr(close + 1), rest...);
            return;
        }
        if (c == '}' && i + 1 < fmt.size() && fmt[i + 1] == '}') { out += '}'; ++i; continue; }
        out += c;
    }
}

} // namespace raop_detail

// raopFormat("{} of {}", 1, "two") -> "1 of two". surplus arguments are
// ignored; a missing argument leaves the rest of the text as written.
template <class... A>
inline std::string raopFormat(std::string_view fmt, const A&... a) {
    std::string out;
    out.reserve(fmt.size() + 16);
    raop_detail::formatInto(out, fmt, a...);
    return out;
}

} // namespace fxchain
