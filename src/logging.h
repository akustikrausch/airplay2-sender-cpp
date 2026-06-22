// SPDX-License-Identifier: Apache-2.0
#pragma once
//
// logging.h -- the Qt-free log sink (ROADMAP m2).
// ----------------------------------------------------------------------------
// the sender used to log through a host `common/logger.h` (a fmt-style
// `Log::info("...{}...", a, b)`). that becomes a one-line std::function sink
// the caller supplies, plus a thin {}-formatting wrapper so the existing call
// sites port over almost verbatim (`Log::info(` -> `log_.info(`). pass an
// empty sink to silence all output.

#include <format>
#include <functional>
#include <string>
#include <utility>

namespace fxchain {

enum class LogLevel { Info, Warn };

// the host's logging hook: (level, already-formatted message).
using LogSink = std::function<void(LogLevel, std::string)>;

// {}-style formatting on top of a LogSink. std::format keeps the same
// placeholder syntax the old Log:: macro used, so the call sites are
// unchanged apart from `Log::` -> `log_.`. when the sink is empty the
// format work is still skipped (the if-guard short-circuits).
class Logger {
public:
    Logger() = default;
    explicit Logger(LogSink sink) : sink_(std::move(sink)) {}

    template <class... A>
    void info(std::format_string<A...> fmt, A&&... a) const {
        if (sink_) sink_(LogLevel::Info,
                         std::format(fmt, std::forward<A>(a)...));
    }
    template <class... A>
    void warn(std::format_string<A...> fmt, A&&... a) const {
        if (sink_) sink_(LogLevel::Warn,
                         std::format(fmt, std::forward<A>(a)...));
    }

private:
    LogSink sink_;
};

} // namespace fxchain
