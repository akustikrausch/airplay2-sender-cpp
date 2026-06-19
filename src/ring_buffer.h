// SPDX-License-Identifier: Apache-2.0
#pragma once

#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <algorithm>
#include <atomic>
#include <cstddef>
#include <cstring>
#include <memory>
#include <span>
#include <type_traits>

namespace fxchain {

template <typename T>
class RingBuffer {
    static_assert(std::is_trivially_copyable_v<T>);

public:
    explicit RingBuffer(size_t requested_size)
        : mask_{nextPow2(requested_size) - 1}
        , buffer_{std::make_unique<T[]>(mask_ + 1)} {}

    bool tryPush(std::span<const T> data) {
        const auto wr = write_.load(std::memory_order_relaxed);
        const auto rd = read_.load(std::memory_order_acquire);
        if (data.size() > capacity() - (wr - rd))
            return false;

        const auto pos = wr & mask_;
        const auto first = (std::min)(data.size(), capacity() - pos);
        std::memcpy(buffer_.get() + pos, data.data(), first * sizeof(T));
        std::memcpy(buffer_.get(), data.data() + first, (data.size() - first) * sizeof(T));

        write_.store(wr + data.size(), std::memory_order_release);
        return true;
    }

    bool tryPop(std::span<T> data) {
        const auto rd = read_.load(std::memory_order_relaxed);
        const auto wr = write_.load(std::memory_order_acquire);
        if (data.size() > wr - rd)
            return false;

        const auto pos = rd & mask_;
        const auto first = (std::min)(data.size(), capacity() - pos);
        std::memcpy(data.data(), buffer_.get() + pos, first * sizeof(T));
        std::memcpy(data.data() + first, buffer_.get(), (data.size() - first) * sizeof(T));

        read_.store(rd + data.size(), std::memory_order_release);
        return true;
    }

    size_t availableRead() const {
        return write_.load(std::memory_order_acquire) - read_.load(std::memory_order_relaxed);
    }

    size_t availableWrite() const {
        return capacity() - availableRead();
    }

    size_t capacity() const { return mask_ + 1; }

    void reset() {
        write_.store(0, std::memory_order_release);
        read_.store(0, std::memory_order_release);
    }

private:
    static size_t nextPow2(size_t v) {
        v--;
        v |= v >> 1; v |= v >> 2; v |= v >> 4;
        v |= v >> 8; v |= v >> 16; v |= v >> 32;
        return ++v;
    }

    const size_t mask_;
    std::unique_ptr<T[]> buffer_;

    alignas(64) std::atomic<size_t> read_{0};
    alignas(64) std::atomic<size_t> write_{0};
};

} // namespace fxchain
