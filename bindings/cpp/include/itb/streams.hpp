// streams.hpp — chunked encrypt / decrypt over caller-owned I/O.
//
// ITB ciphertexts cap at ~64 MB plaintext per chunk (the underlying
// container size limit). Streaming larger payloads slices the input
// into chunks at the binding layer, encrypts each chunk through the
// regular FFI path, and concatenates the results. The reverse walks
// a concatenated chunk stream by reading the chunk header, calling
// `itb_parse_chunk_len` to learn the chunk's body length, reading
// that many bytes, and decrypting the single chunk.
//
// Two flavours of stream wrappers:
//
//   1. Class-based push-pattern (`StreamEncryptor` /
//      `StreamDecryptor` and Triple counterparts) — caller invokes
//      `write(buf)` / `feed(buf)` repeatedly, then `close()`. Output
//      lands via a caller-supplied sink callback
//      (`std::function<void(const uint8_t*, std::size_t)>`) so the
//      sink can be a `std::ofstream`, an in-memory `std::vector`, a
//      socket write, or any other byte-consumer.
//
//   2. Free functions (`encrypt_stream` / `decrypt_stream` and
//      Triple counterparts) — bridge to the C binding's
//      `itb_stream_*` callbacks. The caller supplies a `read` and a
//      `write` `std::function`; the binding wires them through
//      thunks to the C-side stream loop.
//
// `chunk_size > 0` preflight in constructor / free function:
// `chunk_size = 0` is semantically invalid (zero chunks emit no
// output) and surfaces as `ItbError(STATUS_BAD_INPUT)`. Closed-state
// preflight on write / feed mirrors the Encryptor surface — calls
// after close raise `ItbError(STATUS_EASY_CLOSED)`.
//
// Seed lifetime contract. Every `Seed` (and the optional `Mac`)
// referenced by a stream wrapper must remain alive for the entire
// stream session. The wrapper holds raw pointers internally; freeing
// an originating `Seed` mid-session yields a use-after-free in the
// FFI call.
//
// Free-function thunk dispatch. The C-binding's stream loop
// (`itb_stream_encrypt` / `_decrypt` and Triple counterparts)
// dispatches the `read_thunk` and `write_thunk` callbacks serially
// from a single goroutine per call; each `encrypt_stream` /
// `decrypt_stream` invocation uses an independent on-stack
// `StreamCtx`. The `ctx.ex` exception_ptr write inside a thunk is
// therefore safe — only one thread touches the field per call. Two
// concurrent stream invocations have two disjoint contexts.
//
// Platform support. The chunk-loop arithmetic uses
// `static_cast<std::ptrdiff_t>(chunk_size_)` / `(chunk_len)` to
// convert size_t offsets into `vector::begin()` iterator arithmetic.
// This relies on `sizeof(std::ptrdiff_t) >= sizeof(std::size_t)`
// (LP64 / LLP64 with 64-bit pointer); the binding ships against
// 64-bit Linux / macOS / FreeBSD only. A hypothetical 32-bit build
// where ptrdiff_t is 32-bit would wrap on chunks exceeding
// INT32_MAX, and the slice arithmetic would be undefined.
//
// Warning. Do not call `itb::set_nonce_bits` between calls on the
// same stream pair. Each chunk is encrypted under the active nonce
// width at the moment it is flushed; switching mid-stream produces
// a chunk header layout the paired decryptor cannot parse.

#pragma once

#include <itb.h>
#include <itb/cipher.hpp>
#include <itb/errors.hpp>
#include <itb/mac.hpp>
#include <itb/seed.hpp>

#include <cstddef>
#include <cstdint>
#include <exception>
#include <functional>
#include <string_view>
#include <utility>
#include <vector>

namespace itb {

constexpr std::size_t kDefaultChunkSize = 16 * 1024 * 1024;

using StreamSink = std::function<void(const std::uint8_t*, std::size_t)>;
using StreamSource = std::function<std::size_t(std::uint8_t*, std::size_t)>;

// ---- Single Ouroboros — push-pattern encryptor -------------------

class StreamEncryptor {
public:
    StreamEncryptor(const Seed& noise, const Seed& data, const Seed& start,
                    StreamSink sink,
                    std::size_t chunk_size = kDefaultChunkSize)
        : noise_{&noise}, data_{&data}, start_{&start},
          sink_{std::move(sink)}, chunk_size_{chunk_size} {
        if (chunk_size == 0) {
            throw ItbError{status::kBadInput,
                           "chunk_size must be > 0"};
        }
    }

    StreamEncryptor(const StreamEncryptor&) = delete;
    StreamEncryptor& operator=(const StreamEncryptor&) = delete;
    StreamEncryptor(StreamEncryptor&&) noexcept = default;

    // Hand-written to flush any pending plaintext on the destination
    // before adopting the source's state — a defaulted move-assignment
    // would silently overwrite the destination's `buf_` and drop
    // unencrypted bytes the user had already written.
    StreamEncryptor& operator=(StreamEncryptor&& other) noexcept {
        if (this != &other) {
            try {
                close();
            } catch (...) {
                // assignment must not propagate
            }
            noise_ = other.noise_;
            data_ = other.data_;
            start_ = other.start_;
            sink_ = std::move(other.sink_);
            chunk_size_ = other.chunk_size_;
            buf_ = std::move(other.buf_);
            closed_ = other.closed_;
        }
        return *this;
    }

    ~StreamEncryptor() noexcept {
        try {
            close();
        } catch (...) {
            // dtor must not propagate
        }
    }

    void write(const std::uint8_t* p, std::size_t n) {
        if (closed_) {
            throw ItbError{status::kEasyClosed,
                           "write on closed StreamEncryptor"};
        }
        if (n > 0) {
            buf_.insert(buf_.end(), p, p + n);
        }
        while (buf_.size() >= chunk_size_) {
            std::vector<std::uint8_t> chunk(
                buf_.begin(),
                buf_.begin() + static_cast<std::ptrdiff_t>(chunk_size_));
            buf_.erase(
                buf_.begin(),
                buf_.begin() + static_cast<std::ptrdiff_t>(chunk_size_));
            auto ct = encrypt(*noise_, *data_, *start_, chunk);
            sink_(ct.data(), ct.size());
        }
    }

    void write(const std::vector<std::uint8_t>& v) {
        write(v.data(), v.size());
    }
    void write(std::string_view sv) {
        write(reinterpret_cast<const std::uint8_t*>(sv.data()), sv.size());
    }

    void close() {
        if (closed_) {
            return;
        }
        if (!buf_.empty()) {
            auto ct = encrypt(*noise_, *data_, *start_, buf_);
            sink_(ct.data(), ct.size());
            buf_.clear();
        }
        closed_ = true;
    }

    bool is_closed() const noexcept { return closed_; }

private:
    const Seed* noise_;
    const Seed* data_;
    const Seed* start_;
    StreamSink sink_;
    std::size_t chunk_size_;
    std::vector<std::uint8_t> buf_;
    bool closed_ = false;
};

// ---- Single Ouroboros — feed-pattern decryptor -------------------

class StreamDecryptor {
public:
    StreamDecryptor(const Seed& noise, const Seed& data, const Seed& start,
                    StreamSink sink)
        : noise_{&noise}, data_{&data}, start_{&start},
          sink_{std::move(sink)} {
        int hs = itb_header_size();
        if (hs <= 0) {
            throw ItbError{status::kInternal,
                           "itb_header_size returned non-positive value"};
        }
        header_size_ = static_cast<std::size_t>(hs);
    }

    StreamDecryptor(const StreamDecryptor&) = delete;
    StreamDecryptor& operator=(const StreamDecryptor&) = delete;
    StreamDecryptor(StreamDecryptor&&) noexcept = default;
    StreamDecryptor& operator=(StreamDecryptor&&) noexcept = default;

    ~StreamDecryptor() noexcept = default;

    void feed(const std::uint8_t* p, std::size_t n) {
        if (closed_) {
            throw ItbError{status::kEasyClosed,
                           "feed on closed StreamDecryptor"};
        }
        if (n > 0) {
            buf_.insert(buf_.end(), p, p + n);
        }
        for (;;) {
            if (buf_.size() < header_size_) {
                break;
            }
            std::size_t chunk_len = 0;
            int rc = itb_parse_chunk_len(buf_.data(), header_size_,
                                         &chunk_len);
            if (rc != ITB_OK) {
                detail::throw_from_status(rc);
            }
            if (buf_.size() < chunk_len) {
                break;
            }
            std::vector<std::uint8_t> chunk(
                buf_.begin(),
                buf_.begin() + static_cast<std::ptrdiff_t>(chunk_len));
            buf_.erase(
                buf_.begin(),
                buf_.begin() + static_cast<std::ptrdiff_t>(chunk_len));
            auto pt = decrypt(*noise_, *data_, *start_, chunk);
            sink_(pt.data(), pt.size());
        }
    }

    void feed(const std::vector<std::uint8_t>& v) {
        feed(v.data(), v.size());
    }

    void close() {
        if (closed_) {
            return;
        }
        if (!buf_.empty()) {
            throw ItbError{status::kBadInput,
                           "StreamDecryptor::close: trailing bytes "
                           "(partial chunk)"};
        }
        closed_ = true;
    }

    bool is_closed() const noexcept { return closed_; }

private:
    const Seed* noise_;
    const Seed* data_;
    const Seed* start_;
    StreamSink sink_;
    std::size_t header_size_ = 0;
    std::vector<std::uint8_t> buf_;
    bool closed_ = false;
};

// ---- Triple Ouroboros — push-pattern encryptor -------------------

class StreamEncryptorTriple {
public:
    StreamEncryptorTriple(const Seed& noise,
                          const Seed& data1, const Seed& data2,
                          const Seed& data3,
                          const Seed& start1, const Seed& start2,
                          const Seed& start3,
                          StreamSink sink,
                          std::size_t chunk_size = kDefaultChunkSize)
        : noise_{&noise},
          data1_{&data1}, data2_{&data2}, data3_{&data3},
          start1_{&start1}, start2_{&start2}, start3_{&start3},
          sink_{std::move(sink)}, chunk_size_{chunk_size} {
        if (chunk_size == 0) {
            throw ItbError{status::kBadInput,
                           "chunk_size must be > 0"};
        }
    }

    StreamEncryptorTriple(const StreamEncryptorTriple&) = delete;
    StreamEncryptorTriple& operator=(const StreamEncryptorTriple&) = delete;
    StreamEncryptorTriple(StreamEncryptorTriple&&) noexcept = default;

    // Hand-written to flush pending plaintext on the destination
    // before adopting the source's state (parallels StreamEncryptor's
    // move-assign discipline; defaulted move would drop the
    // destination's unflushed bytes).
    StreamEncryptorTriple& operator=(StreamEncryptorTriple&& other) noexcept {
        if (this != &other) {
            try {
                close();
            } catch (...) {
                // assignment must not propagate
            }
            noise_ = other.noise_;
            data1_ = other.data1_;
            data2_ = other.data2_;
            data3_ = other.data3_;
            start1_ = other.start1_;
            start2_ = other.start2_;
            start3_ = other.start3_;
            sink_ = std::move(other.sink_);
            chunk_size_ = other.chunk_size_;
            buf_ = std::move(other.buf_);
            closed_ = other.closed_;
        }
        return *this;
    }

    ~StreamEncryptorTriple() noexcept {
        try {
            close();
        } catch (...) {
            // dtor must not propagate
        }
    }

    void write(const std::uint8_t* p, std::size_t n) {
        if (closed_) {
            throw ItbError{status::kEasyClosed,
                           "write on closed StreamEncryptorTriple"};
        }
        if (n > 0) {
            buf_.insert(buf_.end(), p, p + n);
        }
        while (buf_.size() >= chunk_size_) {
            std::vector<std::uint8_t> chunk(
                buf_.begin(),
                buf_.begin() + static_cast<std::ptrdiff_t>(chunk_size_));
            buf_.erase(
                buf_.begin(),
                buf_.begin() + static_cast<std::ptrdiff_t>(chunk_size_));
            auto ct = encrypt_triple(*noise_,
                                     *data1_, *data2_, *data3_,
                                     *start1_, *start2_, *start3_,
                                     chunk);
            sink_(ct.data(), ct.size());
        }
    }

    void write(const std::vector<std::uint8_t>& v) {
        write(v.data(), v.size());
    }
    void write(std::string_view sv) {
        write(reinterpret_cast<const std::uint8_t*>(sv.data()), sv.size());
    }

    void close() {
        if (closed_) {
            return;
        }
        if (!buf_.empty()) {
            auto ct = encrypt_triple(*noise_,
                                     *data1_, *data2_, *data3_,
                                     *start1_, *start2_, *start3_,
                                     buf_);
            sink_(ct.data(), ct.size());
            buf_.clear();
        }
        closed_ = true;
    }

    bool is_closed() const noexcept { return closed_; }

private:
    const Seed* noise_;
    const Seed* data1_;
    const Seed* data2_;
    const Seed* data3_;
    const Seed* start1_;
    const Seed* start2_;
    const Seed* start3_;
    StreamSink sink_;
    std::size_t chunk_size_;
    std::vector<std::uint8_t> buf_;
    bool closed_ = false;
};

// ---- Triple Ouroboros — feed-pattern decryptor -------------------

class StreamDecryptorTriple {
public:
    StreamDecryptorTriple(const Seed& noise,
                          const Seed& data1, const Seed& data2,
                          const Seed& data3,
                          const Seed& start1, const Seed& start2,
                          const Seed& start3,
                          StreamSink sink)
        : noise_{&noise},
          data1_{&data1}, data2_{&data2}, data3_{&data3},
          start1_{&start1}, start2_{&start2}, start3_{&start3},
          sink_{std::move(sink)} {
        int hs = itb_header_size();
        if (hs <= 0) {
            throw ItbError{status::kInternal,
                           "itb_header_size returned non-positive value"};
        }
        header_size_ = static_cast<std::size_t>(hs);
    }

    StreamDecryptorTriple(const StreamDecryptorTriple&) = delete;
    StreamDecryptorTriple& operator=(const StreamDecryptorTriple&) = delete;
    StreamDecryptorTriple(StreamDecryptorTriple&&) noexcept = default;
    StreamDecryptorTriple& operator=(StreamDecryptorTriple&&) noexcept = default;

    ~StreamDecryptorTriple() noexcept = default;

    void feed(const std::uint8_t* p, std::size_t n) {
        if (closed_) {
            throw ItbError{status::kEasyClosed,
                           "feed on closed StreamDecryptorTriple"};
        }
        if (n > 0) {
            buf_.insert(buf_.end(), p, p + n);
        }
        for (;;) {
            if (buf_.size() < header_size_) {
                break;
            }
            std::size_t chunk_len = 0;
            int rc = itb_parse_chunk_len(buf_.data(), header_size_,
                                         &chunk_len);
            if (rc != ITB_OK) {
                detail::throw_from_status(rc);
            }
            if (buf_.size() < chunk_len) {
                break;
            }
            std::vector<std::uint8_t> chunk(
                buf_.begin(),
                buf_.begin() + static_cast<std::ptrdiff_t>(chunk_len));
            buf_.erase(
                buf_.begin(),
                buf_.begin() + static_cast<std::ptrdiff_t>(chunk_len));
            auto pt = decrypt_triple(*noise_,
                                     *data1_, *data2_, *data3_,
                                     *start1_, *start2_, *start3_,
                                     chunk);
            sink_(pt.data(), pt.size());
        }
    }

    void feed(const std::vector<std::uint8_t>& v) {
        feed(v.data(), v.size());
    }

    void close() {
        if (closed_) {
            return;
        }
        if (!buf_.empty()) {
            throw ItbError{status::kBadInput,
                           "StreamDecryptorTriple::close: trailing "
                           "bytes (partial chunk)"};
        }
        closed_ = true;
    }

    bool is_closed() const noexcept { return closed_; }

private:
    const Seed* noise_;
    const Seed* data1_;
    const Seed* data2_;
    const Seed* data3_;
    const Seed* start1_;
    const Seed* start2_;
    const Seed* start3_;
    StreamSink sink_;
    std::size_t header_size_ = 0;
    std::vector<std::uint8_t> buf_;
    bool closed_ = false;
};

// ---- Free-function streams (callback bridge) ---------------------

namespace detail {

struct StreamCtx {
    StreamSource* read_fn;
    StreamSink* write_fn;
    std::exception_ptr ex;
};

inline int read_thunk(void* user_ctx, void* buf, std::size_t cap,
                      std::size_t* out_n) noexcept {
    auto* c = static_cast<StreamCtx*>(user_ctx);
    try {
        *out_n = (*c->read_fn)(static_cast<std::uint8_t*>(buf), cap);
        return ITB_OK;
    } catch (...) {
        c->ex = std::current_exception();
        return ITB_INTERNAL;
    }
}

inline int write_thunk(void* user_ctx, const void* buf,
                       std::size_t n) noexcept {
    auto* c = static_cast<StreamCtx*>(user_ctx);
    try {
        (*c->write_fn)(static_cast<const std::uint8_t*>(buf), n);
        return ITB_OK;
    } catch (...) {
        c->ex = std::current_exception();
        return ITB_INTERNAL;
    }
}

} // namespace detail

inline void encrypt_stream(const Seed& noise,
                           const Seed& data,
                           const Seed& start,
                           StreamSource read,
                           StreamSink write,
                           std::size_t chunk_size = kDefaultChunkSize) {
    if (chunk_size == 0) {
        throw ItbError{status::kBadInput, "chunk_size must be > 0"};
    }
    detail::StreamCtx ctx{&read, &write, nullptr};
    int rc = itb_stream_encrypt(noise.raw_handle(), data.raw_handle(),
                                start.raw_handle(),
                                detail::read_thunk, &ctx,
                                detail::write_thunk, &ctx,
                                chunk_size);
    if (ctx.ex) {
        std::rethrow_exception(ctx.ex);
    }
    if (rc != ITB_OK) {
        detail::throw_from_status(rc);
    }
}

inline void decrypt_stream(const Seed& noise,
                           const Seed& data,
                           const Seed& start,
                           StreamSource read,
                           StreamSink write,
                           std::size_t chunk_size = kDefaultChunkSize) {
    if (chunk_size == 0) {
        throw ItbError{status::kBadInput, "chunk_size must be > 0"};
    }
    detail::StreamCtx ctx{&read, &write, nullptr};
    int rc = itb_stream_decrypt(noise.raw_handle(), data.raw_handle(),
                                start.raw_handle(),
                                detail::read_thunk, &ctx,
                                detail::write_thunk, &ctx,
                                chunk_size);
    if (ctx.ex) {
        std::rethrow_exception(ctx.ex);
    }
    if (rc != ITB_OK) {
        detail::throw_from_status(rc);
    }
}

inline void encrypt_stream_triple(const Seed& noise,
                                  const Seed& data1, const Seed& data2,
                                  const Seed& data3,
                                  const Seed& start1, const Seed& start2,
                                  const Seed& start3,
                                  StreamSource read,
                                  StreamSink write,
                                  std::size_t chunk_size = kDefaultChunkSize) {
    if (chunk_size == 0) {
        throw ItbError{status::kBadInput, "chunk_size must be > 0"};
    }
    detail::StreamCtx ctx{&read, &write, nullptr};
    int rc = itb_stream_encrypt_triple(
        noise.raw_handle(),
        data1.raw_handle(), data2.raw_handle(), data3.raw_handle(),
        start1.raw_handle(), start2.raw_handle(), start3.raw_handle(),
        detail::read_thunk, &ctx,
        detail::write_thunk, &ctx,
        chunk_size);
    if (ctx.ex) {
        std::rethrow_exception(ctx.ex);
    }
    if (rc != ITB_OK) {
        detail::throw_from_status(rc);
    }
}

inline void decrypt_stream_triple(const Seed& noise,
                                  const Seed& data1, const Seed& data2,
                                  const Seed& data3,
                                  const Seed& start1, const Seed& start2,
                                  const Seed& start3,
                                  StreamSource read,
                                  StreamSink write,
                                  std::size_t chunk_size = kDefaultChunkSize) {
    if (chunk_size == 0) {
        throw ItbError{status::kBadInput, "chunk_size must be > 0"};
    }
    detail::StreamCtx ctx{&read, &write, nullptr};
    int rc = itb_stream_decrypt_triple(
        noise.raw_handle(),
        data1.raw_handle(), data2.raw_handle(), data3.raw_handle(),
        start1.raw_handle(), start2.raw_handle(), start3.raw_handle(),
        detail::read_thunk, &ctx,
        detail::write_thunk, &ctx,
        chunk_size);
    if (ctx.ex) {
        std::rethrow_exception(ctx.ex);
    }
    if (rc != ITB_OK) {
        detail::throw_from_status(rc);
    }
}

} // namespace itb
