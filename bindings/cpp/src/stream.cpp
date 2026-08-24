/*
 * stream.cpp — incremental stream sessions over an open Pipeline
 * plus the whole-buffer pump conveniences.
 *
 * A session is a dumb byte pump: plaintext (or wire) goes in through
 * write, produced bytes come out through read. All chunking, MAC,
 * envelope, and wire-format decisions stay inside libitb — the
 * binding moves opaque bytes and relays status codes.
 */

#include <algorithm>

#include "internal.hpp"

namespace itb {

using detail::check;
using detail::ffi_bytes;

/* ------------------------------------------------------------------ */
/* Session lifecycle                                                   */
/* ------------------------------------------------------------------ */

EncryptStream Pipeline::encrypt_stream_begin() const
{
    uintptr_t handle = 0;
    check(ITB_Triple_EncryptStreamBegin(handle_, &handle),
          "Pipeline::encrypt_stream_begin");
    return EncryptStream(handle);
}

DecryptStream Pipeline::decrypt_stream_begin() const
{
    uintptr_t handle = 0;
    check(ITB_Triple_DecryptStreamBegin(handle_, &handle),
          "Pipeline::decrypt_stream_begin");
    return DecryptStream(handle);
}

void Stream::write(std::span<const std::byte> src)
{
    check(ITB_Triple_StreamWrite(handle_, ffi_bytes(src), src.size()),
          "Stream::write");
}

void Stream::end()
{
    check(ITB_Triple_StreamEnd(handle_), "Stream::end");
}

StreamRead Stream::read(std::span<std::byte> dst)
{
    std::size_t n = 0;
    int fin = 0;
    check(ITB_Triple_StreamRead(handle_, ffi_bytes(dst), dst.size(), &n, &fin),
          "Stream::read");
    return {n, fin != 0};
}

void Stream::close() noexcept
{
    if (handle_ != 0) {
        /* StreamFree cancels and releases from any state, wiping the
         * Go-side spool; the status is deliberately ignored on the
         * release path. */
        (void)ITB_Triple_StreamFree(handle_);
        handle_ = 0;
    }
}

/* ------------------------------------------------------------------ */
/* Whole-buffer pumps                                                  */
/* ------------------------------------------------------------------ */

namespace {

/* Canonical pump: begin session → feed bounded slices, draining the
 * spool after each write → end → drain until finished. The whole
 * output lands in one vector handed to the caller; the session is
 * RAII-released even on a thrown error. */
std::vector<std::uint8_t> pump(Stream &session, std::span<const std::byte> src)
{
    std::vector<std::uint8_t> out;
    std::vector<std::byte> scratch(detail::kPumpBuf);

    std::size_t offset = 0;
    while (offset < src.size()) {
        const std::size_t slice = std::min(src.size() - offset, detail::kPumpBuf);
        session.write(src.subspan(offset, slice));
        offset += slice;
        /* Drain whatever the chain has produced so far; a read before
         * end never blocks. */
        for (;;) {
            const StreamRead r = session.read(scratch);
            if (r.n == 0) {
                break;
            }
            const auto *first = reinterpret_cast<const std::uint8_t *>(scratch.data());
            out.insert(out.end(), first, first + r.n);
        }
    }

    session.end();
    for (;;) {
        const StreamRead r = session.read(scratch);
        const auto *first = reinterpret_cast<const std::uint8_t *>(scratch.data());
        out.insert(out.end(), first, first + r.n);
        if (r.finished) {
            break;
        }
    }
    return out;
}

} // namespace

std::vector<std::uint8_t> Pipeline::encrypt_stream_pump(std::span<const std::byte> plain) const
{
    EncryptStream session = encrypt_stream_begin();
    return pump(session, plain);
}

std::vector<std::uint8_t> Pipeline::decrypt_stream_pump(std::span<const std::byte> wire) const
{
    DecryptStream session = decrypt_stream_begin();
    return pump(session, wire);
}

} // namespace itb
