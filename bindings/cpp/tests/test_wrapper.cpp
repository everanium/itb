// test_wrapper.cpp — format-deniability wrapper smoke + corner-case
// coverage for the C++ binding.
//
// Mirrors bindings/c/tests/test_wrapper.c via Catch2 v3.
//
// Coverage:
//
//   1. ffi_name interns the canonical short names per cipher and
//      returns an empty view for an out-of-range value.
//   2. key_size / nonce_size return the expected per-cipher byte
//      lengths and reject unknown cipher values.
//   3. wrap / unwrap round-trip preserves the blob bytes per cipher.
//   4. wrap_in_place / unwrap_in_place round-trip preserves the blob
//      bytes per cipher and the nonce buffer holds the correct size.
//   5. Streaming round-trip preserves bytes when the writer feeds
//      multiple update batches under a single keystream session.
//   6. wrap rejects mismatched-key length with ItbError(BAD_INPUT).
//   7. unwrap rejects truncated wire (shorter than nonce) with
//      ItbError(BAD_INPUT).
//   8. mismatched outer key produces a body that does not equal the
//      original blob (sanity check; no claim about distinguishability).
//   9. WrapStreamWriter / UnwrapStreamReader move-construction
//      transfers the handle and the source becomes inert.
//  10. UnwrapStreamReader rejects nonce of wrong length with
//      ItbError(BAD_INPUT).
//  11. generate_key returns a buffer of the right length that drives a
//      wrap / unwrap round-trip end-to-end.
//  12. Eitb-style end-to-end: ITB encryptor -> wrap_in_place ->
//      unwrap_in_place -> ITB decrypt round-trips a small payload.

#include <catch2/catch_test_macros.hpp>
#include <itb.hpp>
#include <itb/wrapper.hpp>

#include <cstdint>
#include <span>
#include <utility>
#include <vector>

namespace {

constexpr std::size_t kBlobLen = 1024;

std::vector<std::uint8_t> fill_pattern(std::size_t n) {
    std::vector<std::uint8_t> out(n);
    for (std::size_t i = 0; i < n; ++i) {
        out[i] = static_cast<std::uint8_t>((i * 73u + 19u) & 0xFFu);
    }
    return out;
}

constexpr itb::wrapper::Cipher kAllCiphers[] = {
    itb::wrapper::Cipher::Aes128Ctr,
    itb::wrapper::Cipher::ChaCha20,
    itb::wrapper::Cipher::SipHash24,
};

constexpr std::size_t kExpectedKey[]   = { 16, 32, 16 };
constexpr std::size_t kExpectedNonce[] = { 16, 12, 16 };

} // namespace

TEST_CASE("wrapper::ffi_name interns canonical short names",
          "[wrapper][ffi_name]") {
    REQUIRE(itb::wrapper::ffi_name(itb::wrapper::Cipher::Aes128Ctr) == "aes");
    REQUIRE(itb::wrapper::ffi_name(itb::wrapper::Cipher::ChaCha20)  == "chacha");
    REQUIRE(itb::wrapper::ffi_name(itb::wrapper::Cipher::SipHash24) == "siphash");
    // Out-of-range → empty view.
    auto bad = itb::wrapper::ffi_name(static_cast<itb::wrapper::Cipher>(99));
    REQUIRE(bad.empty());
}

TEST_CASE("wrapper::key_size / nonce_size match per-cipher contract",
          "[wrapper][sizes]") {
    for (std::size_t i = 0; i < std::size(kAllCiphers); ++i) {
        REQUIRE(itb::wrapper::key_size(kAllCiphers[i]) == kExpectedKey[i]);
        REQUIRE(itb::wrapper::nonce_size(kAllCiphers[i]) == kExpectedNonce[i]);
    }
    // Unknown cipher value rejected.
    REQUIRE_THROWS_AS(
        itb::wrapper::key_size(static_cast<itb::wrapper::Cipher>(99)),
        itb::ItbError);
    REQUIRE_THROWS_AS(
        itb::wrapper::nonce_size(static_cast<itb::wrapper::Cipher>(99)),
        itb::ItbError);
}

TEST_CASE("wrapper::wrap / unwrap round-trip preserves blob bytes",
          "[wrapper][roundtrip]") {
    auto blob = fill_pattern(kBlobLen);
    for (auto cipher : kAllCiphers) {
        auto key = itb::wrapper::generate_key(cipher);
        auto wire = itb::wrapper::wrap(cipher, key, blob);
        REQUIRE(wire.size() == itb::wrapper::nonce_size(cipher) + blob.size());
        auto recovered = itb::wrapper::unwrap(cipher, key, wire);
        REQUIRE(recovered == blob);
    }
}

TEST_CASE("wrapper::wrap_in_place / unwrap_in_place round-trip preserves bytes",
          "[wrapper][roundtrip][inplace]") {
    auto pristine = fill_pattern(kBlobLen);
    for (auto cipher : kAllCiphers) {
        auto key = itb::wrapper::generate_key(cipher);

        // Wrap in place — `blob` becomes ciphertext; `nonce` is
        // captured separately.
        std::vector<std::uint8_t> blob = pristine;
        auto nonce = itb::wrapper::wrap_in_place(
            cipher,
            std::span<const std::uint8_t>{key},
            std::span<std::uint8_t>{blob});
        REQUIRE(nonce.size() == itb::wrapper::nonce_size(cipher));
        REQUIRE(blob != pristine); // body has been XORed

        // Compose `nonce || blob` to reproduce a wrap() wire.
        std::vector<std::uint8_t> wire(nonce.size() + blob.size());
        std::copy(nonce.begin(), nonce.end(), wire.begin());
        std::copy(blob.begin(), blob.end(), wire.begin() + static_cast<std::ptrdiff_t>(nonce.size()));

        auto body = itb::wrapper::unwrap_in_place(
            cipher,
            std::span<const std::uint8_t>{key},
            std::span<std::uint8_t>{wire});
        REQUIRE(body.size() == pristine.size());
        REQUIRE(std::vector<std::uint8_t>(body.begin(), body.end()) == pristine);
    }
}

TEST_CASE("wrapper::WrapStreamWriter / UnwrapStreamReader round-trip "
          "across multiple updates", "[wrapper][stream]") {
    auto blob = fill_pattern(2 * kBlobLen);
    for (auto cipher : kAllCiphers) {
        auto key = itb::wrapper::generate_key(cipher);

        // Sender — feed two halves through one keystream session.
        itb::wrapper::WrapStreamWriter ww{cipher, key};
        REQUIRE(ww.cipher() == cipher);
        REQUIRE(ww.nonce().size() == itb::wrapper::nonce_size(cipher));
        std::span<const std::uint8_t> first{blob.data(), kBlobLen};
        std::span<const std::uint8_t> second{blob.data() + kBlobLen, kBlobLen};
        auto wire1 = ww.update(first);
        auto wire2 = ww.update(second);

        // Receiver — strip nonce, feed the same two halves through one
        // unwrap session, recover the original bytes.
        itb::wrapper::UnwrapStreamReader ur{cipher, key, ww.nonce()};
        auto recovered1 = ur.update(wire1);
        auto recovered2 = ur.update(wire2);
        std::vector<std::uint8_t> recovered;
        recovered.insert(recovered.end(), recovered1.begin(), recovered1.end());
        recovered.insert(recovered.end(), recovered2.begin(), recovered2.end());
        REQUIRE(recovered == blob);
    }
}

TEST_CASE("wrapper::WrapStreamWriter::update_in_place mutates the buffer",
          "[wrapper][stream][inplace]") {
    auto pristine = fill_pattern(kBlobLen);
    for (auto cipher : kAllCiphers) {
        auto key = itb::wrapper::generate_key(cipher);

        std::vector<std::uint8_t> buf = pristine;
        itb::wrapper::WrapStreamWriter ww{cipher, key};
        auto nonce = ww.nonce();
        ww.update_in_place(std::span<std::uint8_t>{buf});
        REQUIRE(buf != pristine);

        itb::wrapper::UnwrapStreamReader ur{cipher, key, nonce};
        ur.update_in_place(std::span<std::uint8_t>{buf});
        REQUIRE(buf == pristine);
    }
}

TEST_CASE("wrapper::wrap rejects mismatched key length",
          "[wrapper][errors]") {
    auto blob = fill_pattern(64);
    // AES needs 16 bytes; pass 8.
    std::vector<std::uint8_t> short_key(8, 0xAB);
    REQUIRE_THROWS_AS(
        itb::wrapper::wrap(itb::wrapper::Cipher::Aes128Ctr, short_key, blob),
        itb::ItbError);
}

TEST_CASE("wrapper::unwrap rejects truncated wire shorter than nonce",
          "[wrapper][errors]") {
    auto key = itb::wrapper::generate_key(itb::wrapper::Cipher::Aes128Ctr);
    // Nonce size for AES-128-CTR is 16; pass 8 bytes total.
    std::vector<std::uint8_t> too_short(8, 0xCD);
    REQUIRE_THROWS_AS(
        itb::wrapper::unwrap(itb::wrapper::Cipher::Aes128Ctr, key, too_short),
        itb::ItbError);
}

TEST_CASE("wrapper::unwrap with mismatched key produces non-equal body",
          "[wrapper][errors]") {
    // Sanity check: a different outer key recovers garbage, not the
    // original blob. No claim about distinguishability — the wrap is
    // unauthenticated.
    auto blob = fill_pattern(kBlobLen);
    auto k1 = itb::wrapper::generate_key(itb::wrapper::Cipher::Aes128Ctr);
    auto k2 = itb::wrapper::generate_key(itb::wrapper::Cipher::Aes128Ctr);
    auto wire = itb::wrapper::wrap(itb::wrapper::Cipher::Aes128Ctr, k1, blob);
    auto recovered = itb::wrapper::unwrap(itb::wrapper::Cipher::Aes128Ctr, k2, wire);
    REQUIRE(recovered != blob);
}

TEST_CASE("wrapper::UnwrapStreamReader rejects wrong-length wire nonce",
          "[wrapper][stream][errors]") {
    auto key = itb::wrapper::generate_key(itb::wrapper::Cipher::Aes128Ctr);
    std::vector<std::uint8_t> wrong_nonce(8, 0x11);
    auto build = [&]() {
        return itb::wrapper::UnwrapStreamReader{
            itb::wrapper::Cipher::Aes128Ctr, key, wrong_nonce};
    };
    REQUIRE_THROWS_AS(build(), itb::ItbError);
}

TEST_CASE("wrapper::WrapStreamWriter move-construction transfers handle",
          "[wrapper][stream][move]") {
    auto key = itb::wrapper::generate_key(itb::wrapper::Cipher::Aes128Ctr);
    itb::wrapper::WrapStreamWriter src{
        itb::wrapper::Cipher::Aes128Ctr, key};
    auto nonce = src.nonce();
    itb::wrapper::WrapStreamWriter dst{std::move(src)};
    REQUIRE(dst.nonce() == nonce);
    auto blob = fill_pattern(64);
    auto wire = dst.update(blob);
    REQUIRE(wire.size() == blob.size());
    // Receiver still pairs against `nonce` from `dst`, regardless of
    // the source vs. destination identity.
    itb::wrapper::UnwrapStreamReader ur{
        itb::wrapper::Cipher::Aes128Ctr, key, dst.nonce()};
    auto recovered = ur.update(wire);
    REQUIRE(recovered == blob);
}

TEST_CASE("wrapper::generate_key returns a buffer that drives a round-trip",
          "[wrapper][generate_key]") {
    for (auto cipher : kAllCiphers) {
        auto key = itb::wrapper::generate_key(cipher);
        REQUIRE(key.size() == itb::wrapper::key_size(cipher));
        auto blob = fill_pattern(64);
        auto wire = itb::wrapper::wrap(cipher, key, blob);
        auto recovered = itb::wrapper::unwrap(cipher, key, wire);
        REQUIRE(recovered == blob);
    }
}

TEST_CASE("eitb-style end-to-end: ITB encryptor + wrapper round-trip",
          "[wrapper][eitb]") {
    auto plaintext = fill_pattern(256);
    itb::Encryptor enc{"areion512", 1024, "hmac-blake3", 1};

    auto ct = enc.encrypt(plaintext);
    auto outer_key = itb::wrapper::generate_key(itb::wrapper::Cipher::Aes128Ctr);

    // Wrap in place mutates ct; nonce captured separately.
    auto nonce = itb::wrapper::wrap_in_place(
        itb::wrapper::Cipher::Aes128Ctr,
        std::span<const std::uint8_t>{outer_key},
        std::span<std::uint8_t>{ct});

    // Compose wire = nonce || ct.
    std::vector<std::uint8_t> wire(nonce.size() + ct.size());
    std::copy(nonce.begin(), nonce.end(), wire.begin());
    std::copy(ct.begin(), ct.end(), wire.begin() + static_cast<std::ptrdiff_t>(nonce.size()));

    auto body = itb::wrapper::unwrap_in_place(
        itb::wrapper::Cipher::Aes128Ctr,
        std::span<const std::uint8_t>{outer_key},
        std::span<std::uint8_t>{wire});

    std::vector<std::uint8_t> body_vec(body.begin(), body.end());
    auto recovered = enc.decrypt(body_vec);
    REQUIRE(recovered == plaintext);
}
